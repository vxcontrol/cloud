package anonymizer

import (
	"io"
	"reflect"

	"github.com/vxcontrol/cloud/anonymizer/patterns"
)

type Anonymizer interface {
	Anonymize(any) error
	ReplaceString(string) string
	ReplaceBytes([]byte) []byte
	WrapReader(io.Reader) io.Reader
}

type anonymizer struct {
	Replacer
}

func NewAnonymizer(pts []patterns.Pattern) (Anonymizer, error) {
	patterns, err := patterns.LoadPatterns(patterns.PatternListTypeAll)
	if err != nil {
		return nil, err
	}

	patterns.Patterns = append(patterns.Patterns, pts...)

	replacer, err := NewReplacer(patterns.Regexes(), patterns.Names())
	if err != nil {
		return nil, err
	}

	return &anonymizer{Replacer: replacer}, nil
}

func (a *anonymizer) Anonymize(v any) error {
	rv := reflect.ValueOf(v)

	if !isMutable(rv) {
		return ErrObjectImmutable
	}

	// use visited map to prevent infinite recursion
	visited := make(map[uintptr]bool)
	return a.anonymizeValue(rv, visited)
}

// anonymizeValue recursively anonymizes a reflect.Value with cycle detection
func (a *anonymizer) anonymizeValue(v reflect.Value, visited map[uintptr]bool) error {
	if !v.IsValid() {
		return nil
	}

	// check for cycles in pointer types
	if v.Kind() == reflect.Pointer && !v.IsNil() {
		ptr := v.Pointer()
		if visited[ptr] {
			return nil // already visited, skip to prevent cycles
		}
		visited[ptr] = true
	}

	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return nil
		}
		// for pointer to string, anonymize the string value directly
		elem := v.Elem()
		if elem.Kind() == reflect.String && elem.CanSet() {
			original := elem.String()
			anonymized := a.ReplaceString(original)
			elem.SetString(anonymized)
			return nil
		}
		// for other types, recurse
		return a.anonymizeValue(elem, visited)

	case reflect.Interface:
		if v.IsNil() {
			return nil
		}
		elem := v.Elem()

		// if the interface contains a struct value, we need special handling
		if elem.Kind() == reflect.Struct {
			// create a new struct value that can be modified
			newStruct := reflect.New(elem.Type()).Elem()
			newStruct.Set(elem)

			if err := a.anonymizeValue(newStruct.Addr(), visited); err != nil {
				return err
			}

			// set the modified struct back to the interface
			v.Set(newStruct)
			return nil
		}

		// for other types, try to modify in place if possible
		if elem.CanSet() {
			return a.anonymizeValue(elem, visited)
		}

		// if we can't modify in place, create a new value
		newVal := reflect.New(elem.Type()).Elem()
		newVal.Set(elem)

		if err := a.anonymizeValue(newVal, visited); err != nil {
			return err
		}

		v.Set(newVal)
		return nil

	case reflect.Map:
		return a.anonymizeMap(v, visited)

	case reflect.Slice, reflect.Array:
		return a.anonymizeSlice(v, visited)

	case reflect.Struct:
		return a.anonymizeStruct(v, visited)

	case reflect.String:
		if v.CanSet() {
			original := v.String()
			anonymized := a.ReplaceString(original)
			v.SetString(anonymized)
		}
		return nil

	default:
		// for other types (numbers, bools, etc.) do nothing
		return nil
	}
}

// anonymizeMap anonymizes all values in a map with cycle detection
func (a *anonymizer) anonymizeMap(v reflect.Value, visited map[uintptr]bool) error {
	if v.IsNil() {
		return nil
	}

	iter := v.MapRange()
	for iter.Next() {
		key := iter.Key()
		val := iter.Value()

		// handle different value types appropriately
		switch val.Kind() {
		case reflect.Pointer:
			// for pointers, work directly with the original pointer
			if err := a.anonymizeValue(val, visited); err != nil {
				return err
			}
			// no need to set back to map - we modified the pointed-to value

		case reflect.Struct:
			// for struct values in map, create a copy and work with its address
			newVal := reflect.New(val.Type()).Elem()
			newVal.Set(val)
			if err := a.anonymizeValue(newVal.Addr(), visited); err != nil {
				return err
			}
			v.SetMapIndex(key, newVal)

		default:
			// for other types (strings, primitives, slices, maps), create a copy
			newVal := reflect.New(val.Type()).Elem()
			newVal.Set(val)
			if err := a.anonymizeValue(newVal, visited); err != nil {
				return err
			}
			v.SetMapIndex(key, newVal)
		}
	}

	return nil
}

// anonymizeSlice anonymizes all elements in a slice or array with cycle detection
func (a *anonymizer) anonymizeSlice(v reflect.Value, visited map[uintptr]bool) error {
	for i := 0; i < v.Len(); i++ {
		elem := v.Index(i)
		if err := a.anonymizeValue(elem, visited); err != nil {
			return err
		}
	}

	return nil
}

// anonymizeStruct anonymizes struct fields based on their tags and types with cycle detection
func (a *anonymizer) anonymizeStruct(v reflect.Value, visited map[uintptr]bool) error {
	structType := v.Type()

	// get struct information from cache or parse it
	info, err := getStructInfo(structType)
	if err != nil {
		return err
	}

	// iterate through all fields
	for _, field := range info.Fields {
		// skip fields marked with skip tag
		if field.Skip {
			continue
		}

		// get field value using index path
		fieldValue := v
		for _, idx := range field.Index {
			if fieldValue.Kind() == reflect.Pointer {
				if fieldValue.IsNil() {
					// skip nil pointers - don't create new objects
					fieldValue = reflect.Value{}
					break
				}
				fieldValue = fieldValue.Elem()
			}

			if !fieldValue.IsValid() || idx >= fieldValue.NumField() {
				// field index out of range or invalid, skip
				fieldValue = reflect.Value{}
				break
			}

			fieldValue = fieldValue.Field(idx)
		}

		// anonymize the field value only if it's valid and not marked as skip
		if fieldValue.IsValid() {
			if err := a.anonymizeValue(fieldValue, visited); err != nil {
				return err
			}
		}
	}

	return nil
}
