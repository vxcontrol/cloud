package anonymizer

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
)

const (
	// defined anonymizer decorator name for struct tag
	anonymizerTagName = "anonymizer"

	// specifies if the field should be skipped from anonymization
	skipField = "skip"
)

// structField represents a single field found in a struct
type structField struct {
	// field name
	Name string
	// field index path
	Index []int
	// field type
	Type reflect.Type
	// whether to skip anonymization
	Skip bool
}

// structInfo holds information about a struct for anonymization
type structInfo struct {
	Fields []structField
	Type   reflect.Type
}

var (
	// cache for struct information
	structCache = make(map[reflect.Type]*structInfo)
	cacheMutex  sync.RWMutex
)

// ErrObjectImmutable is returned when trying to anonymize an immutable object
var ErrObjectImmutable = fmt.Errorf("object is immutable and cannot be anonymized")

// getStructInfo returns struct information from cache or parses it
func getStructInfo(t reflect.Type) (*structInfo, error) {
	cacheMutex.RLock()
	info, exists := structCache[t]
	cacheMutex.RUnlock()

	if exists {
		return info, nil
	}

	// parse struct and cache result
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	// double-check after acquiring write lock
	if info, exists := structCache[t]; exists {
		return info, nil
	}

	info, err := parseStruct(t)
	if err != nil {
		return nil, err
	}

	structCache[t] = info
	return info, nil
}

// parseStruct parses struct fields and returns StructInfo
func parseStruct(t reflect.Type) (*structInfo, error) {
	if t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("expected struct type, got %s", t.Kind())
	}

	fields, err := getStructFields(t)
	if err != nil {
		return nil, err
	}

	return &structInfo{
		Fields: fields,
		Type:   t,
	}, nil
}

// getStructFields returns a list of fields for the given struct type
func getStructFields(t reflect.Type) ([]structField, error) {
	// anonymous fields to explore at current and next level
	current := []structField{}
	next := []structField{{Type: t}}

	// count of queued names for current level and the next
	var count, nextCount map[reflect.Type]int

	// types already visited at an earlier level
	visited := map[reflect.Type]bool{}

	// fields found
	var fields []structField

	for len(next) > 0 {
		current, next = next, current[:0]
		count, nextCount = nextCount, map[reflect.Type]int{}

		for _, f := range current {
			if visited[f.Type] {
				continue
			}
			visited[f.Type] = true

			// scan f.Type for fields to include
			for i := 0; i < f.Type.NumField(); i++ {
				sf := f.Type.Field(i)
				if sf.Anonymous {
					t := sf.Type
					if t.Kind() == reflect.Pointer {
						t = t.Elem()
					}
					if !sf.IsExported() && t.Kind() != reflect.Struct {
						// ignore embedded fields of unexported non-struct types
						continue
					}
				} else if !sf.IsExported() {
					// ignore unexported non-embedded fields
					continue
				}

				// parse anonymizer tag
				var skip bool
				tagAnonymizer := sf.Tag.Get(anonymizerTagName)
				if tagAnonymizer != "" {
					opts := strings.Split(tagAnonymizer, ",")
					for _, opt := range opts {
						if strings.TrimSpace(opt) == skipField {
							skip = true
							break
						}
					}
				}

				index := make([]int, len(f.Index)+1)
				copy(index, f.Index)
				index[len(f.Index)] = i

				ft := sf.Type
				for ft.Name() == "" && ft.Kind() == reflect.Pointer {
					// follow pointer
					ft = ft.Elem()
				}

				// record found field and index sequence
				if !sf.Anonymous || ft.Kind() != reflect.Struct {
					field := structField{
						Name:  sf.Name,
						Index: index,
						Type:  ft,
						Skip:  skip,
					}
					fields = append(fields, field)
					if count[f.Type] > 1 {
						// if there were multiple instances, add a second
						fields = append(fields, fields[len(fields)-1])
					}
					continue
				}

				// record new anonymous struct to explore in next round
				nextCount[ft]++
				if nextCount[ft] == 1 {
					next = append(next, structField{Name: ft.Name(), Index: index, Type: ft})
				}
			}
		}
	}

	return fields, nil
}

// isMutable checks if the given value can be modified
func isMutable(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Pointer:
		return !v.IsNil()
	case reflect.Map, reflect.Slice:
		return true
	case reflect.Interface:
		if !v.IsNil() {
			return isMutable(v.Elem())
		}
		return false
	default:
		return false
	}
}
