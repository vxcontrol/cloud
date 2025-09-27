package anonymizer

import (
	"fmt"
	"io"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"
)

// test constants
const (
	maskedString = "***MASKED***"
)

// testMockReplacer replaces any non-empty string with a constant for predictable testing
type testMockReplacer struct{}

func (m *testMockReplacer) ReplaceString(s string) string {
	if s == "" {
		return s
	}
	return maskedString
}

func (m *testMockReplacer) ReplaceBytes(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	return []byte(maskedString)
}

func (m *testMockReplacer) WrapReader(r io.Reader) io.Reader {
	return r // not used in struct anonymization tests
}

// test helper structures
type SimpleStruct struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Skip  string `json:"skip" anonymizer:"skip"`
}

type NestedStruct struct {
	ID     string       `json:"id"`
	Simple SimpleStruct `json:"simple"`
}

type EmbeddedStruct struct {
	SimpleStruct
	Extra string `json:"extra"`
}

type ComplexStruct struct {
	Name     string            `json:"name"`
	Tags     []string          `json:"tags"`
	Metadata map[string]string `json:"metadata"`
	Any      map[string]any    `json:"any"`
	Skip     string            `json:"skip" anonymizer:"skip"`
}

// test structures for pointer and special type handling
type PointerTestStruct struct {
	StringPtr    *string       `json:"string_ptr"`
	IntPtr       *int          `json:"int_ptr"`
	NilStringPtr *string       `json:"nil_string_ptr"`
	NilIntPtr    *int          `json:"nil_int_ptr"`
	StructPtr    *SimpleStruct `json:"struct_ptr"`
	NilStructPtr *SimpleStruct `json:"nil_struct_ptr"`
	Skip         *string       `json:"skip" anonymizer:"skip"`
}

type SpecialTypesStruct struct {
	Mutex      sync.Mutex     `json:"mutex"`
	RWMutex    sync.RWMutex   `json:"rwmutex"`
	AtomicInt  atomic.Int64   `json:"atomic_int"`
	AtomicBool atomic.Bool    `json:"atomic_bool"`
	UnsafePtr  unsafe.Pointer `json:"unsafe_ptr"`
	String     string         `json:"string"`
	Skip       string         `json:"skip" anonymizer:"skip"`
}

type DeepPointerStruct struct {
	Level1 *struct {
		StringPtr *string `json:"string_ptr"`
		Level2    *struct {
			StringPtr *string `json:"string_ptr"`
			NilPtr    *string `json:"nil_ptr"`
		} `json:"level2"`
	} `json:"level1"`
}

// test case structure
type testCase struct {
	name   string
	object any
	check  func(any) error
}

// helper function to create anonymizer with mock replacer
func createMockAnonymizer() Anonymizer {
	return &anonymizer{Replacer: &testMockReplacer{}}
}

func checkSimpleStruct(name, value, skip string) func(any) error {
	return func(obj any) error {
		s, ok := obj.(*SimpleStruct)
		if !ok {
			return fmt.Errorf("object is not *SimpleStruct: %T", obj)
		}
		if s.Name != name {
			return fmt.Errorf("Name: expected %q, got %q", name, s.Name)
		}
		if s.Value != value {
			return fmt.Errorf("Value: expected %q, got %q", value, s.Value)
		}
		if s.Skip != skip {
			return fmt.Errorf("Skip: expected %q, got %q", skip, s.Skip)
		}
		return nil
	}
}

func checkMapStringString(expected map[string]string) func(any) error {
	return func(obj any) error {
		m, ok := obj.(map[string]string)
		if !ok {
			return fmt.Errorf("object is not map[string]string: %T", obj)
		}
		if len(m) != len(expected) {
			return fmt.Errorf("map length: expected %d, got %d", len(expected), len(m))
		}
		for k, v := range expected {
			if actual, exists := m[k]; !exists {
				return fmt.Errorf("key %q not found", k)
			} else if actual != v {
				return fmt.Errorf("key %q: expected %q, got %q", k, v, actual)
			}
		}
		return nil
	}
}

func checkSliceStrings(expected []string) func(any) error {
	return func(obj any) error {
		s, ok := obj.([]string)
		if !ok {
			return fmt.Errorf("object is not []string: %T", obj)
		}
		if len(s) != len(expected) {
			return fmt.Errorf("slice length: expected %d, got %d", len(expected), len(s))
		}
		for i, exp := range expected {
			if s[i] != exp {
				return fmt.Errorf("index %d: expected %q, got %q", i, exp, s[i])
			}
		}
		return nil
	}
}

// helper to check pointer identity (same address)
func checkPointerIdentity(original, current any, fieldName string) error {
	origPtr := fmt.Sprintf("%p", original)
	currPtr := fmt.Sprintf("%p", current)
	if origPtr != currPtr {
		return fmt.Errorf("%s pointer identity changed: original %s, current %s", fieldName, origPtr, currPtr)
	}
	return nil
}

// helper to check that nil pointers remain nil
func checkNilPointer(ptr any, fieldName string) error {
	if ptr == nil {
		return nil // truly nil
	}

	// check for typed nil using reflection
	v := reflect.ValueOf(ptr)
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return nil // typed nil pointer
	}

	return fmt.Errorf("%s should be nil, got %v (type: %T)", fieldName, ptr, ptr)
}

// helper to check string pointer value
func checkStringPointer(ptr *string, expected string, fieldName string) error {
	if ptr == nil {
		return fmt.Errorf("%s should not be nil", fieldName)
	}
	if *ptr != expected {
		return fmt.Errorf("%s: expected %q, got %q", fieldName, expected, *ptr)
	}
	return nil
}

// comprehensive test cases
func TestAnonymizeComprehensive(t *testing.T) {
	anonymizer := createMockAnonymizer()

	testCases := []testCase{
		// basic types
		{
			name:   "simple_struct_pointer",
			object: &SimpleStruct{Name: "test", Value: "value", Skip: "keep"},
			check:  checkSimpleStruct(maskedString, maskedString, "keep"),
		},

		// nested structures
		{
			name: "nested_struct",
			object: &NestedStruct{
				ID:     "outer",
				Simple: SimpleStruct{Name: "inner", Value: "data", Skip: "preserve"},
			},
			check: func(obj any) error {
				n := obj.(*NestedStruct)
				if n.ID != maskedString {
					return fmt.Errorf("ID: expected %q, got %q", maskedString, n.ID)
				}
				return checkSimpleStruct(maskedString, maskedString, "preserve")(&n.Simple)
			},
		},

		// embedded structures
		{
			name: "embedded_struct",
			object: &EmbeddedStruct{
				SimpleStruct: SimpleStruct{Name: "embedded", Value: "data", Skip: "keep"},
				Extra:        "additional",
			},
			check: func(obj any) error {
				e := obj.(*EmbeddedStruct)
				if e.Extra != maskedString {
					return fmt.Errorf("Extra: expected %q, got %q", maskedString, e.Extra)
				}
				return checkSimpleStruct(maskedString, maskedString, "keep")(&e.SimpleStruct)
			},
		},

		// maps
		{
			name: "map_string_string",
			object: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			check: checkMapStringString(map[string]string{
				"key1": maskedString,
				"key2": maskedString,
			}),
		},

		// slices
		{
			name:   "slice_strings",
			object: []string{"first", "second", "third"},
			check:  checkSliceStrings([]string{maskedString, maskedString, maskedString}),
		},

		// map of structs
		{
			name: "map_of_structs",
			object: map[string]*SimpleStruct{
				"struct1": {Name: "name1", Value: "value1", Skip: "skip1"},
				"struct2": {Name: "name2", Value: "value2", Skip: "skip2"},
			},
			check: func(obj any) error {
				m := obj.(map[string]*SimpleStruct)
				if len(m) != 2 {
					return fmt.Errorf("expected 2 structs, got %d", len(m))
				}
				if err := checkSimpleStruct(maskedString, maskedString, "skip1")(m["struct1"]); err != nil {
					return fmt.Errorf("struct1: %w", err)
				}
				if err := checkSimpleStruct(maskedString, maskedString, "skip2")(m["struct2"]); err != nil {
					return fmt.Errorf("struct2: %w", err)
				}
				return nil
			},
		},

		// slice of structs
		{
			name: "slice_of_structs",
			object: []*SimpleStruct{
				{Name: "first", Value: "val1", Skip: "keep1"},
				{Name: "second", Value: "val2", Skip: "keep2"},
			},
			check: func(obj any) error {
				s := obj.([]*SimpleStruct)
				if len(s) != 2 {
					return fmt.Errorf("expected 2 structs, got %d", len(s))
				}
				if err := checkSimpleStruct(maskedString, maskedString, "keep1")(s[0]); err != nil {
					return fmt.Errorf("index 0: %w", err)
				}
				if err := checkSimpleStruct(maskedString, maskedString, "keep2")(s[1]); err != nil {
					return fmt.Errorf("index 1: %w", err)
				}
				return nil
			},
		},

		// map of slice of structs
		{
			name: "map_of_slice_of_structs",
			object: map[string][]*SimpleStruct{
				"group1": {
					{Name: "g1s1", Value: "v1", Skip: "k1"},
					{Name: "g1s2", Value: "v2", Skip: "k2"},
				},
			},
			check: func(obj any) error {
				m := obj.(map[string][]*SimpleStruct)
				group := m["group1"]
				if len(group) != 2 {
					return fmt.Errorf("expected 2 structs in group1, got %d", len(group))
				}
				if err := checkSimpleStruct(maskedString, maskedString, "k1")(group[0]); err != nil {
					return fmt.Errorf("group1[0]: %w", err)
				}
				if err := checkSimpleStruct(maskedString, maskedString, "k2")(group[1]); err != nil {
					return fmt.Errorf("group1[1]: %w", err)
				}
				return nil
			},
		},

		// slice of maps of structs
		{
			name: "slice_of_maps_of_structs",
			object: []map[string]*SimpleStruct{
				{
					"item1": {Name: "name1", Value: "value1", Skip: "skip1"},
				},
				{
					"item2": {Name: "name2", Value: "value2", Skip: "skip2"},
				},
			},
			check: func(obj any) error {
				s := obj.([]map[string]*SimpleStruct)
				if len(s) != 2 {
					return fmt.Errorf("expected 2 maps, got %d", len(s))
				}
				if err := checkSimpleStruct(maskedString, maskedString, "skip1")(s[0]["item1"]); err != nil {
					return fmt.Errorf("map[0][item1]: %w", err)
				}
				if err := checkSimpleStruct(maskedString, maskedString, "skip2")(s[1]["item2"]); err != nil {
					return fmt.Errorf("map[1][item2]: %w", err)
				}
				return nil
			},
		},

		// struct with slice of strings
		{
			name: "struct_with_slice_of_strings",
			object: &struct {
				Name  string   `json:"name"`
				Items []string `json:"items"`
			}{
				Name:  "container",
				Items: []string{"item1", "item2", "item3"},
			},
			check: func(obj any) error {
				s := obj.(*struct {
					Name  string   `json:"name"`
					Items []string `json:"items"`
				})
				if s.Name != maskedString {
					return fmt.Errorf("Name: expected %q, got %q", maskedString, s.Name)
				}
				return checkSliceStrings([]string{maskedString, maskedString, maskedString})(s.Items)
			},
		},

		// struct with slice of maps of strings
		{
			name: "struct_with_slice_of_maps_of_strings",
			object: &struct {
				Name string              `json:"name"`
				Data []map[string]string `json:"data"`
			}{
				Name: "complex",
				Data: []map[string]string{
					{"key1": "val1", "key2": "val2"},
					{"key3": "val3", "key4": "val4"},
				},
			},
			check: func(obj any) error {
				s := obj.(*struct {
					Name string              `json:"name"`
					Data []map[string]string `json:"data"`
				})
				if s.Name != maskedString {
					return fmt.Errorf("Name: expected %q, got %q", maskedString, s.Name)
				}
				if len(s.Data) != 2 {
					return fmt.Errorf("expected 2 maps, got %d", len(s.Data))
				}
				expectedMap1 := map[string]string{"key1": maskedString, "key2": maskedString}
				expectedMap2 := map[string]string{"key3": maskedString, "key4": maskedString}
				if err := checkMapStringString(expectedMap1)(s.Data[0]); err != nil {
					return fmt.Errorf("Data[0]: %w", err)
				}
				if err := checkMapStringString(expectedMap2)(s.Data[1]); err != nil {
					return fmt.Errorf("Data[1]: %w", err)
				}
				return nil
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := anonymizer.Anonymize(tc.object)
			if err != nil {
				t.Fatalf("failed to anonymize: %v", err)
			}

			if err := tc.check(tc.object); err != nil {
				t.Errorf("check failed: %v", err)
			}
		})
	}
}

// edge cases tests
func TestAnonymizeEdgeCases(t *testing.T) {
	anonymizer := createMockAnonymizer()

	edgeCases := []testCase{
		// map[string]any with mixed types (mutable and immutable)
		{
			name: "map_string_any_mixed_types",
			object: map[string]any{
				"string":     "test_string",
				"int":        42,
				"struct":     SimpleStruct{Name: "embedded", Value: "data", Skip: "keep"},
				"ptr_struct": &SimpleStruct{Name: "pointer", Value: "ptr_data", Skip: "preserve"},
				"slice":      []string{"item1", "item2"},
				"map":        map[string]string{"nested_key": "nested_value"},
				"empty":      "",
				"nil":        nil,
			},
			check: func(obj any) error {
				m := obj.(map[string]any)

				// string should be masked
				if str, ok := m["string"].(string); !ok || str != maskedString {
					return fmt.Errorf("string: expected %q, got %v", maskedString, m["string"])
				}

				// int should remain unchanged
				if val, ok := m["int"].(int); !ok || val != 42 {
					return fmt.Errorf("int: expected 42, got %v", m["int"])
				}

				// struct should be anonymized (note: Go will convert to pointer internally)
				if s, ok := m["struct"].(SimpleStruct); ok {
					if s.Name != maskedString || s.Value != maskedString || s.Skip != "keep" {
						return fmt.Errorf("struct: expected masked fields, got %+v", s)
					}
				} else {
					return fmt.Errorf("struct: expected SimpleStruct, got %T", m["struct"])
				}

				// ptr_struct should be anonymized
				if s, ok := m["ptr_struct"].(*SimpleStruct); ok {
					if s.Name != maskedString || s.Value != maskedString || s.Skip != "preserve" {
						return fmt.Errorf("ptr_struct: expected masked fields, got %+v", s)
					}
				} else {
					return fmt.Errorf("ptr_struct: expected *SimpleStruct, got %T", m["ptr_struct"])
				}

				// slice should be anonymized
				if slice, ok := m["slice"].([]string); ok {
					expected := []string{maskedString, maskedString}
					if err := checkSliceStrings(expected)(slice); err != nil {
						return fmt.Errorf("slice: %w", err)
					}
				} else {
					return fmt.Errorf("slice: expected []string, got %T", m["slice"])
				}

				// nested map should be anonymized
				if nestedMap, ok := m["map"].(map[string]string); ok {
					expected := map[string]string{"nested_key": maskedString}
					if err := checkMapStringString(expected)(nestedMap); err != nil {
						return fmt.Errorf("map: %w", err)
					}
				} else {
					return fmt.Errorf("map: expected map[string]string, got %T", m["map"])
				}

				// empty string should remain empty
				if str, ok := m["empty"].(string); !ok || str != "" {
					return fmt.Errorf("empty: expected empty string, got %v", m["empty"])
				}

				// nil should remain nil
				if m["nil"] != nil {
					return fmt.Errorf("nil: expected nil, got %v", m["nil"])
				}

				return nil
			},
		},

		// deeply nested structures
		{
			name: "deeply_nested_structures",
			object: &struct {
				Level1 *struct {
					Level2 *struct {
						Level3 *struct {
							Level4 string `json:"deep_value"`
						} `json:"level3"`
					} `json:"level2"`
				} `json:"level1"`
			}{
				Level1: &struct {
					Level2 *struct {
						Level3 *struct {
							Level4 string `json:"deep_value"`
						} `json:"level3"`
					} `json:"level2"`
				}{
					Level2: &struct {
						Level3 *struct {
							Level4 string `json:"deep_value"`
						} `json:"level3"`
					}{
						Level3: &struct {
							Level4 string `json:"deep_value"`
						}{
							Level4: "deeply_nested_string",
						},
					},
				},
			},
			check: func(obj any) error {
				s := obj.(*struct {
					Level1 *struct {
						Level2 *struct {
							Level3 *struct {
								Level4 string `json:"deep_value"`
							} `json:"level3"`
						} `json:"level2"`
					} `json:"level1"`
				})

				if s.Level1 == nil || s.Level1.Level2 == nil || s.Level1.Level2.Level3 == nil {
					return fmt.Errorf("nested structure is nil")
				}

				if s.Level1.Level2.Level3.Level4 != maskedString {
					return fmt.Errorf("deeply nested string: expected %q, got %q", maskedString, s.Level1.Level2.Level3.Level4)
				}

				return nil
			},
		},

		// any containing various types
		{
			name: "interface_containing_various_types",
			object: &struct {
				Data any `json:"data"`
			}{
				Data: map[string]any{
					"nested_struct": &SimpleStruct{Name: "interface_test", Value: "test_value", Skip: "keep"},
					"nested_slice":  []string{"a", "b", "c"},
				},
			},
			check: func(obj any) error {
				s := obj.(*struct {
					Data any `json:"data"`
				})

				dataMap, ok := s.Data.(map[string]any)
				if !ok {
					return fmt.Errorf("Data is not map[string]any: %T", s.Data)
				}

				// check nested struct
				if nestedStruct, ok := dataMap["nested_struct"].(*SimpleStruct); ok {
					if nestedStruct.Name != maskedString || nestedStruct.Value != maskedString || nestedStruct.Skip != "keep" {
						return fmt.Errorf("nested_struct: expected masked fields, got %+v", nestedStruct)
					}
				} else {
					return fmt.Errorf("nested_struct: expected *SimpleStruct, got %T", dataMap["nested_struct"])
				}

				// check nested slice
				if nestedSlice, ok := dataMap["nested_slice"].([]string); ok {
					expected := []string{maskedString, maskedString, maskedString}
					if err := checkSliceStrings(expected)(nestedSlice); err != nil {
						return fmt.Errorf("nested_slice: %w", err)
					}
				} else {
					return fmt.Errorf("nested_slice: expected []string, got %T", dataMap["nested_slice"])
				}

				return nil
			},
		},

		// empty collections
		{
			name: "empty_collections",
			object: &struct {
				EmptyMap   map[string]string `json:"empty_map"`
				EmptySlice []string          `json:"empty_slice"`
				NilMap     map[string]string `json:"nil_map"`
				NilSlice   []string          `json:"nil_slice"`
			}{
				EmptyMap:   make(map[string]string),
				EmptySlice: make([]string, 0),
				NilMap:     nil,
				NilSlice:   nil,
			},
			check: func(obj any) error {
				s := obj.(*struct {
					EmptyMap   map[string]string `json:"empty_map"`
					EmptySlice []string          `json:"empty_slice"`
					NilMap     map[string]string `json:"nil_map"`
					NilSlice   []string          `json:"nil_slice"`
				})

				if s.EmptyMap == nil || len(s.EmptyMap) != 0 {
					return fmt.Errorf("EmptyMap should be empty, got %v", s.EmptyMap)
				}
				if s.EmptySlice == nil || len(s.EmptySlice) != 0 {
					return fmt.Errorf("EmptySlice should be empty, got %v", s.EmptySlice)
				}
				if s.NilMap != nil {
					return fmt.Errorf("NilMap should be nil, got %v", s.NilMap)
				}
				if s.NilSlice != nil {
					return fmt.Errorf("NilSlice should be nil, got %v", s.NilSlice)
				}

				return nil
			},
		},

		// circular reference prevention (using pointers)
		{
			name: "complex_pointer_structures",
			object: &struct {
				Self *struct {
					Name  string `json:"name"`
					Other *struct {
						Value string `json:"value"`
					} `json:"other"`
				} `json:"self"`
			}{
				Self: &struct {
					Name  string `json:"name"`
					Other *struct {
						Value string `json:"value"`
					} `json:"other"`
				}{
					Name: "self_reference",
					Other: &struct {
						Value string `json:"value"`
					}{
						Value: "other_value",
					},
				},
			},
			check: func(obj any) error {
				s := obj.(*struct {
					Self *struct {
						Name  string `json:"name"`
						Other *struct {
							Value string `json:"value"`
						} `json:"other"`
					} `json:"self"`
				})

				if s.Self.Name != maskedString {
					return fmt.Errorf("Self.Name: expected %q, got %q", maskedString, s.Self.Name)
				}
				if s.Self.Other.Value != maskedString {
					return fmt.Errorf("Self.Other.Value: expected %q, got %q", maskedString, s.Self.Other.Value)
				}

				return nil
			},
		},
	}

	for _, tc := range edgeCases {
		t.Run(tc.name, func(t *testing.T) {
			err := anonymizer.Anonymize(tc.object)
			if err != nil {
				t.Fatalf("failed to anonymize: %v", err)
			}

			if err := tc.check(tc.object); err != nil {
				t.Errorf("check failed: %v", err)
			}
		})
	}
}

// error cases tests
func TestAnonymizeErrorCases(t *testing.T) {
	anonymizer := createMockAnonymizer()

	errorCases := []struct {
		name        string
		object      any
		expectedErr error
	}{
		{
			name:        "immutable_string",
			object:      "immutable string",
			expectedErr: ErrObjectImmutable,
		},
		{
			name:        "immutable_int",
			object:      42,
			expectedErr: ErrObjectImmutable,
		},
		{
			name:        "immutable_struct_value",
			object:      SimpleStruct{Name: "test", Value: "value", Skip: "keep"},
			expectedErr: ErrObjectImmutable,
		},
		{
			name:        "nil_pointer",
			object:      (*SimpleStruct)(nil),
			expectedErr: ErrObjectImmutable,
		},
	}

	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			err := anonymizer.Anonymize(tc.object)
			if err != tc.expectedErr {
				t.Errorf("expected error %v, got %v", tc.expectedErr, err)
			}
		})
	}
}

// critical edge cases tests for pointer handling and special types
func TestAnonymizeCriticalEdgeCases(t *testing.T) {
	anonymizer := createMockAnonymizer()

	t.Run("pointer_handling", func(t *testing.T) {
		// create test data with various pointer types
		stringVal := "test_string"
		intVal := 42
		skipVal := "skip_value"

		originalStruct := &PointerTestStruct{
			StringPtr:    &stringVal,
			IntPtr:       &intVal,
			NilStringPtr: nil,
			NilIntPtr:    nil,
			StructPtr:    &SimpleStruct{Name: "struct_name", Value: "struct_value", Skip: "struct_skip"},
			NilStructPtr: nil,
			Skip:         &skipVal,
		}

		// store original pointer addresses for identity checks
		origStringPtr := originalStruct.StringPtr
		origIntPtr := originalStruct.IntPtr
		origStructPtr := originalStruct.StructPtr
		origSkipPtr := originalStruct.Skip

		err := anonymizer.Anonymize(originalStruct)
		if err != nil {
			t.Fatalf("failed to anonymize: %v", err)
		}

		// check that string pointer value is anonymized but pointer identity is preserved
		if err := checkStringPointer(originalStruct.StringPtr, maskedString, "StringPtr"); err != nil {
			t.Errorf("StringPtr check failed: %v", err)
		}
		if err := checkPointerIdentity(origStringPtr, originalStruct.StringPtr, "StringPtr"); err != nil {
			t.Errorf("StringPtr identity check failed: %v", err)
		}

		// check that int pointer remains unchanged (both value and identity)
		if originalStruct.IntPtr == nil || *originalStruct.IntPtr != 42 {
			t.Errorf("IntPtr value changed: expected 42, got %v", originalStruct.IntPtr)
		}
		if err := checkPointerIdentity(origIntPtr, originalStruct.IntPtr, "IntPtr"); err != nil {
			t.Errorf("IntPtr identity check failed: %v", err)
		}

		// check that nil pointers remain nil
		if err := checkNilPointer(originalStruct.NilStringPtr, "NilStringPtr"); err != nil {
			t.Errorf("NilStringPtr check failed: %v", err)
		}
		if err := checkNilPointer(originalStruct.NilIntPtr, "NilIntPtr"); err != nil {
			t.Errorf("NilIntPtr check failed: %v", err)
		}
		if err := checkNilPointer(originalStruct.NilStructPtr, "NilStructPtr"); err != nil {
			t.Errorf("NilStructPtr check failed: %v", err)
		}

		// check that struct pointer is anonymized but identity is preserved
		if originalStruct.StructPtr.Name != maskedString || originalStruct.StructPtr.Value != maskedString || originalStruct.StructPtr.Skip != "struct_skip" {
			t.Errorf("StructPtr values incorrect: %+v", originalStruct.StructPtr)
		}
		if err := checkPointerIdentity(origStructPtr, originalStruct.StructPtr, "StructPtr"); err != nil {
			t.Errorf("StructPtr identity check failed: %v", err)
		}

		// check that skip field pointer remains unchanged (both value and identity)
		if err := checkStringPointer(originalStruct.Skip, "skip_value", "Skip"); err != nil {
			t.Errorf("Skip check failed: %v", err)
		}
		if err := checkPointerIdentity(origSkipPtr, originalStruct.Skip, "Skip"); err != nil {
			t.Errorf("Skip identity check failed: %v", err)
		}
	})

	t.Run("special_types_preservation", func(t *testing.T) {
		// create struct with special types that should not be modified
		originalStruct := &SpecialTypesStruct{
			String: "test_string",
			Skip:   "skip_value",
		}

		// set some values in atomic types
		originalStruct.AtomicInt.Store(123)
		originalStruct.AtomicBool.Store(true)

		// store original addresses for identity checks
		origMutex := &originalStruct.Mutex
		origRWMutex := &originalStruct.RWMutex
		origAtomicInt := &originalStruct.AtomicInt
		origAtomicBool := &originalStruct.AtomicBool

		err := anonymizer.Anonymize(originalStruct)
		if err != nil {
			t.Fatalf("failed to anonymize: %v", err)
		}

		// check that string is anonymized
		if originalStruct.String != maskedString {
			t.Errorf("String not anonymized: expected %q, got %q", maskedString, originalStruct.String)
		}

		// check that skip field is not changed
		if originalStruct.Skip != "skip_value" {
			t.Errorf("Skip field changed: expected %q, got %q", "skip_value", originalStruct.Skip)
		}

		// check that special types are not modified (identity preserved)
		if err := checkPointerIdentity(origMutex, &originalStruct.Mutex, "Mutex"); err != nil {
			t.Errorf("Mutex identity check failed: %v", err)
		}
		if err := checkPointerIdentity(origRWMutex, &originalStruct.RWMutex, "RWMutex"); err != nil {
			t.Errorf("RWMutex identity check failed: %v", err)
		}
		if err := checkPointerIdentity(origAtomicInt, &originalStruct.AtomicInt, "AtomicInt"); err != nil {
			t.Errorf("AtomicInt identity check failed: %v", err)
		}
		if err := checkPointerIdentity(origAtomicBool, &originalStruct.AtomicBool, "AtomicBool"); err != nil {
			t.Errorf("AtomicBool identity check failed: %v", err)
		}

		// check that atomic values are preserved
		if originalStruct.AtomicInt.Load() != 123 {
			t.Errorf("AtomicInt value changed: expected 123, got %d", originalStruct.AtomicInt.Load())
		}
		if !originalStruct.AtomicBool.Load() {
			t.Errorf("AtomicBool value changed: expected true, got false")
		}
	})

	t.Run("deep_pointer_structures", func(t *testing.T) {
		level2String := "level2_string"
		level1String := "level1_string"

		originalStruct := &DeepPointerStruct{
			Level1: &struct {
				StringPtr *string `json:"string_ptr"`
				Level2    *struct {
					StringPtr *string `json:"string_ptr"`
					NilPtr    *string `json:"nil_ptr"`
				} `json:"level2"`
			}{
				StringPtr: &level1String,
				Level2: &struct {
					StringPtr *string `json:"string_ptr"`
					NilPtr    *string `json:"nil_ptr"`
				}{
					StringPtr: &level2String,
					NilPtr:    nil,
				},
			},
		}

		// store original pointer addresses
		origLevel1Ptr := originalStruct.Level1
		origLevel1StringPtr := originalStruct.Level1.StringPtr
		origLevel2Ptr := originalStruct.Level1.Level2
		origLevel2StringPtr := originalStruct.Level1.Level2.StringPtr

		err := anonymizer.Anonymize(originalStruct)
		if err != nil {
			t.Fatalf("failed to anonymize: %v", err)
		}

		// check that structure pointers are preserved
		if err := checkPointerIdentity(origLevel1Ptr, originalStruct.Level1, "Level1"); err != nil {
			t.Errorf("Level1 identity check failed: %v", err)
		}
		if err := checkPointerIdentity(origLevel2Ptr, originalStruct.Level1.Level2, "Level2"); err != nil {
			t.Errorf("Level2 identity check failed: %v", err)
		}

		// check that string pointers are preserved but values are anonymized
		if err := checkPointerIdentity(origLevel1StringPtr, originalStruct.Level1.StringPtr, "Level1.StringPtr"); err != nil {
			t.Errorf("Level1.StringPtr identity check failed: %v", err)
		}
		if err := checkStringPointer(originalStruct.Level1.StringPtr, maskedString, "Level1.StringPtr"); err != nil {
			t.Errorf("Level1.StringPtr value check failed: %v", err)
		}

		if err := checkPointerIdentity(origLevel2StringPtr, originalStruct.Level1.Level2.StringPtr, "Level2.StringPtr"); err != nil {
			t.Errorf("Level2.StringPtr identity check failed: %v", err)
		}
		if err := checkStringPointer(originalStruct.Level1.Level2.StringPtr, maskedString, "Level2.StringPtr"); err != nil {
			t.Errorf("Level2.StringPtr value check failed: %v", err)
		}

		// check that nil pointer remains nil
		if err := checkNilPointer(originalStruct.Level1.Level2.NilPtr, "Level2.NilPtr"); err != nil {
			t.Errorf("Level2.NilPtr check failed: %v", err)
		}
	})

	t.Run("map_with_pointers", func(t *testing.T) {
		stringVal1 := "string1"
		intVal := 42

		originalMap := map[string]any{
			"string_ptr":     &stringVal1,
			"nil_string_ptr": (*string)(nil),
			"int_ptr":        &intVal,
			"nil_int_ptr":    (*int)(nil),
			"struct_ptr":     &SimpleStruct{Name: "test", Value: "value", Skip: "skip"},
			"nil_struct_ptr": (*SimpleStruct)(nil),
		}

		// store original pointer addresses
		origStringPtr := originalMap["string_ptr"].(*string)
		origIntPtr := originalMap["int_ptr"].(*int)
		origStructPtr := originalMap["struct_ptr"].(*SimpleStruct)

		err := anonymizer.Anonymize(originalMap)
		if err != nil {
			t.Fatalf("failed to anonymize: %v", err)
		}

		// check string pointer
		if currentPtr, ok := originalMap["string_ptr"].(*string); ok {
			if err := checkPointerIdentity(origStringPtr, currentPtr, "string_ptr"); err != nil {
				t.Errorf("string_ptr identity check failed: %v", err)
			}
			if err := checkStringPointer(currentPtr, maskedString, "string_ptr"); err != nil {
				t.Errorf("string_ptr value check failed: %v", err)
			}
		} else {
			t.Errorf("string_ptr type changed")
		}

		// check int pointer
		if currentPtr, ok := originalMap["int_ptr"].(*int); ok {
			if err := checkPointerIdentity(origIntPtr, currentPtr, "int_ptr"); err != nil {
				t.Errorf("int_ptr identity check failed: %v", err)
			}
			if *currentPtr != 42 {
				t.Errorf("int_ptr value changed: expected 42, got %d", *currentPtr)
			}
		} else {
			t.Errorf("int_ptr type changed")
		}

		// check struct pointer
		if currentPtr, ok := originalMap["struct_ptr"].(*SimpleStruct); ok {
			if err := checkPointerIdentity(origStructPtr, currentPtr, "struct_ptr"); err != nil {
				t.Errorf("struct_ptr identity check failed: %v", err)
			}
			if currentPtr.Name != maskedString || currentPtr.Value != maskedString || currentPtr.Skip != "skip" {
				t.Errorf("struct_ptr values incorrect: %+v", currentPtr)
			}
		} else {
			t.Errorf("struct_ptr type changed")
		}

		// check nil pointers
		if err := checkNilPointer(originalMap["nil_string_ptr"], "nil_string_ptr"); err != nil {
			t.Errorf("nil_string_ptr check failed: %v", err)
		}
		if err := checkNilPointer(originalMap["nil_int_ptr"], "nil_int_ptr"); err != nil {
			t.Errorf("nil_int_ptr check failed: %v", err)
		}
		if err := checkNilPointer(originalMap["nil_struct_ptr"], "nil_struct_ptr"); err != nil {
			t.Errorf("nil_struct_ptr check failed: %v", err)
		}
	})

	t.Run("slice_with_pointers", func(t *testing.T) {
		stringVal1 := "slice_string1"
		stringVal2 := "slice_string2"
		intVal := 99

		originalSlice := []*string{&stringVal1, nil, &stringVal2}
		originalIntSlice := []*int{&intVal, nil}

		// store original addresses
		origPtr1 := originalSlice[0]
		origPtr3 := originalSlice[2]
		origIntPtr := originalIntSlice[0]

		err := anonymizer.Anonymize(originalSlice)
		if err != nil {
			t.Fatalf("failed to anonymize string slice: %v", err)
		}

		err = anonymizer.Anonymize(originalIntSlice)
		if err != nil {
			t.Fatalf("failed to anonymize int slice: %v", err)
		}

		// check string pointers
		if err := checkPointerIdentity(origPtr1, originalSlice[0], "slice[0]"); err != nil {
			t.Errorf("slice[0] identity check failed: %v", err)
		}
		if err := checkStringPointer(originalSlice[0], maskedString, "slice[0]"); err != nil {
			t.Errorf("slice[0] value check failed: %v", err)
		}

		if err := checkNilPointer(originalSlice[1], "slice[1]"); err != nil {
			t.Errorf("slice[1] nil check failed: %v", err)
		}

		if err := checkPointerIdentity(origPtr3, originalSlice[2], "slice[2]"); err != nil {
			t.Errorf("slice[2] identity check failed: %v", err)
		}
		if err := checkStringPointer(originalSlice[2], maskedString, "slice[2]"); err != nil {
			t.Errorf("slice[2] value check failed: %v", err)
		}

		// check int pointers (should remain unchanged)
		if err := checkPointerIdentity(origIntPtr, originalIntSlice[0], "intSlice[0]"); err != nil {
			t.Errorf("intSlice[0] identity check failed: %v", err)
		}
		if originalIntSlice[0] == nil || *originalIntSlice[0] != 99 {
			t.Errorf("intSlice[0] value changed: expected 99, got %v", originalIntSlice[0])
		}

		if err := checkNilPointer(originalIntSlice[1], "intSlice[1]"); err != nil {
			t.Errorf("intSlice[1] nil check failed: %v", err)
		}
	})

	t.Run("complex_nested_with_skip_tags", func(t *testing.T) {
		// test complex structure with skip tags at various levels
		type NestedWithSkips struct {
			ProcessData string `json:"process_data"`
			SkipField   string `json:"skip_field" anonymizer:"skip"`
			Inner       *struct {
				Value     string `json:"value"`
				SkipInner string `json:"skip_inner" anonymizer:"skip"`
			} `json:"inner"`
		}

		innerValue := "inner_value"
		innerSkip := "inner_skip"

		originalStruct := &NestedWithSkips{
			ProcessData: "process_this",
			SkipField:   "dont_process",
			Inner: &struct {
				Value     string `json:"value"`
				SkipInner string `json:"skip_inner" anonymizer:"skip"`
			}{
				Value:     innerValue,
				SkipInner: innerSkip,
			},
		}

		// store original pointer
		origInnerPtr := originalStruct.Inner

		err := anonymizer.Anonymize(originalStruct)
		if err != nil {
			t.Fatalf("failed to anonymize: %v", err)
		}

		// check that processed fields are anonymized
		if originalStruct.ProcessData != maskedString {
			t.Errorf("ProcessData not anonymized: expected %q, got %q", maskedString, originalStruct.ProcessData)
		}

		// check that skip fields are not changed
		if originalStruct.SkipField != "dont_process" {
			t.Errorf("SkipField changed: expected %q, got %q", "dont_process", originalStruct.SkipField)
		}

		// check inner structure pointer identity
		if err := checkPointerIdentity(origInnerPtr, originalStruct.Inner, "Inner"); err != nil {
			t.Errorf("Inner pointer identity check failed: %v", err)
		}

		// check inner values
		if originalStruct.Inner.Value != maskedString {
			t.Errorf("Inner.Value not anonymized: expected %q, got %q", maskedString, originalStruct.Inner.Value)
		}
		if originalStruct.Inner.SkipInner != "inner_skip" {
			t.Errorf("Inner.SkipInner changed: expected %q, got %q", "inner_skip", originalStruct.Inner.SkipInner)
		}
	})
}

// performance and memory tests
func TestAnonymizeLargeStructures(t *testing.T) {
	anonymizer := createMockAnonymizer()

	// create large nested structure
	largeMap := make(map[string]string)
	for i := range 1000 {
		largeMap[fmt.Sprintf("key_%d", i)] = fmt.Sprintf("value_%d", i)
	}

	largeSlice := make([]string, 1000)
	for i := range 1000 {
		largeSlice[i] = fmt.Sprintf("item_%d", i)
	}

	largeStruct := &struct {
		LargeMap   map[string]string `json:"large_map"`
		LargeSlice []string          `json:"large_slice"`
	}{
		LargeMap:   largeMap,
		LargeSlice: largeSlice,
	}

	err := anonymizer.Anonymize(largeStruct)
	if err != nil {
		t.Fatalf("failed to anonymize large structure: %v", err)
	}

	// verify all strings were masked
	for _, v := range largeStruct.LargeMap {
		if v != maskedString {
			t.Errorf("map value not masked: %s", v)
			break
		}
	}

	for _, v := range largeStruct.LargeSlice {
		if v != maskedString {
			t.Errorf("slice value not masked: %s", v)
			break
		}
	}
}

// additional comprehensive edge cases
func TestAnonymizeAdditionalEdgeCases(t *testing.T) {
	anonymizer := createMockAnonymizer()

	t.Run("channels_and_functions", func(t *testing.T) {
		// test that channels and functions are not modified
		type ChannelStruct struct {
			StringChan chan string   `json:"string_chan"`
			IntChan    chan int      `json:"int_chan"`
			Func       func() string `json:"func"`
			String     string        `json:"string"`
		}

		originalStruct := &ChannelStruct{
			StringChan: make(chan string, 1),
			IntChan:    make(chan int, 1),
			Func:       func() string { return "test" },
			String:     "test_string",
		}

		// store original addresses
		origStringChan := originalStruct.StringChan
		origIntChan := originalStruct.IntChan
		origFunc := fmt.Sprintf("%p", originalStruct.Func)

		err := anonymizer.Anonymize(originalStruct)
		if err != nil {
			t.Fatalf("failed to anonymize: %v", err)
		}

		// check that channels and functions are not modified
		if err := checkPointerIdentity(origStringChan, originalStruct.StringChan, "StringChan"); err != nil {
			t.Errorf("StringChan identity check failed: %v", err)
		}
		if err := checkPointerIdentity(origIntChan, originalStruct.IntChan, "IntChan"); err != nil {
			t.Errorf("IntChan identity check failed: %v", err)
		}

		currentFunc := fmt.Sprintf("%p", originalStruct.Func)
		if origFunc != currentFunc {
			t.Errorf("Function pointer changed: original %s, current %s", origFunc, currentFunc)
		}

		// check that string is anonymized
		if originalStruct.String != maskedString {
			t.Errorf("String not anonymized: expected %q, got %q", maskedString, originalStruct.String)
		}

		// verify function still works
		if originalStruct.Func() != "test" {
			t.Errorf("Function behavior changed")
		}
	})

	t.Run("interface_with_nil_and_pointers", func(t *testing.T) {
		stringVal := "interface_string"
		intVal := 42

		originalMap := map[string]any{
			"nil_interface":     nil,
			"string_interface":  "direct_string",
			"ptr_interface":     &stringVal,
			"int_interface":     intVal,
			"int_ptr_interface": &intVal,
		}

		// store original pointer
		origStringPtr := originalMap["ptr_interface"].(*string)
		origIntPtr := originalMap["int_ptr_interface"].(*int)

		err := anonymizer.Anonymize(originalMap)
		if err != nil {
			t.Fatalf("failed to anonymize: %v", err)
		}

		// check nil interface
		if originalMap["nil_interface"] != nil {
			t.Errorf("nil_interface should remain nil, got %v", originalMap["nil_interface"])
		}

		// check string interface
		if str, ok := originalMap["string_interface"].(string); !ok || str != maskedString {
			t.Errorf("string_interface: expected %q, got %v", maskedString, originalMap["string_interface"])
		}

		// check pointer interface (should preserve pointer identity)
		if currentPtr, ok := originalMap["ptr_interface"].(*string); ok {
			if err := checkPointerIdentity(origStringPtr, currentPtr, "ptr_interface"); err != nil {
				t.Errorf("ptr_interface identity check failed: %v", err)
			}
			if err := checkStringPointer(currentPtr, maskedString, "ptr_interface"); err != nil {
				t.Errorf("ptr_interface value check failed: %v", err)
			}
		} else {
			t.Errorf("ptr_interface type changed")
		}

		// check int interface (should remain unchanged)
		if val, ok := originalMap["int_interface"].(int); !ok || val != 42 {
			t.Errorf("int_interface changed: expected 42, got %v", originalMap["int_interface"])
		}

		// check int pointer interface (should preserve pointer identity and value)
		if currentPtr, ok := originalMap["int_ptr_interface"].(*int); ok {
			if err := checkPointerIdentity(origIntPtr, currentPtr, "int_ptr_interface"); err != nil {
				t.Errorf("int_ptr_interface identity check failed: %v", err)
			}
			if *currentPtr != 42 {
				t.Errorf("int_ptr_interface value changed: expected 42, got %d", *currentPtr)
			}
		} else {
			t.Errorf("int_ptr_interface type changed")
		}
	})

	t.Run("tree_structures_without_cycles", func(t *testing.T) {
		// test tree-like structures without circular references
		type Node struct {
			Value    string  `json:"value"`
			Skip     string  `json:"skip" anonymizer:"skip"`
			Children []*Node `json:"children"`
		}

		// create tree structure without parent references to avoid cycles
		child1 := &Node{Value: "child1", Skip: "child1_skip"}
		child2 := &Node{Value: "child2", Skip: "child2_skip"}
		root := &Node{
			Value:    "root",
			Skip:     "root_skip",
			Children: []*Node{child1, child2},
		}

		// store original pointers
		origRoot := root
		origChild1 := child1
		origChild2 := child2

		err := anonymizer.Anonymize(root)
		if err != nil {
			t.Fatalf("failed to anonymize: %v", err)
		}

		// check that structure pointers are preserved
		if err := checkPointerIdentity(origRoot, root, "root"); err != nil {
			t.Errorf("root identity check failed: %v", err)
		}
		if err := checkPointerIdentity(origChild1, root.Children[0], "child1"); err != nil {
			t.Errorf("child1 identity check failed: %v", err)
		}
		if err := checkPointerIdentity(origChild2, root.Children[1], "child2"); err != nil {
			t.Errorf("child2 identity check failed: %v", err)
		}

		// check that values are anonymized
		if root.Value != maskedString {
			t.Errorf("root.Value not anonymized: expected %q, got %q", maskedString, root.Value)
		}
		if child1.Value != maskedString {
			t.Errorf("child1.Value not anonymized: expected %q, got %q", maskedString, child1.Value)
		}
		if child2.Value != maskedString {
			t.Errorf("child2.Value not anonymized: expected %q, got %q", maskedString, child2.Value)
		}

		// check that skip fields are preserved
		if root.Skip != "root_skip" {
			t.Errorf("root.Skip changed: expected %q, got %q", "root_skip", root.Skip)
		}
		if child1.Skip != "child1_skip" {
			t.Errorf("child1.Skip changed: expected %q, got %q", "child1_skip", child1.Skip)
		}
		if child2.Skip != "child2_skip" {
			t.Errorf("child2.Skip changed: expected %q, got %q", "child2_skip", child2.Skip)
		}
	})

	t.Run("circular_reference_handling", func(t *testing.T) {
		// test that circular references are handled correctly
		type CircularNode struct {
			Value string        `json:"value"`
			Next  *CircularNode `json:"next"`
		}

		// create circular structure
		node1 := &CircularNode{Value: "node1"}
		node2 := &CircularNode{Value: "node2"}
		node1.Next = node2
		node2.Next = node1 // circular reference

		// store original pointers
		origNode1 := node1
		origNode2 := node2

		err := anonymizer.Anonymize(node1)
		if err != nil {
			t.Fatalf("failed to anonymize circular structure: %v", err)
		}

		// check that pointers are preserved
		if err := checkPointerIdentity(origNode1, node1, "node1"); err != nil {
			t.Errorf("node1 identity check failed: %v", err)
		}
		if err := checkPointerIdentity(origNode2, node1.Next, "node2"); err != nil {
			t.Errorf("node2 identity check failed: %v", err)
		}

		// check that values are anonymized
		if node1.Value != maskedString {
			t.Errorf("node1.Value not anonymized: expected %q, got %q", maskedString, node1.Value)
		}
		if node2.Value != maskedString {
			t.Errorf("node2.Value not anonymized: expected %q, got %q", maskedString, node2.Value)
		}

		// check that circular reference is preserved
		if node1.Next != node2 || node2.Next != node1 {
			t.Errorf("circular reference broken")
		}
	})
}
