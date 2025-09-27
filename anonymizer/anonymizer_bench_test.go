package anonymizer

import (
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/vxcontrol/cloud/anonymizer/patterns"
)

// benchmark test structures
type BenchmarkStruct struct {
	Name     string            `json:"name"`
	Email    string            `json:"email"`
	Token    string            `json:"token"`
	Skip     string            `json:"skip" anonymizer:"skip"`
	Age      int               `json:"age"`
	Active   bool              `json:"active"`
	Metadata map[string]string `json:"metadata"`
	Tags     []string          `json:"tags"`
}

type ComplexBenchmarkStruct struct {
	ID     string                      `json:"id"`
	Data   *BenchmarkStruct            `json:"data"`
	Items  []*BenchmarkStruct          `json:"items"`
	Groups map[string]*BenchmarkStruct `json:"groups"`
	Any    map[string]any              `json:"any"`
	Skip   string                      `json:"skip" anonymizer:"skip"`
}

type SpecialTypesBenchmark struct {
	Mutex      sync.Mutex     `json:"mutex"`
	RWMutex    sync.RWMutex   `json:"rwmutex"`
	AtomicInt  atomic.Int64   `json:"atomic_int"`
	AtomicBool atomic.Bool    `json:"atomic_bool"`
	UnsafePtr  unsafe.Pointer `json:"unsafe_ptr"`
	String     string         `json:"string"`
	Skip       string         `json:"skip" anonymizer:"skip"`
}

// benchmark data generators
func generateBenchmarkStruct() *BenchmarkStruct {
	return &BenchmarkStruct{
		Name:   "John Doe",
		Email:  "john.doe@example.com",
		Token:  "secret_token_12345",
		Skip:   "do_not_anonymize",
		Age:    30,
		Active: true,
		Metadata: map[string]string{
			"ip":      "192.168.1.1",
			"user_id": "user_12345",
			"session": "session_abc123",
		},
		Tags: []string{"admin", "privileged", "api_access"},
	}
}

func generateComplexBenchmarkStruct() *ComplexBenchmarkStruct {
	items := make([]*BenchmarkStruct, 10)
	for i := range items {
		items[i] = generateBenchmarkStruct()
		items[i].Name = fmt.Sprintf("User_%d", i)
	}

	groups := make(map[string]*BenchmarkStruct)
	for i := 0; i < 5; i++ {
		groups[fmt.Sprintf("group_%d", i)] = generateBenchmarkStruct()
	}

	return &ComplexBenchmarkStruct{
		ID:     "complex_struct_id",
		Data:   generateBenchmarkStruct(),
		Items:  items,
		Groups: groups,
		Any: map[string]any{
			"string": "any_string_value",
			"int":    42,
			"struct": *generateBenchmarkStruct(),
			"ptr":    generateBenchmarkStruct(),
			"slice":  []string{"a", "b", "c"},
			"nil":    nil,
		},
		Skip: "complex_skip_value",
	}
}

func generateSpecialTypesBenchmark() *SpecialTypesBenchmark {
	s := &SpecialTypesBenchmark{
		String: "test_string",
		Skip:   "skip_value",
	}
	s.AtomicInt.Store(123)
	s.AtomicBool.Store(true)
	return s
}

// benchmarks for different structure types
func BenchmarkAnonymize_SimpleStruct(b *testing.B) {
	anonymizer := createMockAnonymizer()

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		data := generateBenchmarkStruct()
		err := anonymizer.Anonymize(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnonymize_ComplexStruct(b *testing.B) {
	anonymizer := createMockAnonymizer()

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		data := generateComplexBenchmarkStruct()
		err := anonymizer.Anonymize(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnonymize_SpecialTypes(b *testing.B) {
	anonymizer := createMockAnonymizer()

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		data := generateSpecialTypesBenchmark()
		err := anonymizer.Anonymize(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// benchmarks for different collection types
func BenchmarkAnonymize_MapStringString(b *testing.B) {
	anonymizer := createMockAnonymizer()

	// generate test data
	data := make(map[string]string)
	for i := 0; i < 100; i++ {
		data[fmt.Sprintf("key_%d", i)] = fmt.Sprintf("value_%d", i)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		// create fresh copy for each iteration
		testData := make(map[string]string)
		for k, v := range data {
			testData[k] = v
		}

		err := anonymizer.Anonymize(testData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnonymize_SliceStrings(b *testing.B) {
	anonymizer := createMockAnonymizer()

	// generate test data
	data := make([]string, 100)
	for i := range data {
		data[i] = fmt.Sprintf("string_value_%d", i)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		// create fresh copy for each iteration
		testData := make([]string, len(data))
		copy(testData, data)

		err := anonymizer.Anonymize(testData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnonymize_MapStringAny(b *testing.B) {
	anonymizer := createMockAnonymizer()

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		data := map[string]any{
			"string":     "test_string",
			"int":        42,
			"struct":     *generateBenchmarkStruct(),
			"ptr_struct": generateBenchmarkStruct(),
			"slice":      []string{"a", "b", "c"},
			"map":        map[string]string{"nested": "value"},
			"nil":        nil,
		}

		err := anonymizer.Anonymize(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// benchmarks for struct caching efficiency
func BenchmarkAnonymize_StructCaching_SameType(b *testing.B) {
	anonymizer := createMockAnonymizer()

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		// same struct type - should hit cache after first parse
		data := generateBenchmarkStruct()
		err := anonymizer.Anonymize(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnonymize_StructCaching_DifferentTypes(b *testing.B) {
	anonymizer := createMockAnonymizer()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; b.Loop(); i++ {
		// different struct types - will require parsing each time
		switch i % 3 {
		case 0:
			data := generateBenchmarkStruct()
			err := anonymizer.Anonymize(data)
			if err != nil {
				b.Fatal(err)
			}
		case 1:
			data := generateComplexBenchmarkStruct()
			err := anonymizer.Anonymize(data)
			if err != nil {
				b.Fatal(err)
			}
		case 2:
			data := generateSpecialTypesBenchmark()
			err := anonymizer.Anonymize(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

// benchmarks for memory allocation patterns
func BenchmarkAnonymize_LargeMap(b *testing.B) {
	anonymizer := createMockAnonymizer()

	sizes := []int{100, 500, 1000, 5000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for b.Loop() {
				data := make(map[string]string)
				for i := 0; i < size; i++ {
					data[fmt.Sprintf("key_%d", i)] = fmt.Sprintf("sensitive_value_%d", i)
				}

				err := anonymizer.Anonymize(data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkAnonymize_LargeSlice(b *testing.B) {
	anonymizer := createMockAnonymizer()

	sizes := []int{100, 500, 1000, 5000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for b.Loop() {
				data := make([]string, size)
				for i := range data {
					data[i] = fmt.Sprintf("sensitive_string_%d", i)
				}

				err := anonymizer.Anonymize(data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkAnonymize_DeepNesting(b *testing.B) {
	anonymizer := createMockAnonymizer()

	depths := []int{5, 10, 20, 50}

	for _, depth := range depths {
		b.Run(fmt.Sprintf("depth_%d", depth), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for b.Loop() {
				// create deeply nested structure
				data := &struct {
					Value string      `json:"value"`
					Next  interface{} `json:"next"`
				}{Value: "root"}

				current := data
				for i := 0; i < depth; i++ {
					next := &struct {
						Value string      `json:"value"`
						Next  interface{} `json:"next"`
					}{Value: fmt.Sprintf("level_%d", i)}
					current.Next = next
					current = next
				}

				err := anonymizer.Anonymize(data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// benchmarks comparing with naive implementations
func BenchmarkAnonymize_vs_Naive_SimpleStruct(b *testing.B) {
	anonymizer := createMockAnonymizer()

	b.Run("optimized", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			data := generateBenchmarkStruct()
			err := anonymizer.Anonymize(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("naive_reflection", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			data := generateBenchmarkStruct()
			// naive implementation without caching
			naiveAnonymizeStruct(data)
		}
	})
}

// naive implementation for comparison (without caching)
func naiveAnonymizeStruct(v any) {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return
	}

	elem := rv.Elem()
	if elem.Kind() != reflect.Struct {
		return
	}

	// parse struct every time (no caching)
	for i := 0; i < elem.NumField(); i++ {
		field := elem.Field(i)
		if field.Kind() == reflect.String && field.CanSet() {
			field.SetString(maskedString)
		}
	}
}

// benchmark for pointer handling efficiency
func BenchmarkAnonymize_PointerHandling(b *testing.B) {
	anonymizer := createMockAnonymizer()

	b.Run("many_pointers", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			// structure with many pointer fields
			str1, str2, str3 := "value1", "value2", "value3"
			data := &struct {
				Ptr1 *string `json:"ptr1"`
				Ptr2 *string `json:"ptr2"`
				Ptr3 *string `json:"ptr3"`
				Nil1 *string `json:"nil1"`
				Nil2 *string `json:"nil2"`
			}{
				Ptr1: &str1,
				Ptr2: &str2,
				Ptr3: &str3,
				Nil1: nil,
				Nil2: nil,
			}

			err := anonymizer.Anonymize(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("deep_pointers", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			// deeply nested pointer structure
			level3String := "deep_value"
			data := &struct {
				Level1 *struct {
					Level2 *struct {
						Level3 *struct {
							Value *string `json:"value"`
						} `json:"level3"`
					} `json:"level2"`
				} `json:"level1"`
			}{
				Level1: &struct {
					Level2 *struct {
						Level3 *struct {
							Value *string `json:"value"`
						} `json:"level3"`
					} `json:"level2"`
				}{
					Level2: &struct {
						Level3 *struct {
							Value *string `json:"value"`
						} `json:"level3"`
					}{
						Level3: &struct {
							Value *string `json:"value"`
						}{
							Value: &level3String,
						},
					},
				},
			}

			err := anonymizer.Anonymize(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// benchmark for circular reference handling
func BenchmarkAnonymize_CircularReferences(b *testing.B) {
	anonymizer := createMockAnonymizer()

	type CircularNode struct {
		Value string        `json:"value"`
		Next  *CircularNode `json:"next"`
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		// create circular structure
		node1 := &CircularNode{Value: "node1"}
		node2 := &CircularNode{Value: "node2"}
		node3 := &CircularNode{Value: "node3"}

		node1.Next = node2
		node2.Next = node3
		node3.Next = node1 // circular reference

		err := anonymizer.Anonymize(node1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// benchmark for real-world production patterns
func BenchmarkAnonymize_ProductionPatterns(b *testing.B) {
	// create anonymizer with real patterns
	anonymizer, err := NewAnonymizer([]patterns.Pattern{})
	if err != nil {
		b.Skip("failed to create production anonymizer")
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		data := generateComplexBenchmarkStruct()
		err := anonymizer.Anonymize(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// benchmark for struct parsing vs caching
func BenchmarkStructParsing_vs_Caching(b *testing.B) {
	type TestStruct struct {
		Field1 string `json:"field1"`
		Field2 string `json:"field2"`
		Field3 string `json:"field3"`
		Skip   string `json:"skip" anonymizer:"skip"`
	}

	b.Run("with_caching", func(b *testing.B) {
		anonymizer := createMockAnonymizer()

		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			data := &TestStruct{
				Field1: "value1",
				Field2: "value2",
				Field3: "value3",
				Skip:   "skip_value",
			}
			err := anonymizer.Anonymize(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("without_caching", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			data := &TestStruct{
				Field1: "value1",
				Field2: "value2",
				Field3: "value3",
				Skip:   "skip_value",
			}
			// naive implementation - parse struct every time
			naiveAnonymizeStruct(data)
		}
	})
}

// benchmark for memory allocation patterns
func BenchmarkAnonymize_AllocationPatterns(b *testing.B) {
	anonymizer := createMockAnonymizer()

	b.Run("struct_reuse", func(b *testing.B) {
		// reuse the same struct instance
		data := generateBenchmarkStruct()

		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			// reset values
			data.Name = "John Doe"
			data.Email = "john.doe@example.com"
			data.Token = "secret_token_12345"

			err := anonymizer.Anonymize(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("struct_recreation", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			// create new struct each time
			data := generateBenchmarkStruct()
			err := anonymizer.Anonymize(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// benchmark for concurrent usage
func BenchmarkAnonymize_Concurrent(b *testing.B) {
	anonymizer := createMockAnonymizer()

	b.Run("parallel_simple_structs", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				data := generateBenchmarkStruct()
				err := anonymizer.Anonymize(data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})

	b.Run("parallel_complex_structs", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				data := generateComplexBenchmarkStruct()
				err := anonymizer.Anonymize(data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})
}

// benchmark for edge case performance
func BenchmarkAnonymize_EdgeCases(b *testing.B) {
	anonymizer := createMockAnonymizer()

	b.Run("many_nil_pointers", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			data := &struct {
				Ptr1  *string `json:"ptr1"`
				Ptr2  *string `json:"ptr2"`
				Ptr3  *string `json:"ptr3"`
				Ptr4  *string `json:"ptr4"`
				Ptr5  *string `json:"ptr5"`
				Value string  `json:"value"`
			}{
				// all pointers are nil
				Value: "only_this_value",
			}

			err := anonymizer.Anonymize(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("many_skip_fields", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			data := &struct {
				Skip1 string `json:"skip1" anonymizer:"skip"`
				Skip2 string `json:"skip2" anonymizer:"skip"`
				Skip3 string `json:"skip3" anonymizer:"skip"`
				Skip4 string `json:"skip4" anonymizer:"skip"`
				Skip5 string `json:"skip5" anonymizer:"skip"`
				Value string `json:"value"`
			}{
				Skip1: "skip1",
				Skip2: "skip2",
				Skip3: "skip3",
				Skip4: "skip4",
				Skip5: "skip5",
				Value: "process_this",
			}

			err := anonymizer.Anonymize(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("empty_collections", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			data := &struct {
				EmptyMap   map[string]string `json:"empty_map"`
				EmptySlice []string          `json:"empty_slice"`
				NilMap     map[string]string `json:"nil_map"`
				NilSlice   []string          `json:"nil_slice"`
				Value      string            `json:"value"`
			}{
				EmptyMap:   make(map[string]string),
				EmptySlice: make([]string, 0),
				NilMap:     nil,
				NilSlice:   nil,
				Value:      "process_this",
			}

			err := anonymizer.Anonymize(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// benchmark for worst-case scenarios
func BenchmarkAnonymize_WorstCase(b *testing.B) {
	anonymizer := createMockAnonymizer()

	b.Run("all_strings_need_processing", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			// structure where every field is a string that needs processing
			data := &struct {
				F1  string `json:"f1"`
				F2  string `json:"f2"`
				F3  string `json:"f3"`
				F4  string `json:"f4"`
				F5  string `json:"f5"`
				F6  string `json:"f6"`
				F7  string `json:"f7"`
				F8  string `json:"f8"`
				F9  string `json:"f9"`
				F10 string `json:"f10"`
			}{
				F1: "value1", F2: "value2", F3: "value3", F4: "value4", F5: "value5",
				F6: "value6", F7: "value7", F8: "value8", F9: "value9", F10: "value10",
			}

			err := anonymizer.Anonymize(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("mixed_with_many_allocations", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			// structure that requires many allocations for map[string]any
			data := map[string]any{
				"s1": "string1", "s2": "string2", "s3": "string3",
				"i1": 1, "i2": 2, "i3": 3,
				"struct1": BenchmarkStruct{Name: "n1", Email: "e1"},
				"struct2": BenchmarkStruct{Name: "n2", Email: "e2"},
				"slice1":  []string{"a", "b", "c"},
				"slice2":  []string{"d", "e", "f"},
				"map1":    map[string]string{"k1": "v1"},
				"map2":    map[string]string{"k2": "v2"},
			}

			err := anonymizer.Anonymize(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// benchmark for best-case scenarios
func BenchmarkAnonymize_BestCase(b *testing.B) {
	anonymizer := createMockAnonymizer()

	b.Run("no_strings_to_process", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			// structure with no strings to anonymize
			data := &struct {
				Int1   int     `json:"int1"`
				Int2   int     `json:"int2"`
				Bool1  bool    `json:"bool1"`
				Bool2  bool    `json:"bool2"`
				Float1 float64 `json:"float1"`
				Float2 float64 `json:"float2"`
			}{
				Int1: 1, Int2: 2, Bool1: true, Bool2: false, Float1: 1.1, Float2: 2.2,
			}

			err := anonymizer.Anonymize(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("all_skip_fields", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			// structure where all string fields are marked as skip
			data := &struct {
				Skip1 string `json:"skip1" anonymizer:"skip"`
				Skip2 string `json:"skip2" anonymizer:"skip"`
				Skip3 string `json:"skip3" anonymizer:"skip"`
				Skip4 string `json:"skip4" anonymizer:"skip"`
				Skip5 string `json:"skip5" anonymizer:"skip"`
			}{
				Skip1: "value1", Skip2: "value2", Skip3: "value3", Skip4: "value4", Skip5: "value5",
			}

			err := anonymizer.Anonymize(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// benchmark for memory efficiency
func BenchmarkAnonymize_MemoryEfficiency(b *testing.B) {
	anonymizer := createMockAnonymizer()

	b.Run("reuse_visited_map", func(b *testing.B) {
		// test if visited map is efficiently managed
		data := generateComplexBenchmarkStruct()

		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			// reset string values
			data.ID = "complex_struct_id"
			data.Data.Name = "John Doe"
			data.Data.Email = "john.doe@example.com"

			err := anonymizer.Anonymize(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("large_visited_map", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			// create structure with many unique pointers
			data := make(map[string]*BenchmarkStruct)
			for i := 0; i < 100; i++ {
				data[fmt.Sprintf("key_%d", i)] = generateBenchmarkStruct()
			}

			err := anonymizer.Anonymize(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
