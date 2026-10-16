package anonymizer

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vxcontrol/cloud/models"
)

// supportIssueDetailsKept are the fields of models.SupportIssueDetails, by their JSON
// names, that anonymisation must leave as they are: closed vocabularies, versions and
// references a reader matches as written — a provider_ref rewritten no longer names its
// provider, a severity rewritten is no severity. Every other string of the document is
// free text and must be anonymised; a field added to the schema is free text until it is
// named here and tagged anonymizer:"skip" in the model.
var supportIssueDetailsKept = map[string]bool{
	"schema": true, "version": true, "os": true, "arch": true, "binary_hash": true,
	"type": true, "source": true, "status": true, "tier": true, "state": true,
	"provider_type": true, "provider_ref": true, "agent": true, "agents": true,
	"kind": true, "error_class": true, "code": true, "severity": true,
	"docker_version": true, "kernel": true, "os_type": true, "architecture": true,
	"ref": true, "live": true, "embedding_provider": true,
}

// The product builds the document and hands a pointer to it to Anonymize, which must
// replace its free text and keep what the model tags anonymizer:"skip". The document is
// filled by reflection — every string set, every list and map holding an element, every
// optional part present — so that a field added to the schema later is checked without
// this test changing: it is anonymised unless it is named in supportIssueDetailsKept.
// Times are structs of unexported fields to the walk and must come out unchanged, and the
// keys of maps, names of closed sets, are never touched.
func TestAnonymizeReplacesTheFreeTextOfSupportIssueDetails(t *testing.T) {
	const text = "free text"
	moment := time.Date(2026, 10, 16, 10, 0, 0, 0, time.UTC)

	var details models.SupportIssueDetails
	fillSupportIssueDetails(reflect.ValueOf(&details).Elem(), text, moment)

	if err := createMockAnonymizer().Anonymize(&details); err != nil {
		t.Fatalf("the document is not anonymised: %v", err)
	}

	seen := map[string]bool{}
	var check func(v reflect.Value, field, path string)
	check = func(v reflect.Value, field, path string) {
		switch v.Kind() {
		case reflect.Pointer:
			if v.IsNil() {
				t.Errorf("%s was emptied", path)
				return
			}
			check(v.Elem(), field, path)
		case reflect.Struct:
			if v.Type() == reflect.TypeOf(moment) {
				if !v.Interface().(time.Time).Equal(moment) {
					t.Errorf("%s is %v, want %v", path, v.Interface(), moment)
				}
				return
			}
			for i := 0; i < v.NumField(); i++ {
				sf := v.Type().Field(i)
				name := strings.Split(sf.Tag.Get("json"), ",")[0]
				if sf.Anonymous && name == "" {
					// the fields of an embedded struct travel in line, under their own names
					check(v.Field(i), field, path)
					continue
				}
				seen[name] = true
				check(v.Field(i), name, path+"."+name)
			}
		case reflect.Slice:
			if v.Len() == 0 {
				t.Errorf("%s was emptied", path)
			}
			for i := 0; i < v.Len(); i++ {
				check(v.Index(i), field, path+"[]")
			}
		case reflect.Map:
			if v.Len() != 1 || !v.MapIndex(reflect.ValueOf("name")).IsValid() {
				t.Errorf("the keys of %s changed: %v", path, v.MapKeys())
			}
			for _, key := range v.MapKeys() {
				check(v.MapIndex(key), field, path+"{}")
			}
		case reflect.String:
			got := v.String()
			switch {
			case supportIssueDetailsKept[field] && got != text:
				t.Errorf("%s is %q: a field of a closed vocabulary was anonymised", path, got)
			case !supportIssueDetailsKept[field] && got != maskedString:
				t.Errorf("%s is %q: free text was not anonymised", path, got)
			}
		}
	}
	check(reflect.ValueOf(details), "", "details")

	// a name in the list that the document does not have keeps nothing, and hides that the
	// field it meant was renamed and is now anonymised
	for name := range supportIssueDetailsKept {
		if !seen[name] {
			t.Errorf("%s is kept, and the document has no field of that name", name)
		}
	}
}

// fillSupportIssueDetails sets every field reachable from v: strings to text, numbers and
// booleans to something other than their zero, times to moment, a pointer to a new value,
// a list to one element and a map to one entry under the key "name".
func fillSupportIssueDetails(v reflect.Value, text string, moment time.Time) {
	switch v.Kind() {
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fillSupportIssueDetails(v.Elem(), text, moment)
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(moment) {
			v.Set(reflect.ValueOf(moment))
			return
		}
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				fillSupportIssueDetails(v.Field(i), text, moment)
			}
		}
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		fillSupportIssueDetails(v.Index(0), text, moment)
	case reflect.Map:
		entry := reflect.New(v.Type().Elem()).Elem()
		fillSupportIssueDetails(entry, text, moment)
		v.Set(reflect.MakeMap(v.Type()))
		v.SetMapIndex(reflect.ValueOf("name"), entry)
	case reflect.String:
		v.SetString(text)
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(7)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(7)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(7.5)
	}
}
