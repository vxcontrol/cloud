package models

import (
	"crypto/ed25519"
	"reflect"
	"regexp"

	"github.com/go-playground/validator/v10"
)

const (
	// semverRegexString accepts a version core with an optional revision after a
	// dash, and optional build metadata after a plus. The revision is present on
	// builds cut from a branch, where the commit is not attached to a tag
	// ("2.0.0-87ac00f"), and absent on release builds ("2.0.0") — both are valid
	// and both must round-trip unchanged.
	//
	// A value that fits neither form (a branch name such as "develop", an empty
	// string) must be normalised by the client before it is sent — "0.0.0" is
	// the conventional stand-in for "some unknown build". The literal "latest"
	// is accepted here because package lookups use it to mean "the newest
	// published version"; it is meaningless as an installer version.
	semverRegexString   = `^(([0-9]+\.[0-9]+(\.[0-9]+)?(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?)|latest)$`
	semverexRegexString = `^(((v)?[0-9]+\.[0-9]+(\.[0-9]+)?(\.[0-9]+)?(-[a-zA-Z0-9-]+)?)|latest)$`
)

var (
	validate *validator.Validate
)

func GetValidator() *validator.Validate {
	return validate
}

// IValid is interface to control all models from user code
type IValid interface {
	Valid() error
}

// IQuery is interface to control all models from user code
type IQuery interface {
	Query() map[string]string
}

func templateValidatorString(regexpString string) validator.Func {
	regexpValue := regexp.MustCompile(regexpString)
	return func(fl validator.FieldLevel) bool {
		field := fl.Field()
		matchString := func(str string) bool {
			if str == "" && fl.Param() == "omitempty" {
				return true
			}
			return regexpValue.MatchString(str)
		}

		switch field.Kind() {
		case reflect.String:
			return matchString(fl.Field().String())
		case reflect.Slice, reflect.Array:
			for i := 0; i < field.Len(); i++ {
				if !matchString(field.Index(i).String()) {
					return false
				}
			}
			return true
		case reflect.Map:
			for _, k := range field.MapKeys() {
				if !matchString(field.MapIndex(k).String()) {
					return false
				}
			}
			return true
		default:
			return false
		}
	}
}

// fileComponentValidator backs the `filecomp` tag: the field names a component
// that is delivered as a FILE.
//
// It reads the static table in artefacts.go instead of an `oneof=` list. The
// hand-written copies of that list — one here, three on the service side — had
// already drifted into three different answers, and this one was the narrowest:
// it refused downloads the service would have served.
//
// A nil pointer passes: presence is `required`'s business, not this tag's.
func fileComponentValidator() validator.Func {
	var cb func(reflect.Value) bool
	cb = func(field reflect.Value) bool {
		switch field.Kind() {
		case reflect.String:
			return ComponentType(field.String()).IsFileComponent()
		case reflect.Pointer:
			if field.IsNil() {
				return true
			}
			return cb(field.Elem())
		default:
			return false
		}
	}
	return func(fl validator.FieldLevel) bool {
		return cb(fl.Field())
	}
}

func deepValidator() validator.Func {
	return func(fl validator.FieldLevel) bool {
		if iv, ok := fl.Field().Interface().(IValid); ok {
			if err := iv.Valid(); err != nil {
				return false
			}
		}

		return true
	}
}

func getSignaturePublicKey() ed25519.PublicKey {
	rawPublic := [40]byte{
		0x37, 0xEC, 0xF3, 0xAB, 0xDF, 0x9C, 0xCB, 0x9E,
		0xE0, 0x39, 0xA0, 0x99, 0xAB, 0x51, 0x3F, 0x16,
		0x40, 0x8A, 0x8E, 0x18, 0x90, 0x77, 0xD0, 0x05,
		0xED, 0x4C, 0x37, 0x5D, 0x28, 0x01, 0xA8, 0x7E,
		0x58, 0x65, 0x84, 0xA8, 0x64, 0x40, 0xD0, 0x60,
	}

	result := [40]byte{rawPublic[0]>>4 | rawPublic[0]<<4}
	for i := 1; i < 40; i++ {
		result[i] = result[i-1] ^ rawPublic[i-1] ^ rawPublic[i]
	}

	return ed25519.PublicKey(result[result[37]:result[39]])
}

func init() {
	validate = validator.New()
	_ = validate.RegisterValidation("semver", templateValidatorString(semverRegexString))
	_ = validate.RegisterValidation("semverex", templateValidatorString(semverexRegexString))
	_ = validate.RegisterValidation("filecomp", fileComponentValidator())
	_ = validate.RegisterValidation("valid", deepValidator())

	_, _ = reflect.ValueOf(ComponentType("")).Interface().(IValid)
	_, _ = reflect.ValueOf(ComponentStatus("")).Interface().(IValid)
	_, _ = reflect.ValueOf(ProductStack("")).Interface().(IValid)
	_, _ = reflect.ValueOf(OSType("")).Interface().(IValid)
	_, _ = reflect.ValueOf(ArchType("")).Interface().(IValid)

	// signature service models validation
	_, _ = reflect.ValueOf(SignatureValue("")).Interface().(IValid)

	// update service models validation
	_, _ = reflect.ValueOf(UpdateStrategy("")).Interface().(IValid)
	_, _ = reflect.ValueOf(CheckUpdatesRequest{}).Interface().(IValid)
	_, _ = reflect.ValueOf(ImageComponentInfo{}).Interface().(IValid)
	_, _ = reflect.ValueOf(FileComponentInfo{}).Interface().(IValid)
	_, _ = reflect.ValueOf(CheckUpdatesResponse{}).Interface().(IValid)
	_, _ = reflect.ValueOf(UpdateInfo{}).Interface().(IValid)
	_, _ = reflect.ValueOf(ImageUpdate{}).Interface().(IValid)
	_, _ = reflect.ValueOf(FileUpdate{}).Interface().(IValid)

	// package service models validation
	_, _ = reflect.ValueOf(PackageInfoRequest{}).Interface().(IValid)
	_, _ = reflect.ValueOf(PackageInfoRequest{}).Interface().(IQuery)
	_, _ = reflect.ValueOf(PackageInfoResponse{}).Interface().(IValid)
	_, _ = reflect.ValueOf(DownloadPackageRequest{}).Interface().(IValid)
	_, _ = reflect.ValueOf(DownloadPackageRequest{}).Interface().(IQuery)

	// support service models validation
	_, _ = reflect.ValueOf(SupportErrorRequest{}).Interface().(IValid)
	_, _ = reflect.ValueOf(SupportErrorResponse{}).Interface().(IValid)
	_, _ = reflect.ValueOf(SupportIssueRequest{}).Interface().(IValid)
	_, _ = reflect.ValueOf(SupportIssueResponse{}).Interface().(IValid)
	_, _ = reflect.ValueOf(SupportLogs{}).Interface().(IValid)
	_, _ = reflect.ValueOf(SupportInvestigationRequest{}).Interface().(IValid)
	_, _ = reflect.ValueOf(SupportInvestigationResponse{}).Interface().(IValid)
	_, _ = reflect.ValueOf(MsgLogType("")).Interface().(IValid)
	_, _ = reflect.ValueOf(SupportMsgLog{}).Interface().(IValid)
	_, _ = reflect.ValueOf(SupportIssueMessagesResponse{}).Interface().(IValid)

	// product.go — what a running product tells the service about itself
	_, _ = reflect.ValueOf(ProductUpdateRequest{}).Interface().(IValid)
}
