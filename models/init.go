package models

import (
	"crypto/ed25519"
	"reflect"
	"regexp"

	"github.com/go-playground/validator/v10"
)

const (
	semverRegexString   = `^(([0-9]+\.[0-9]+(\.[0-9]+)?)|latest)$`
	semverexRegexString = `^(((v)?[0-9]+\.[0-9]+(\.[0-9]+)?(\.[0-9]+)?(-[a-zA-Z0-9]+)?)|latest)$`
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
	_ = validate.RegisterValidation("valid", deepValidator())

	_, _ = reflect.ValueOf(ComponentType("")).Interface().(IValid)
	_, _ = reflect.ValueOf(ComponentStatus("")).Interface().(IValid)
	_, _ = reflect.ValueOf(ProductStack("")).Interface().(IValid)
	_, _ = reflect.ValueOf(OSType("")).Interface().(IValid)
	_, _ = reflect.ValueOf(ArchType("")).Interface().(IValid)

	// signature service models validation
	_, _ = reflect.ValueOf(SignatureValue("")).Interface().(IValid)

	// update service models validation
	_, _ = reflect.ValueOf(CheckUpdatesRequest{}).Interface().(IValid)
	_, _ = reflect.ValueOf(ComponentInfo{}).Interface().(IValid)
	_, _ = reflect.ValueOf(CheckUpdatesResponse{}).Interface().(IValid)
	_, _ = reflect.ValueOf(UpdateInfo{}).Interface().(IValid)

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
}
