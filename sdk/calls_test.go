package sdk

import (
	"testing"
)

func TestCallTypeValidation(t *testing.T) {
	// test all valid call types
	validTypes := []any{
		(*CallReqRespBytes)(nil),
		(*CallReqRespReader)(nil),
		(*CallReqRespWriter)(nil),
		(*CallReqQueryRespBytes)(nil),
		(*CallReqQueryRespReader)(nil),
		(*CallReqQueryRespWriter)(nil),
		(*CallReqWithArgsRespBytes)(nil),
		(*CallReqWithArgsRespReader)(nil),
		(*CallReqWithArgsRespWriter)(nil),
		(*CallReqQueryWithArgsRespBytes)(nil),
		(*CallReqQueryWithArgsRespReader)(nil),
		(*CallReqQueryWithArgsRespWriter)(nil),
		(*CallReqBytesRespBytes)(nil),
		(*CallReqBytesRespReader)(nil),
		(*CallReqBytesRespWriter)(nil),
		(*CallReqReaderRespBytes)(nil),
		(*CallReqReaderRespReader)(nil),
		(*CallReqReaderRespWriter)(nil),
		(*CallReqBytesWithArgsRespBytes)(nil),
		(*CallReqBytesWithArgsRespReader)(nil),
		(*CallReqBytesWithArgsRespWriter)(nil),
		(*CallReqReaderWithArgsRespBytes)(nil),
		(*CallReqReaderWithArgsRespReader)(nil),
		(*CallReqReaderWithArgsRespWriter)(nil),
	}

	for _, call := range validTypes {
		if err := checkCallType(call); err != nil {
			t.Errorf("checkCallType(%T) should be valid, got error: %v", call, err)
		}
	}

	// test invalid types
	invalidTypes := []any{
		nil,
		"string",
		123,
		struct{}{},
		(*string)(nil),
	}

	for _, call := range invalidTypes {
		if err := checkCallType(call); err == nil {
			t.Errorf("checkCallType(%T) should be invalid", call)
		}
	}
}

func TestCallTypeHelpers(t *testing.T) {
	t.Run("isCallWithArgs", func(t *testing.T) {
		tests := []struct {
			call any
			want bool
		}{
			{(*CallReqWithArgsRespBytes)(nil), true},
			{(*CallReqQueryWithArgsRespReader)(nil), true},
			{(*CallReqBytesWithArgsRespWriter)(nil), true},
			{(*CallReqRespBytes)(nil), false},
			{(*CallReqQueryRespBytes)(nil), false},
		}

		for _, tt := range tests {
			got := isCallWithArgs(tt.call)
			if got != tt.want {
				t.Errorf("isCallWithArgs(%T) = %v, want %v", tt.call, got, tt.want)
			}
		}
	})

	t.Run("isCallWithBody", func(t *testing.T) {
		tests := []struct {
			call any
			want bool
		}{
			{(*CallReqBytesRespBytes)(nil), true},
			{(*CallReqReaderRespReader)(nil), true},
			{(*CallReqBytesWithArgsRespWriter)(nil), true},
			{(*CallReqRespBytes)(nil), false},
			{(*CallReqQueryRespBytes)(nil), false},
		}

		for _, tt := range tests {
			got := isCallWithBody(tt.call)
			if got != tt.want {
				t.Errorf("isCallWithBody(%T) = %v, want %v", tt.call, got, tt.want)
			}
		}
	})

	t.Run("isCallWithQuery", func(t *testing.T) {
		tests := []struct {
			call any
			want bool
		}{
			{(*CallReqQueryRespBytes)(nil), true},
			{(*CallReqQueryWithArgsRespReader)(nil), true},
			{(*CallReqRespBytes)(nil), false},
			{(*CallReqBytesRespBytes)(nil), false},
		}

		for _, tt := range tests {
			got := isCallWithQuery(tt.call)
			if got != tt.want {
				t.Errorf("isCallWithQuery(%T) = %v, want %v", tt.call, got, tt.want)
			}
		}
	})
}

func TestFillCallFunc(t *testing.T) {
	sdkPtr := defaultSDK()
	pathGen := func(args []string) (string, error) {
		return "/test", nil
	}

	t.Run("single_call", func(t *testing.T) {
		var testCall CallReqRespBytes
		cfg := CallConfig{
			Calls:  []any{&testCall},
			Host:   "api.example.com",
			Name:   "test",
			Path:   "/test",
			Method: CallMethodGET,
		}

		err := fillCallFunc(cfg, *sdkPtr, pathGen)
		if err != nil {
			t.Errorf("fillCallFunc() error = %v", err)
			return
		}

		if testCall == nil {
			t.Error("CallReqRespBytes was not set")
		}
	})

	t.Run("multiple_calls", func(t *testing.T) {
		var bytesCall CallReqRespBytes
		var readerCall CallReqRespReader
		var writerCall CallReqRespWriter

		cfg := CallConfig{
			Calls:  []any{&bytesCall, &readerCall, &writerCall},
			Host:   "api.example.com",
			Name:   "test",
			Path:   "/test",
			Method: CallMethodGET,
		}

		err := fillCallFunc(cfg, *sdkPtr, pathGen)
		if err != nil {
			t.Errorf("fillCallFunc() error = %v", err)
			return
		}

		if bytesCall == nil || readerCall == nil || writerCall == nil {
			t.Error("not all call functions were set")
		}
	})

	t.Run("invalid_call_type", func(t *testing.T) {
		cfg := CallConfig{
			Calls:  []any{"invalid"},
			Host:   "api.example.com",
			Name:   "test",
			Path:   "/test",
			Method: CallMethodGET,
		}

		err := fillCallFunc(cfg, *sdkPtr, pathGen)
		if err == nil {
			t.Error("expected error for invalid call type")
		}
	})

	t.Run("mixed_call_types", func(t *testing.T) {
		var argsCall CallReqWithArgsRespBytes
		var bodyCall CallReqBytesRespReader
		var queryCall CallReqQueryRespWriter

		cfg := CallConfig{
			Calls:  []any{&argsCall, &bodyCall, &queryCall},
			Host:   "api.example.com",
			Name:   "test",
			Path:   "/test",
			Method: CallMethodPOST,
		}

		err := fillCallFunc(cfg, *sdkPtr, pathGen)
		if err != nil {
			t.Errorf("fillCallFunc() error = %v", err)
			return
		}

		if argsCall == nil || bodyCall == nil || queryCall == nil {
			t.Error("not all mixed call functions were set")
		}
	})
}
