package sdk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"time"
)

const (
	DefaultClientName    = "sdk"
	DefaultClientVersion = "1.0.0"
	DefaultPowTimeout    = 30 * time.Second
	DefaultWaitTime      = 10 * time.Second
	DefaultMaxRetries    = 3
)

type (
	// returns a response body as bytes
	CallReqRespBytes func(ctx context.Context) ([]byte, error)
	// returns a reader for response body
	CallReqRespReader func(ctx context.Context) (io.ReadCloser, error)
	// writes response body to writer
	CallReqRespWriter func(ctx context.Context, w io.Writer) error
	// returns a response body as bytes and gets request query parameters
	CallReqQueryRespBytes func(ctx context.Context, query map[string]string) ([]byte, error)
	// returns a reader for response body and gets request query parameters
	CallReqQueryRespReader func(ctx context.Context, query map[string]string) (io.ReadCloser, error)
	// writes response body to writer and gets request query parameters
	CallReqQueryRespWriter func(ctx context.Context, query map[string]string, w io.Writer) error
	// returns a response body as bytes and gets request position arguments and query parameters
	CallReqWithArgsRespBytes func(ctx context.Context, args []string) ([]byte, error)
	// returns a reader for response body and gets request position arguments and query parameters
	CallReqWithArgsRespReader func(ctx context.Context, args []string) (io.ReadCloser, error)
	// writes response body to writer and gets request position arguments and query parameters
	CallReqWithArgsRespWriter func(ctx context.Context, args []string, w io.Writer) error
	// returns a response body as bytes and gets request position arguments and query parameters
	CallReqQueryWithArgsRespBytes func(ctx context.Context, args []string, query map[string]string) ([]byte, error)
	// returns a reader for response body and gets request position arguments and query parameters
	CallReqQueryWithArgsRespReader func(ctx context.Context, args []string, query map[string]string) (io.ReadCloser, error)
	// writes response body to writer and gets request position arguments and query parameters
	CallReqQueryWithArgsRespWriter func(ctx context.Context, args []string, query map[string]string, w io.Writer) error

	// returns a response body as bytes and gets request body as bytes
	CallReqBytesRespBytes func(ctx context.Context, body []byte) ([]byte, error)
	// returns a reader for response body and gets request body as bytes
	CallReqBytesRespReader func(ctx context.Context, body []byte) (io.ReadCloser, error)
	// writes response body to writer and gets request body as bytes
	CallReqBytesRespWriter func(ctx context.Context, body []byte, w io.Writer) error
	// returns a response body as bytes and gets request body as reader and length
	CallReqReaderRespBytes func(ctx context.Context, r io.Reader, l int64) ([]byte, error)
	// returns a reader for response body and gets request body as reader and length
	CallReqReaderRespReader func(ctx context.Context, r io.Reader, l int64) (io.ReadCloser, error)
	// writes response body to writer and gets request body as reader and length
	CallReqReaderRespWriter func(ctx context.Context, r io.Reader, l int64, w io.Writer) error

	// returns a response body as bytes and gets request position arguments and request body as bytes
	CallReqBytesWithArgsRespBytes func(ctx context.Context, args []string, body []byte) ([]byte, error)
	// returns a reader for response body and gets request position arguments and request body as bytes
	CallReqBytesWithArgsRespReader func(ctx context.Context, args []string, body []byte) (io.ReadCloser, error)
	// writes response body to writer and gets request position arguments and request body as bytes
	CallReqBytesWithArgsRespWriter func(ctx context.Context, args []string, body []byte, w io.Writer) error
	// returns a response body as bytes and gets position arguments and request body as reader and length
	CallReqReaderWithArgsRespBytes func(ctx context.Context, args []string, r io.Reader, l int64) ([]byte, error)
	// returns a reader for response body and gets position arguments and request body as reader and length
	CallReqReaderWithArgsRespReader func(ctx context.Context, args []string, r io.Reader, l int64) (io.ReadCloser, error)
	// writes response body to writer and gets position arguments and request body as reader and length
	CallReqReaderWithArgsRespWriter func(ctx context.Context, args []string, r io.Reader, l int64, w io.Writer) error
)

type CallType interface {
	CallReqRespBytes |
		CallReqRespReader |
		CallReqRespWriter |
		CallReqQueryRespBytes |
		CallReqQueryRespReader |
		CallReqQueryRespWriter |
		CallReqWithArgsRespBytes |
		CallReqWithArgsRespReader |
		CallReqWithArgsRespWriter |
		CallReqQueryWithArgsRespBytes |
		CallReqQueryWithArgsRespReader |
		CallReqQueryWithArgsRespWriter |
		CallReqBytesRespBytes |
		CallReqBytesRespReader |
		CallReqBytesRespWriter |
		CallReqReaderRespBytes |
		CallReqReaderRespReader |
		CallReqReaderRespWriter |
		CallReqBytesWithArgsRespBytes |
		CallReqBytesWithArgsRespReader |
		CallReqBytesWithArgsRespWriter |
		CallReqReaderWithArgsRespBytes |
		CallReqReaderWithArgsRespReader |
		CallReqReaderWithArgsRespWriter
}

type CallPointerType interface {
	*CallReqRespBytes |
		*CallReqRespReader |
		*CallReqRespWriter |
		*CallReqQueryRespBytes |
		*CallReqQueryRespReader |
		*CallReqQueryRespWriter |
		*CallReqWithArgsRespBytes |
		*CallReqWithArgsRespReader |
		*CallReqWithArgsRespWriter |
		*CallReqQueryWithArgsRespBytes |
		*CallReqQueryWithArgsRespReader |
		*CallReqQueryWithArgsRespWriter |
		*CallReqBytesRespBytes |
		*CallReqBytesRespReader |
		*CallReqBytesRespWriter |
		*CallReqReaderRespBytes |
		*CallReqReaderRespReader |
		*CallReqReaderRespWriter |
		*CallReqBytesWithArgsRespBytes |
		*CallReqBytesWithArgsRespReader |
		*CallReqBytesWithArgsRespWriter |
		*CallReqReaderWithArgsRespBytes |
		*CallReqReaderWithArgsRespReader |
		*CallReqReaderWithArgsRespWriter
}

type CallMethod string

const (
	CallMethodGET    CallMethod = "GET"
	CallMethodPOST   CallMethod = "POST"
	CallMethodPUT    CallMethod = "PUT"
	CallMethodPATCH  CallMethod = "PATCH"
	CallMethodDELETE CallMethod = "DELETE"
)

type CallConfig struct {
	Calls  []any      // slice of pointers to CallType function (each must be CallPointerType)
	Host   string     // server host (domain name or IP address)
	Name   string     // unique route name on the server side
	Path   string     // route path may contain position arguments (e.g. /users/:id)
	Method CallMethod // HTTP method (supports: GET, POST, PUT, PATCH, DELETE)
}

func checkCallType(call any) error {
	if call == nil {
		return fmt.Errorf("call %T must be a valid pointer to a function", call)
	}

	switch call.(type) {
	case *CallReqRespBytes:
	case *CallReqRespReader:
	case *CallReqRespWriter:
	case *CallReqQueryRespBytes:
	case *CallReqQueryRespReader:
	case *CallReqQueryRespWriter:
	case *CallReqWithArgsRespBytes:
	case *CallReqWithArgsRespReader:
	case *CallReqWithArgsRespWriter:
	case *CallReqQueryWithArgsRespBytes:
	case *CallReqQueryWithArgsRespReader:
	case *CallReqQueryWithArgsRespWriter:
	case *CallReqBytesRespBytes:
	case *CallReqBytesRespReader:
	case *CallReqBytesRespWriter:
	case *CallReqReaderRespBytes:
	case *CallReqReaderRespReader:
	case *CallReqReaderRespWriter:
	case *CallReqBytesWithArgsRespBytes:
	case *CallReqBytesWithArgsRespReader:
	case *CallReqBytesWithArgsRespWriter:
	case *CallReqReaderWithArgsRespBytes:
	case *CallReqReaderWithArgsRespReader:
	case *CallReqReaderWithArgsRespWriter:
	default:
		return fmt.Errorf("invalid call type: %T", call)
	}

	return nil
}

func isCallWithArgs(call any) bool {
	switch call.(type) {
	case *CallReqWithArgsRespBytes:
	case *CallReqWithArgsRespReader:
	case *CallReqWithArgsRespWriter:
	case *CallReqQueryWithArgsRespBytes:
	case *CallReqQueryWithArgsRespReader:
	case *CallReqQueryWithArgsRespWriter:
	case *CallReqBytesWithArgsRespBytes:
	case *CallReqBytesWithArgsRespReader:
	case *CallReqBytesWithArgsRespWriter:
	case *CallReqReaderWithArgsRespBytes:
	case *CallReqReaderWithArgsRespReader:
	case *CallReqReaderWithArgsRespWriter:
	default:
		return false
	}

	return true
}

func isCallWithBody(call any) bool {
	switch call.(type) {
	case *CallReqBytesRespBytes:
	case *CallReqBytesRespReader:
	case *CallReqBytesRespWriter:
	case *CallReqReaderRespBytes:
	case *CallReqReaderRespReader:
	case *CallReqReaderRespWriter:
	case *CallReqBytesWithArgsRespBytes:
	case *CallReqBytesWithArgsRespReader:
	case *CallReqBytesWithArgsRespWriter:
	case *CallReqReaderWithArgsRespBytes:
	case *CallReqReaderWithArgsRespReader:
	case *CallReqReaderWithArgsRespWriter:
	default:
		return false
	}

	return true
}

func isCallWithQuery(call any) bool {
	switch call.(type) {
	case *CallReqQueryRespBytes:
	case *CallReqQueryRespReader:
	case *CallReqQueryRespWriter:
	case *CallReqQueryWithArgsRespBytes:
	case *CallReqQueryWithArgsRespReader:
	case *CallReqQueryWithArgsRespWriter:
	default:
		return false
	}

	return true
}

type pathGenerator func(args []string) (string, error)

// call request parameters and response results
type callContext struct {
	reqCallURL      url.URL           // request call target URL
	reqTicketURL    url.URL           // request ticket URL
	reqMethod       string            // request method
	reqPathArgs     []string          // position arguments for path template
	reqQueryArgs    map[string]string // request query parameters
	reqBodyReader   io.Reader         // optional input argument if body is provided
	reqBodyLength   int64             // size of the original body in bytes
	respStatusCode  int               // fill after invoke
	respBodyWriter  io.Writer         // optional input argument
	respBodyReader  io.ReadCloser     // fill after invoke
	restWaitTime    time.Duration     // fill after invoke if error is temporary
	context.Context                   // original context
}

type callFunc struct {
	sdk sdk
	cfg CallConfig
	gen pathGenerator
}

func (c *callFunc) invokeWithRetries(cctx *callContext) error {
	path, err := c.gen(cctx.reqPathArgs)
	if err != nil {
		return fmt.Errorf("%w: invalid path args: %w", ErrInvalidRequest, err)
	}

	queryArgs := url.Values{}
	for key, value := range cctx.reqQueryArgs {
		queryArgs.Add(key, value)
	}

	cctx.reqMethod = string(c.cfg.Method)
	cctx.reqCallURL = url.URL{
		Scheme:   defaultScheme,
		Host:     c.cfg.Host,
		Path:     path,
		RawQuery: queryArgs.Encode(),
	}
	cctx.reqTicketURL = url.URL{
		Scheme: defaultScheme,
		Host:   c.cfg.Host,
		Path:   defaultTicketPath + c.cfg.Name,
	}

	maxRetries := max(c.sdk.maxRetries, 1)

	for attempt := range maxRetries {
		if err = c.invokeRequest(cctx); err == nil {
			return nil
		}

		if !isTemporaryError(err) {
			msg := fmt.Sprintf("error on attempt %d/%d for %s", attempt+1, maxRetries, c.cfg.Name)
			c.sdk.logger.WithError(err).Error(msg)
			break
		}

		if attempt < maxRetries-1 {
			waitTime := c.calculateWaitTime(err, cctx)
			msg := fmt.Sprintf("temporary error on attempt %d/%d for %s", attempt+1, maxRetries, c.cfg.Name)
			c.sdk.logger.WithError(err).Debugf("%s, waiting %v before retry", msg, waitTime)

			select {
			case <-cctx.Done():
				return cctx.Err()
			case <-time.After(waitTime):
				// continue to retry
			}
		} else {
			return fmt.Errorf("%w after %d attempts: %w", ErrMaxRetriesExceeded, maxRetries, err)
		}
	}

	return err
}

func (c *callFunc) invokeWithBytes(cctx *callContext) ([]byte, error) {
	if err := c.invokeWithRetries(cctx); err != nil {
		return nil, err
	}

	if cctx.respBodyReader == nil {
		return nil, fmt.Errorf("%w: response reader is not set", ErrClientInternal)
	}

	defer func() {
		if err := cctx.respBodyReader.Close(); err != nil {
			c.sdk.logger.WithError(err).Errorf("failed to close response reader")
		}
	}()

	respBody, err := io.ReadAll(cctx.respBodyReader)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response body: %w", ErrClientInternal, err)
	}

	return respBody, nil
}

func (c *callFunc) invokeWithReader(cctx *callContext) (io.ReadCloser, error) {
	if err := c.invokeWithRetries(cctx); err != nil {
		return nil, err
	}

	if cctx.respBodyReader == nil {
		return nil, fmt.Errorf("%w: response reader is not set", ErrClientInternal)
	}

	return cctx.respBodyReader, nil
}

func (c *callFunc) invokeWithWriter(cctx *callContext) error {
	if cctx.respBodyWriter == nil {
		return fmt.Errorf("%w: response writer is required", ErrInvalidRequest)
	}

	if err := c.invokeWithRetries(cctx); err != nil {
		return err
	}

	// just double check that response reader is closed
	if cctx.respBodyReader != nil {
		if err := cctx.respBodyReader.Close(); err != nil {
			c.sdk.logger.WithError(err).Errorf("failed to close response reader")
		}
	}

	return nil
}

// calculateWaitTime determines how long to wait before retry based on error type and response
func (c *callFunc) calculateWaitTime(err error, cctx *callContext) time.Duration {
	switch {
	case errors.Is(err, ErrTooManyRequestsRPM) || errors.Is(err, ErrExperimentTimeout):
		if cctx != nil && cctx.restWaitTime > 0 {
			return min(cctx.restWaitTime, DefaultWaitTime)
		}
		return DefaultWaitTime
	case errors.Is(err, ErrTooManyRequests):
		return 5 * time.Second
	case errors.Is(err, ErrBadGateway) || errors.Is(err, ErrServerInternal):
		return 3 * time.Second
	default:
		return 1 * time.Second
	}
}

func (c *callFunc) callReqRespBytes(ctx context.Context) ([]byte, error) {
	cctx := callContext{Context: ctx}
	return c.invokeWithBytes(&cctx)
}

func (c *callFunc) callReqRespReader(ctx context.Context) (io.ReadCloser, error) {
	cctx := callContext{Context: ctx}
	return c.invokeWithReader(&cctx)
}

func (c *callFunc) callReqRespWriter(ctx context.Context, w io.Writer) error {
	cctx := callContext{Context: ctx, respBodyWriter: w}
	return c.invokeWithWriter(&cctx)
}

func (c *callFunc) callReqQueryRespBytes(ctx context.Context, query map[string]string) ([]byte, error) {
	cctx := callContext{Context: ctx, reqQueryArgs: query}
	return c.invokeWithBytes(&cctx)
}

func (c *callFunc) callReqQueryRespReader(ctx context.Context, query map[string]string) (io.ReadCloser, error) {
	cctx := callContext{Context: ctx, reqQueryArgs: query}
	return c.invokeWithReader(&cctx)
}

func (c *callFunc) callReqQueryRespWriter(ctx context.Context, query map[string]string, w io.Writer) error {
	cctx := callContext{Context: ctx, reqQueryArgs: query, respBodyWriter: w}
	return c.invokeWithWriter(&cctx)
}

func (c *callFunc) callReqWithArgsRespBytes(ctx context.Context, args []string) ([]byte, error) {
	cctx := callContext{Context: ctx, reqPathArgs: args}
	return c.invokeWithBytes(&cctx)
}

func (c *callFunc) callReqWithArgsRespReader(ctx context.Context, args []string) (io.ReadCloser, error) {
	cctx := callContext{Context: ctx, reqPathArgs: args}
	return c.invokeWithReader(&cctx)
}

func (c *callFunc) callReqWithArgsRespWriter(ctx context.Context, args []string, w io.Writer) error {
	cctx := callContext{Context: ctx, reqPathArgs: args, respBodyWriter: w}
	return c.invokeWithWriter(&cctx)
}

func (c *callFunc) callReqQueryWithArgsRespBytes(ctx context.Context, args []string, query map[string]string) ([]byte, error) {
	cctx := callContext{Context: ctx, reqPathArgs: args, reqQueryArgs: query}
	return c.invokeWithBytes(&cctx)
}

func (c *callFunc) callReqQueryWithArgsRespReader(ctx context.Context, args []string, query map[string]string) (io.ReadCloser, error) {
	cctx := callContext{Context: ctx, reqPathArgs: args, reqQueryArgs: query}
	return c.invokeWithReader(&cctx)
}

func (c *callFunc) callReqQueryWithArgsRespWriter(ctx context.Context, args []string, query map[string]string, w io.Writer) error {
	cctx := callContext{Context: ctx, reqPathArgs: args, reqQueryArgs: query, respBodyWriter: w}
	return c.invokeWithWriter(&cctx)
}

func (c *callFunc) callReqBytesRespBytes(ctx context.Context, body []byte) ([]byte, error) {
	cctx := callContext{Context: ctx, reqBodyReader: bytes.NewReader(body), reqBodyLength: int64(len(body))}
	return c.invokeWithBytes(&cctx)
}

func (c *callFunc) callReqBytesRespReader(ctx context.Context, body []byte) (io.ReadCloser, error) {
	cctx := callContext{Context: ctx, reqBodyReader: bytes.NewReader(body), reqBodyLength: int64(len(body))}
	return c.invokeWithReader(&cctx)
}

func (c *callFunc) callReqBytesRespWriter(ctx context.Context, body []byte, w io.Writer) error {
	cctx := callContext{Context: ctx, reqBodyReader: bytes.NewReader(body), reqBodyLength: int64(len(body)), respBodyWriter: w}
	return c.invokeWithWriter(&cctx)
}

func (c *callFunc) callReqReaderRespBytes(ctx context.Context, r io.Reader, l int64) ([]byte, error) {
	cctx := callContext{Context: ctx, reqBodyReader: r, reqBodyLength: l}
	return c.invokeWithBytes(&cctx)
}

func (c *callFunc) callReqReaderRespReader(ctx context.Context, r io.Reader, l int64) (io.ReadCloser, error) {
	cctx := callContext{Context: ctx, reqBodyReader: r, reqBodyLength: l}
	return c.invokeWithReader(&cctx)
}

func (c *callFunc) callReqReaderRespWriter(ctx context.Context, r io.Reader, l int64, w io.Writer) error {
	cctx := callContext{Context: ctx, reqBodyReader: r, reqBodyLength: l, respBodyWriter: w}
	return c.invokeWithWriter(&cctx)
}

func (c *callFunc) callReqBytesWithArgsRespBytes(ctx context.Context, args []string, body []byte) ([]byte, error) {
	cctx := callContext{Context: ctx, reqPathArgs: args, reqBodyReader: bytes.NewReader(body), reqBodyLength: int64(len(body))}
	return c.invokeWithBytes(&cctx)
}

func (c *callFunc) callReqBytesWithArgsRespReader(ctx context.Context, args []string, body []byte) (io.ReadCloser, error) {
	cctx := callContext{Context: ctx, reqPathArgs: args, reqBodyReader: bytes.NewReader(body), reqBodyLength: int64(len(body))}
	return c.invokeWithReader(&cctx)
}

func (c *callFunc) callReqBytesWithArgsRespWriter(ctx context.Context, args []string, body []byte, w io.Writer) error {
	cctx := callContext{Context: ctx, reqPathArgs: args, reqBodyReader: bytes.NewReader(body), reqBodyLength: int64(len(body)), respBodyWriter: w}
	return c.invokeWithWriter(&cctx)
}

func (c *callFunc) callReqReaderWithArgsRespBytes(ctx context.Context, args []string, r io.Reader, l int64) ([]byte, error) {
	cctx := callContext{Context: ctx, reqPathArgs: args, reqBodyReader: r, reqBodyLength: l}
	return c.invokeWithBytes(&cctx)
}

func (c *callFunc) callReqReaderWithArgsRespReader(ctx context.Context, args []string, r io.Reader, l int64) (io.ReadCloser, error) {
	cctx := callContext{Context: ctx, reqPathArgs: args, reqBodyReader: r, reqBodyLength: l}
	return c.invokeWithReader(&cctx)
}

func (c *callFunc) callReqReaderWithArgsRespWriter(ctx context.Context, args []string, r io.Reader, l int64, w io.Writer) error {
	cctx := callContext{Context: ctx, reqPathArgs: args, reqBodyReader: r, reqBodyLength: l, respBodyWriter: w}
	return c.invokeWithWriter(&cctx)
}

func fillCallFunc(cfg CallConfig, sdk sdk, gen pathGenerator) error {
	cfn := callFunc{
		sdk: sdk,
		cfg: cfg,
		gen: gen,
	}

	for _, call := range cfg.Calls {
		switch fn := call.(type) {
		case *CallReqRespBytes:
			*fn = cfn.callReqRespBytes
		case *CallReqRespReader:
			*fn = cfn.callReqRespReader
		case *CallReqRespWriter:
			*fn = cfn.callReqRespWriter
		case *CallReqQueryRespBytes:
			*fn = cfn.callReqQueryRespBytes
		case *CallReqQueryRespReader:
			*fn = cfn.callReqQueryRespReader
		case *CallReqQueryRespWriter:
			*fn = cfn.callReqQueryRespWriter
		case *CallReqWithArgsRespBytes:
			*fn = cfn.callReqWithArgsRespBytes
		case *CallReqWithArgsRespReader:
			*fn = cfn.callReqWithArgsRespReader
		case *CallReqWithArgsRespWriter:
			*fn = cfn.callReqWithArgsRespWriter
		case *CallReqQueryWithArgsRespBytes:
			*fn = cfn.callReqQueryWithArgsRespBytes
		case *CallReqQueryWithArgsRespReader:
			*fn = cfn.callReqQueryWithArgsRespReader
		case *CallReqQueryWithArgsRespWriter:
			*fn = cfn.callReqQueryWithArgsRespWriter
		case *CallReqBytesRespBytes:
			*fn = cfn.callReqBytesRespBytes
		case *CallReqBytesRespReader:
			*fn = cfn.callReqBytesRespReader
		case *CallReqBytesRespWriter:
			*fn = cfn.callReqBytesRespWriter
		case *CallReqReaderRespBytes:
			*fn = cfn.callReqReaderRespBytes
		case *CallReqReaderRespReader:
			*fn = cfn.callReqReaderRespReader
		case *CallReqReaderRespWriter:
			*fn = cfn.callReqReaderRespWriter
		case *CallReqBytesWithArgsRespBytes:
			*fn = cfn.callReqBytesWithArgsRespBytes
		case *CallReqBytesWithArgsRespReader:
			*fn = cfn.callReqBytesWithArgsRespReader
		case *CallReqBytesWithArgsRespWriter:
			*fn = cfn.callReqBytesWithArgsRespWriter
		case *CallReqReaderWithArgsRespBytes:
			*fn = cfn.callReqReaderWithArgsRespBytes
		case *CallReqReaderWithArgsRespReader:
			*fn = cfn.callReqReaderWithArgsRespReader
		case *CallReqReaderWithArgsRespWriter:
			*fn = cfn.callReqReaderWithArgsRespWriter
		default:
			return fmt.Errorf("invalid call type: %T", fn)
		}
	}

	return nil
}
