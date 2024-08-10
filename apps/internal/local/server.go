// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Package local contains a local HTTP server used with interactive authentication.
package local

import (
	"context"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var okPage = []byte(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>Authentication Complete</title>
</head>
<body>
    <p>Authentication complete. You can return to the application. Feel free to close this browser tab.</p>
</body>
</html>
`)

const failPage = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>Authentication Failed</title>
</head>
<body>
	<p>Authentication failed. You can return to the application. Feel free to close this browser tab.</p>
	<p>Error details: error {{.Code}}, error description: {{.Err}}</p>
</body>
</html>
`

// code is the html template variable name,
// which matches the Result Code variable
const code string = "Code"

// err is the html template variable name
// which matches the Rest Err variable
const err string = "Err"

// Result is the result from the redirect.
type Result struct {
	// Code is the code sent by the authority server.
	Code string
	// Err is set if there was an error.
	Err error
}

// Server is an HTTP server.
type Server struct {
	// Addr is the address the server is listening on.
	Addr              string
	resultCh          chan Result
	s                 *http.Server
	reqState          string
	optionSuccessPage []byte
	optionErrorPage   []byte
	errorPageTemplate string
}

// New creates a local HTTP server and starts it.
func New(reqState string, port int, successPage []byte, errorPage []byte) (*Server, error) {
	var l net.Listener
	var err error
	var portStr string
	if port > 0 {
		// use port provided by caller
		l, err = net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
		portStr = strconv.FormatInt(int64(port), 10)
	} else {
		// find a free port
		for i := 0; i < 10; i++ {
			l, err = net.Listen("tcp", "localhost:0")
			if err != nil {
				continue
			}
			addr := l.Addr().String()
			portStr = addr[strings.LastIndex(addr, ":")+1:]
			break
		}
	}
	if err != nil {
		return nil, err
	}

	serv := &Server{
		Addr:              fmt.Sprintf("http://localhost:%s", portStr),
		s:                 &http.Server{Addr: "localhost:0", ReadHeaderTimeout: time.Second},
		reqState:          reqState,
		resultCh:          make(chan Result, 1),
		optionSuccessPage: successPage,
		optionErrorPage:   errorPage,
		errorPageTemplate: failPage, // default error page
	}
	serv.s.Handler = http.HandlerFunc(serv.handler)

	if err := serv.start(l); err != nil {
		return nil, err
	}

	return serv, nil
}

func (s *Server) start(l net.Listener) error {
	go func() {
		err := s.s.Serve(l)
		if err != nil {
			select {
			case s.resultCh <- Result{Err: err}:
			default:
			}
		}
	}()

	return nil
}

// Result gets the result of the redirect operation. Once a single result is returned, the server
// is shutdown. ctx deadline will be honored.
func (s *Server) Result(ctx context.Context) Result {
	select {
	case <-ctx.Done():
		return Result{Err: ctx.Err()}
	case r := <-s.resultCh:
		return r
	}
}

// Shutdown shuts down the server.
func (s *Server) Shutdown() {
	// Note: You might get clever and think you can do this in handler() as a defer, you can't.
	_ = s.s.Shutdown(context.Background())
}

func (s *Server) putResult(r Result) {
	select {
	case s.resultCh <- r:
	default:
	}
}

func containsVariables(templateStr string, variables ...string) (bool, string) {
	missingVars := []string{}
	containsAll := true

	for _, variable := range variables {
		if !strings.Contains(templateStr, "{{."+variable+"}}") {
			containsAll = false
			missingVars = append(missingVars, variable)
		}
	}

	var missingStr string
	for i, v := range missingVars {
		if i == len(missingVars) {
			missingStr += v
		} else {
			missingStr += v + ", "
		}
	}

	return containsAll, missingStr
}

func (s *Server) handleError(w http.ResponseWriter, errorResult Result) {
	if len(s.optionErrorPage) > 0 {
		validTemplate, missingStr := containsVariables(string(s.optionErrorPage), code, err)
		if !validTemplate {
			errorMessage := fmt.Sprintf("error, template missing variables: %s", missingStr)
			s.error(w, http.StatusInternalServerError, errorMessage)
		}
		s.errorPageTemplate = string(s.optionErrorPage)
	}

	failPageTemplate, err := template.New("failPage").Parse(s.errorPageTemplate)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "error parsing template")
	}

	err = failPageTemplate.Execute(w, errorResult)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "error rendering page")
	}
	s.putResult(Result{Code: errorResult.Code}) // shuts down the server
}

func (s *Server) handleSuccess(w http.ResponseWriter) {
	if len(s.optionSuccessPage) > 0 {
		_, _ = w.Write(s.optionSuccessPage)
	} else {
		_, _ = w.Write(okPage)
	}
}

func (s *Server) handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	headerErr := q.Get("error")
	if headerErr != "" {
		// upstream error
		errorResult := Result{
			Code: headerErr,
			Err:  fmt.Errorf(q.Get("error_description")),
		}
		s.handleError(w, errorResult)
		return
	}

	respState := q.Get("state")
	switch respState {
	case s.reqState:
	case "":
		// missing state
		errorResult := Result{
			Code: fmt.Sprintf("%d", http.StatusInternalServerError),
			Err:  fmt.Errorf("server didn't send OAuth state"),
		}
		s.handleError(w, errorResult)
		return
	default:
		// mismatched state
		errorResult := Result{
			Code: fmt.Sprintf("%d", http.StatusInternalServerError),
			Err:  fmt.Errorf("mismatched OAuth state, req(%s), resp(%s)", s.reqState, respState),
		}
		s.handleError(w, errorResult)
		return
	}

	code := q.Get("code")
	if code == "" {
		// missing code
		errorResult := Result{
			Code: fmt.Sprintf("%d", http.StatusInternalServerError),
			Err:  fmt.Errorf("authorization code missing in query string"),
		}
		s.handleError(w, errorResult)
		return
	}

	s.handleSuccess(w)
	s.putResult(Result{Code: code})
}

func (s *Server) error(w http.ResponseWriter, code int, str string, i ...interface{}) {
	err := fmt.Errorf(str, i...)
	http.Error(w, err.Error(), code)
	s.putResult(Result{Err: err})
}
