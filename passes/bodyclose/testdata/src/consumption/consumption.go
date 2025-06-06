package consumption

import (
	"io"
	"net/http"
)

// These test cases are for consumption checking enabled mode

func consumedWithCopy() {
	resp, err := http.Get("http://example.com/") // OK - body consumed with io.Copy
	if err != nil {
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
}

func consumedWithReadAll() {
	resp, err := http.Get("http://example.com/") // OK - body consumed with io.ReadAll
	if err != nil {
		return
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
}

func notConsumed1() {
	resp, err := http.Get("http://example.com/") // want "response body must be closed and consumed"
	if err != nil {
		return
	}
	defer resp.Body.Close()
	// Body not consumed
}

func notConsumed2() {
	resp, err := http.Get("http://example.com/") // want "response body must be closed and consumed"
	if err != nil {
		return
	}
	defer resp.Body.Close()
	// Just accessing status, not consuming body
	_ = resp.Status
}

func consumedInHelper() {
	resp, err := http.Get("http://example.com/") // OK - consumed in helper function
	if err != nil {
		return
	}
	defer drainAndClose(resp)
}

func drainAndClose(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func notClosedAtAll() {
	resp, err := http.Get("http://example.com/") // want "response body must be closed and consumed"
	if err != nil {
		return
	}
	_ = resp
	// Neither closed nor consumed
}