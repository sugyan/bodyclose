package a

import (
	"io"
	"net/http"
)

func issue43_f1() {
	resp, err := http.Get("http://example.com/") // OK with flag disabled, should warn with flag enabled
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

func issue43_f2() {
	resp, err := http.Get("http://example.com/") // OK - body consumed and closed
	if err != nil {
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
}

func issue43_f3() {
	resp, err := http.Get("http://example.com/") // OK - body consumed and closed
	if err != nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func issue43_f4() {
	resp, err := http.Get("http://example.com/") // OK - body consumed with ReadAll
	if err != nil {
		return
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
}

func issue43_f5() {
	resp, err := http.Get("http://example.com/") // OK with flag disabled, should warn with flag enabled
	if err != nil {
		return
	}
	defer resp.Body.Close()
	// Body not consumed
}

func disposeResponseBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func issue43_f6() {
	resp, err := http.Get("http://example.com/") // OK - body consumed in helper
	if err != nil {
		return
	}
	defer disposeResponseBody(resp)
}