package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
)

type triageStatusTransport func(*http.Request) (*http.Response, error)

func (f triageStatusTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type triageStatusBody struct {
	io.Reader
	closed bool
}

func (b *triageStatusBody) Close() error { b.closed = true; return nil }

func TestSyntheticChunkHTTPStatus(t *testing.T) {
	payload := []byte("Synthetic chunk bytes, identical for success and denial.")
	for _, status := range []int{200, 206, 403, 404, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			body := &triageStatusBody{Reader: bytes.NewReader(payload)}
			c := &Client{UnauthorizedClient: UnauthorizedClient{httpClient: http.Client{Transport: triageStatusTransport(func(r *http.Request) (*http.Response, error) {
				if r.Method != "GET" || r.URL.String() != "https://egest.filen.io/synthetic-region/synthetic-bucket/synthetic-file/0" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
				}
				return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Body: body, Header: make(http.Header), ContentLength: int64(len(payload)), Request: r}, nil
			})}}, APIKey: "synthetic-key"}
			data, err := c.DownloadFileChunk(context.Background(), "synthetic-file", "synthetic-region", "synthetic-bucket", 0)
			if !body.closed {
				t.Error("response body was not closed")
			}
			if status == 200 {
				if err != nil || !bytes.Equal(data, payload) {
					t.Fatalf("valid chunk failed: bytes=%d err=%v", len(data), err)
				}
			} else if err == nil || len(data) != 0 {
				t.Fatalf("HTTP %d accepted: bytes=%d err=%v", status, len(data), err)
			}
		})
	}
}
