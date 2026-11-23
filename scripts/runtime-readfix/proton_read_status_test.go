package proton

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

type triageStatusTransport func(*http.Request) (*http.Response, error)

func (f triageStatusTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type triageStatusBody struct {
	io.Reader
	closed bool
}

func (b *triageStatusBody) Close() error { b.closed = true; return nil }

func TestSyntheticBlockHTTPStatus(t *testing.T) {
	payload := []byte("Synthetic block bytes, identical for success and denial.")
	for _, status := range []int{200, 206, 403, 404, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			body := &triageStatusBody{Reader: bytes.NewReader(payload)}
			manager := New(WithHostURL("https://synthetic-api.invalid"), WithTransport(triageStatusTransport(func(r *http.Request) (*http.Response, error) {
				if r.Method != "GET" || r.URL.String() != "https://synthetic-content.invalid/block" || r.Header.Get("pm-storage-token") != "synthetic-storage" {
					t.Errorf("unexpected block request %s %s", r.Method, r.URL)
				}
				return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Body: body, Header: http.Header{"Date": []string{time.Now().UTC().Format(http.TimeFormat)}}, ContentLength: int64(len(payload)), Request: r}, nil
			})))
			defer manager.Close()
			client := manager.NewClient("synthetic-uid", "synthetic-access", "synthetic-refresh")
			defer client.Close()
			reader, err := client.GetBlock(context.Background(), "https://synthetic-content.invalid/block", "synthetic-storage")
			if status == 200 {
				if err != nil || reader == nil {
					t.Fatalf("valid block failed: %v", err)
				}
				data, readErr := io.ReadAll(reader)
				_ = reader.Close()
				if readErr != nil || !bytes.Equal(data, payload) {
					t.Fatalf("block bytes=%d err=%v", len(data), readErr)
				}
			} else {
				accepted := reader != nil
				if reader != nil {
					_ = reader.Close()
				}
				if err == nil || accepted {
					t.Fatalf("HTTP %d accepted: readable=%v err=%v", status, accepted, err)
				}
			}
			if !body.closed {
				t.Error("response body was not closed")
			}
		})
	}
}
