package imagekit

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/rclone/rclone/backend/imagekit/client"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
)

func TestOpenReadStatus(t *testing.T) {
	payload := "Synthetic provider read payload."
	for _, tc := range []struct {
		name    string
		status  int
		partial bool
		denied  bool
	}{
		{"full", 200, false, false}, {"range", 206, true, false}, {"ignored_range", 200, true, false},
		{"forbidden", 403, false, true}, {"not_found", 404, false, true}, {"server_error", 500, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := payload
			if tc.status == 206 {
				wire = payload[3:14]
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/synthetic.txt" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				if tc.partial && r.Header.Get("Range") != "bytes=3-13" {
					t.Errorf("range = %q", r.Header.Get("Range"))
				}
				w.Header().Set("Content-Type", "application/octet-stream")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, wire)
			}))
			defer server.Close()
			ctx := context.Background()
			filesystem, err := NewFs(ctx, "Synthetic", "", configmap.Simple{"endpoint": server.URL, "public_key": "synthetic-public", "private_key": "synthetic-private"})
			if err != nil {
				t.Fatal(err)
			}
			private := false
			object := &Object{fs: filesystem.(*Fs), remote: "synthetic.txt", file: client.File{URL: server.URL + "/synthetic.txt", Size: uint64(len(payload)), IsPrivateFile: &private}}
			options := []fs.OpenOption{}
			if tc.partial {
				options = append(options, &fs.RangeOption{Start: 3, End: 13})
			}
			body, err := object.Open(ctx, options...)
			if tc.denied {
				if body != nil {
					_ = body.Close()
					t.Error("denied response returned a readable body")
				}
				if err == nil {
					t.Fatal("denied HTTP status accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(body)
			_ = body.Close()
			expected := payload
			if tc.partial {
				expected = payload[3:14]
			}
			if err != nil || string(data) != expected {
				t.Fatalf("read = %q, %v; want %q", data, err, expected)
			}
		})
	}
}

func TestOpenHonorsCancelledContext(t *testing.T) {
	var called atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		_, _ = io.WriteString(w, "synthetic")
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	filesystem, err := NewFs(ctx, "Synthetic", "", configmap.Simple{"endpoint": server.URL, "public_key": "synthetic-public", "private_key": "synthetic-private"})
	if err != nil {
		t.Fatal(err)
	}
	private := false
	object := &Object{fs: filesystem.(*Fs), remote: "synthetic.txt", file: client.File{URL: server.URL + "/synthetic.txt", Size: 9, IsPrivateFile: &private}}
	cancel()
	body, err := object.Open(ctx)
	if body != nil {
		_ = body.Close()
	}
	if err == nil || called.Load() {
		t.Fatal("cancelled read reached the server or succeeded")
	}
}
