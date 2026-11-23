package filescom

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
)

func TestOpenReadStatus(t *testing.T) {
	payload := "Synthetic provider read payload."
	for _, tc := range []struct {
		name                   string
		status                 int
		partial, denied, empty bool
	}{
		{"full", 200, false, false, false}, {"range", 206, true, false, false}, {"empty", 200, false, false, true},
		{"forbidden", 403, true, true, false}, {"not_found", 404, true, true, false}, {"server_error", 500, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expected := payload
			if tc.empty {
				expected = ""
			}
			var endpoint string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/rest/v1/files/synthetic.txt":
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"type": "file", "path": "synthetic.txt", "size": len(expected), "download_uri": endpoint + "/content"})
				case "/content":
					requested := r.Header.Get("Range")
					if tc.partial {
						if requested != "bytes=3-13" {
							t.Errorf("range = %q", requested)
						}
					} else if tc.empty {
						if requested != "" {
							t.Errorf("empty file range = %q", requested)
						}
					} else if requested != "" && requested != fmt.Sprintf("bytes=0-%d", len(payload)-1) {
						t.Errorf("full read sent invalid range %q", requested)
					}
					wire := expected
					if tc.status == 206 {
						wire = payload[3:14]
					}
					w.Header().Set("Content-Type", "application/octet-stream")
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, wire)
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					w.WriteHeader(400)
				}
			}))
			defer server.Close()
			endpoint = server.URL
			ctx := context.Background()
			filesystem, err := NewFs(ctx, "Synthetic", "", configmap.Simple{"site": endpoint, "api_key": "synthetic-key"})
			if err != nil {
				t.Fatal(err)
			}
			object := &Object{fs: filesystem.(*Fs), remote: "synthetic.txt", size: int64(len(expected))}
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
			if tc.partial {
				expected = payload[3:14]
			}
			if err != nil || string(data) != expected {
				t.Fatalf("read = %q, %v; want %q", data, err, expected)
			}
		})
	}
}
