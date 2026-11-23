package filen

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/obscure"
	"golang.org/x/crypto/pbkdf2"
)

// TestNewFsFileParent exercises the actual saved-account constructor through an
// owned HTTPS server. The CONNECT proxy never dials a vendor endpoint.
func TestNewFsFileParent(t *testing.T) {
	const master = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const rootID, nestedID = "synthetic-root", "synthetic-nested"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	public := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	derived := pbkdf2.Key([]byte(master), []byte(master), 1, 32, sha512.New)
	block, err := aes.NewCipher(derived)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	encrypt := func(value any) string {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		random := make([]byte, 6)
		if _, err := rand.Read(random); err != nil {
			t.Fatal(err)
		}
		nonce := []byte(hex.EncodeToString(random))
		return "002" + string(nonce) + base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, data, nil))
	}
	metadata := encrypt(map[string]any{
		"name": "file.txt", "size": 3, "mime": "text/plain", "key": "0123456789abcdef0123456789abcdef",
		"lastModified": 1704067200000, "creation": 1704067200000, "blake3": "",
	})
	folderMetadata := encrypt(map[string]any{"name": "nested", "creation": 1704067200})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "POST" || r.URL.Path != "/v3/dir/content" || r.Header.Get("Authorization") != "Bearer synthetic-key" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(400)
			return
		}
		var request struct {
			UUID string `json:"uuid"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if request.UUID != rootID && request.UUID != nestedID {
			t.Errorf("unexpected directory %q", request.UUID)
			w.WriteHeader(400)
			return
		}
		uploads := []map[string]any{{"uuid": "synthetic-file-" + request.UUID, "metadata": metadata,
			"parent": request.UUID, "chunks": 1, "size": 3, "bucket": "synthetic-bucket",
			"region": "synthetic-region", "version": 2}}
		folders := []map[string]any{}
		if request.UUID == rootID {
			folders = append(folders, map[string]any{"uuid": nestedID, "name": folderMetadata, "parent": rootID})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": true, "data": map[string]any{"uploads": uploads, "folders": folders}})
	}))
	defer server.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != "gateway.filen.io:443" {
			t.Errorf("unexpected tunnel %s %s", r.Method, r.Host)
			w.WriteHeader(400)
			return
		}
		upstream, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
		if err != nil {
			t.Error(err)
			w.WriteHeader(502)
			return
		}
		defer func() { _ = upstream.Close() }()
		connection, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = connection.Close() }()
		_ = upstream.SetDeadline(time.Now().Add(5 * time.Second))
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := fmt.Fprint(buffered, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			t.Error(err)
			return
		}
		if err := buffered.Flush(); err != nil {
			t.Error(err)
			return
		}
		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(upstream, buffered)
			_ = upstream.Close()
			close(done)
		}()
		_, _ = io.Copy(connection, upstream)
		_ = connection.Close()
		<-done
	}))
	defer proxy.Close()
	// NewFromTSConfig constructs its client from context.Background.
	config := fs.GetConfig(context.Background())
	previousProxy, previousInsecure := config.HTTPProxy, config.InsecureSkipVerify
	config.HTTPProxy, config.InsecureSkipVerify = proxy.URL, true
	defer func() { config.HTTPProxy, config.InsecureSkipVerify = previousProxy, previousInsecure }()
	options := configmap.Simple{
		"email": "synthetic@example.invalid", "password": obscure.MustObscure("INTERNAL"),
		"api_key": obscure.MustObscure("synthetic-key"), "master_keys": master, "auth_version": "2",
		"base_folder_uuid": rootID, "private_key": base64.StdEncoding.EncodeToString(private),
		"public_key": base64.StdEncoding.EncodeToString(public),
	}
	for _, tc := range []struct{ remote, parent string }{{"file.txt", ""}, {"nested/file.txt", "nested"}} {
		t.Run(tc.remote, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			filesystem, err := NewFs(ctx, "Synthetic", tc.remote, options)
			if !errors.Is(err, fs.ErrorIsFile) || filesystem == nil {
				t.Fatalf("file root = %v, %v", filesystem, err)
			}
			if filesystem.Root() != tc.parent {
				t.Fatalf("parent = %q, want %q", filesystem.Root(), tc.parent)
			}
			entries, err := filesystem.List(ctx, "")
			if err != nil {
				t.Fatalf("list file parent: %v", err)
			}
			found := false
			for _, entry := range entries {
				if strings.TrimPrefix(entry.Remote(), tc.parent+"/") == "file.txt" {
					found = true
				}
			}
			if !found {
				t.Fatal("file absent from its parent listing")
			}
			object, err := filesystem.NewObject(ctx, "file.txt")
			if err != nil || object == nil || object.Size() != 3 {
				t.Fatalf("file lookup = %v, %v", object, err)
			}
		})
	}
}
