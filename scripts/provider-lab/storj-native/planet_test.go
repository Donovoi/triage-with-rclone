package triagefixture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"storj.io/common/grant"
	"storj.io/common/macaroon"
	"storj.io/common/storj"
	"storj.io/common/testcontext"
	"storj.io/storj/private/testplanet"
	"storj.io/storj/satellite"
	"storj.io/uplink"
)

type nativeCheck struct {
	Backend string `json:"backend"`
	Case    string `json:"case"`
	Exit    int    `json:"exit"`
	Bytes   int    `json:"bytes"`
}

func TestSyntheticNetwork(t *testing.T) {
	observed := false
	testplanet.Run(t, testplanet.Config{
		SatelliteCount: 1, StorageNodeCount: 4, UplinkCount: 1,
		NonParallel: true, Timeout: 100 * time.Second, Host: "127.0.0.1",
		Reconfigure: testplanet.Reconfigure{
			Satellite: testplanet.Combine(testplanet.DisablePeerCAWhitelist.Satellite,
				func(log *zap.Logger, index int, config *satellite.Config) {
					config.Mail.TemplatePath = "/opt/triage/web/static/emails"
					config.Console.StaticDir = "/opt/triage/web"
				}),
			StorageNode: testplanet.DisablePeerCAWhitelist.StorageNode,
		},
	}, func(t *testing.T, ctx *testcontext.Context, planet *testplanet.Planet) {
		observed = true
		if len(planet.Satellites) != 1 || len(planet.StorageNodes) != 4 {
			t.Fatal("synthetic_topology_mismatch")
		}
		const bucket = "synthetic-bucket"
		files := map[string][]byte{
			"README-synthetic.txt":    []byte("Synthetic provider protocol fixture. No account or user data.\n"),
			"nested/space name.txt":   []byte("Nested synthetic payload.\n"),
			"nested/bytes.bin":        make([]byte, 2048),
			"nested/remote-piece.bin": make([]byte, 1024*1024),
		}
		for i := range files["nested/bytes.bin"] {
			files["nested/bytes.bin"][i] = byte(i % 256)
		}
		for i := range files["nested/remote-piece.bin"] {
			files["nested/remote-piece.bin"][i] = byte((i*17 + i/257) % 256)
		}
		names := make([]string, 0, len(files))
		for name := range files {
			names = append(names, name)
		}
		sort.Strings(names)
		sat, client := planet.Satellites[0], planet.Uplinks[0]
		for _, name := range names {
			if err := client.Upload(ctx, sat, bucket, name, files[name]); err != nil {
				t.Fatalf("synthetic_seed_failed: %v", err)
			}
		}
		segments, err := sat.Metabase.DB.TestingAllSegments(ctx)
		if err != nil {
			t.Fatal("segment_inventory_failed")
		}
		inline, remote, pieces := 0, 0, 0
		for _, segment := range segments {
			if segment.Inline() {
				inline++
			} else {
				remote++
				pieces += len(segment.Pieces)
			}
		}
		if inline != 3 || remote < 1 || pieces < 2 {
			t.Fatalf("segment_topology_invalid: inline=%d remote=%d pieces=%d", inline, remote, pieces)
		}
		full := client.Access[sat.ID()]
		read, err := full.Share(uplink.ReadOnlyPermission(), uplink.SharePrefix{Bucket: bucket})
		if err != nil {
			t.Fatal("readonly_grant_failed")
		}
		listOnly, err := full.Share(uplink.Permission{AllowList: true}, uplink.SharePrefix{Bucket: bucket})
		if err != nil {
			t.Fatal("listonly_grant_failed")
		}
		expired, err := full.Share(uplink.Permission{AllowList: true, AllowDownload: true, NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour)}, uplink.SharePrefix{Bucket: bucket})
		if err != nil {
			t.Fatal("expired_grant_failed")
		}
		unknownKey, err := macaroon.NewAPIKey([]byte("synthetic-unregistered-root-api-key"))
		if err != nil {
			t.Fatal("unknown_key_creation_failed")
		}
		unknownEncryption := grant.NewEncryptionAccessWithDefaultKey(&storj.Key{})
		unknownEncryption.SetDefaultPathCipher(storj.EncAESGCM)
		unknownGrant := grant.Access{SatelliteAddress: sat.URL(), APIKey: unknownKey, EncAccess: unknownEncryption}
		unknownSerialized, err := unknownGrant.Serialize()
		if err != nil {
			t.Fatal("unknown_grant_serialization_failed")
		}
		unknown, err := uplink.ParseAccess(unknownSerialized)
		if err != nil {
			t.Fatal("unknown_grant_parse_failed")
		}
		checks := []nativeCheck{}
		work := t.TempDir()
		for _, backend := range []string{"storj", "tardigrade"} {
			dir := filepath.Join(work, backend)
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			configs := map[string][]byte{}
			for name, access := range map[string]*uplink.Access{"read": read, "list-only": listOnly, "expired": expired, "unknown": unknown} {
				serialized, err := access.Serialize()
				if err != nil {
					t.Fatal("grant_serialization_failed")
				}
				raw := []byte(fmt.Sprintf("[Synthetic]\ntype = %s\nprovider = existing\naccess_grant = %s\n", backend, serialized))
				path := filepath.Join(dir, name+".conf")
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				configs[path] = raw
			}
			run := func(label, grant string, args ...string) ([]byte, int) {
				t.Helper()
				child, cancel := context.WithTimeout(ctx, 15*time.Second)
				defer cancel()
				argv := append([]string{"--config", filepath.Join(dir, grant+".conf"), "--cache-dir", filepath.Join(dir, "cache"), "--temp-dir", dir, "--retries", "1", "--low-level-retries", "1", "--contimeout", "3s", "--timeout", "10s", "--log-level", "ERROR"}, args...)
				cmd := exec.CommandContext(child, "/opt/triage/rclone", argv...)
				cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "TMPDIR=" + dir, "GOMAXPROCS=2", "GOGC=35"}
				var out, stderr bytes.Buffer
				cmd.Stdout = &out
				cmd.Stderr = &stderr
				err := cmd.Run()
				code := 0
				if child.Err() != nil {
					t.Fatalf("native_timeout: %s/%s", backend, label)
				}
				if err != nil {
					var ok bool
					var exit *exec.ExitError
					exit, ok = err.(*exec.ExitError)
					if !ok {
						t.Fatal("native_start_failed")
					}
					code = exit.ExitCode()
				}
				for path, expected := range configs {
					current, e := os.ReadFile(path)
					if e != nil || !bytes.Equal(current, expected) {
						t.Fatal("configuration_changed")
					}
				}
				checks = append(checks, nativeCheck{backend, label, code, out.Len()})
				if code != 0 && grant == "read" && !strings.HasSuffix(label, "denied") && !strings.HasPrefix(label, "missing") {
					t.Logf("native_failure %s: %s", label, stderr.String())
				}
				return out.Bytes(), code
			}
			type entry struct {
				Path  string
				Size  int64
				IsDir bool
			}
			verifyList := func(grant string) {
				t.Helper()
				raw, code := run("listing-"+grant, grant, "lsjson", "Synthetic:"+bucket, "--recursive", "--files-only")
				var entries []entry
				if code != 0 || json.Unmarshal(raw, &entries) != nil || len(entries) != len(files) {
					t.Fatal("native_listing_failed")
				}
				seen := map[string]bool{}
				for _, entry := range entries {
					data, ok := files[entry.Path]
					if !ok || seen[entry.Path] || entry.IsDir || int64(len(data)) != entry.Size {
						t.Fatal("native_listing_mismatch")
					}
					seen[entry.Path] = true
				}
			}
			verifyList("read")
			verifyList("list-only")
			for _, name := range names {
				raw, code := run("cat:"+name, "read", "cat", "Synthetic:"+bucket+"/"+name)
				if code != 0 || !bytes.Equal(raw, files[name]) {
					t.Fatal("native_cat_hash_mismatch")
				}
				destination := filepath.Join(dir, fmt.Sprintf("download-%x", sha256.Sum256([]byte(name))))
				_, code = run("copy:"+name, "read", "copyto", "Synthetic:"+bucket+"/"+name, destination)
				got, err := os.ReadFile(destination)
				if code != 0 || err != nil || !bytes.Equal(got, files[name]) {
					t.Fatal("native_copy_hash_mismatch")
				}
			}
			for _, name := range []string{"nested/bytes.bin", "nested/remote-piece.bin"} {
				offset, count := 3, 11
				if strings.Contains(name, "remote-piece") {
					offset, count = 1234, 8193
				}
				raw, code := run("range:"+name, "read", "cat", "Synthetic:"+bucket+"/"+name, "--offset", fmt.Sprint(offset), "--count", fmt.Sprint(count))
				if code != 0 || !bytes.Equal(raw, files[name][offset:offset+count]) {
					t.Fatal("native_range_mismatch")
				}
			}
			unknownOutput, unknownCode := run("unknown-key-list-denied", "unknown", "lsjson", "Synthetic:"+bucket, "--files-only")
			if unknownCode == 0 || bytes.Contains(unknownOutput, []byte("README-synthetic")) {
				t.Fatal("unknown_key_accepted")
			}
			raw, code := run("expired-list-denied", "expired", "lsjson", "Synthetic:"+bucket, "--files-only")
			if code == 0 || bytes.Contains(raw, []byte("README-synthetic")) {
				t.Fatal("expired_grant_accepted")
			}
			for _, name := range []string{"README-synthetic.txt", "nested/remote-piece.bin"} {
				raw, code := run("cat-denied", "list-only", "cat", "Synthetic:"+bucket+"/"+name)
				if code == 0 || len(raw) != 0 {
					t.Fatal("download_denial_accepted")
				}
				destination := filepath.Join(dir, "denied-download")
				_, code = run("copy-denied", "list-only", "copyto", "Synthetic:"+bucket+"/"+name, destination)
				_, staterr := os.Stat(destination)
				if code == 0 || !os.IsNotExist(staterr) {
					t.Fatal("denied_copy_created_file")
				}
			}
			missing := filepath.Join(dir, "missing-download")
			_, code = run("missing-copy", "read", "copyto", "--error-on-no-transfer", "Synthetic:"+bucket+"/missing.txt", missing)
			_, missingErr := os.Stat(missing)
			if code == 0 || !os.IsNotExist(missingErr) {
				t.Fatal("missing_object_copy_accepted")
			}
			_, code = run("delete-denied", "read", "deletefile", "Synthetic:"+bucket+"/README-synthetic.txt")
			if code == 0 {
				t.Fatal("readonly_delete_accepted")
			}
			upload := filepath.Join(dir, "upload.txt")
			if err := os.WriteFile(upload, []byte("Synthetic forbidden mutation.\n"), 0600); err != nil {
				t.Fatal(err)
			}
			_, code = run("upload-denied", "read", "copyto", upload, "Synthetic:"+bucket+"/forbidden.txt")
			if code == 0 {
				t.Fatal("readonly_upload_accepted")
			}
			verifyList("read")
			for _, name := range names {
				got, err := client.Download(ctx, sat, bucket, name)
				if err != nil || !bytes.Equal(got, files[name]) {
					t.Fatal("source_changed")
				}
			}
		}
		result := map[string]any{"success": true, "backends": []string{"storj", "tardigrade"}, "inline_segments": inline, "remote_segments": remote, "remote_pieces": pieces, "native_checks": checks, "source_preserved": true, "configuration_preserved": true}
		data, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println("TRIAGE_STORJ_NATIVE_RESULT " + string(data))
	})
	if !observed {
		t.Fatal("synthetic_network_not_executed")
	}
}
