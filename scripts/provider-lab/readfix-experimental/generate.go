package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"sort"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

type M = map[string]any

const email = "synthetic@example.invalid"

var folderHashKeys = map[string][]byte{}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
func token() string { return base64.StdEncoding.EncodeToString(must(crypto.RandomToken(32))) }
func key(pass string) (string, *crypto.KeyRing) {
	k := must(crypto.PGP().KeyGeneration().AddUserId("Synthetic fixture", email).New().GenerateKey())
	locked := must(crypto.PGP().LockKey(k, []byte(pass)))
	return must(locked.Armor()), must(crypto.NewKeyRing(k))
}
func encrypt(kr, signer *crypto.KeyRing, value []byte) string {
	b := crypto.PGP().Encryption().Recipients(kr)
	if signer != nil {
		b = b.SigningKeys(signer)
	}
	return must(must(must(b.New()).Encrypt(value)).Armor())
}
func sign(kr *crypto.KeyRing, value []byte, armor bool) []byte {
	encoding := crypto.Bytes
	if armor {
		encoding = crypto.Armor
	}
	return must(must(crypto.PGP().Sign().SigningKeys(kr).Detached().New()).Sign(value, encoding))
}
func newNode(id, parent, name string, parentKR, addrKR *crypto.KeyRing, kind int) (M, *crypto.KeyRing) {
	pass := token()
	locked, kr := key(pass)
	n := M{"LinkID": id, "ParentLinkID": parent, "Type": kind, "Name": encrypt(parentKR, addrKR, []byte(name)),
		"NameSignatureEmail": email, "Hash": "", "Size": 0, "State": 1, "MIMEType": "application/octet-stream",
		"CreateTime": 1704067200, "ModifyTime": 1704067200, "ExpirationTime": 0,
		"NodeKey": locked, "NodePassphrase": encrypt(parentKR, nil, []byte(pass)),
		"NodePassphraseSignature": string(sign(addrKR, []byte(pass), true)), "SignatureEmail": email}
	if kind == 1 {
		n["MIMEType"] = "Folder"
		folderHashKeys[id] = []byte(token())
		n["FolderProperties"] = M{"NodeHashKey": encrypt(kr, addrKR, folderHashKeys[id])}
	}
	if hashKey, ok := folderHashKeys[parent]; ok {
		mac := hmac.New(sha256.New, hashKey)
		mac.Write([]byte(name))
		n["Hash"] = hex.EncodeToString(mac.Sum(nil))
	}
	return n, kr
}
func main() {
	var files map[string][]byte
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 32768))
	if err := decoder.Decode(&files); err != nil {
		panic(err)
	}
	if len(files) != 3 {
		panic("expected three synthetic files")
	}
	userPass := token()
	userLocked, userKR := key(userPass)
	addressPass := token()
	addressLocked, addrKR := key(addressPass)
	addressToken := encrypt(userKR, nil, []byte(addressPass))
	user := M{"ID": "user-synthetic", "Name": "synthetic", "DisplayName": "Synthetic fixture", "Email": email,
		"UsedSpace": 4096, "MaxSpace": 1048576, "MaxUpload": 1048576,
		"Keys": []M{{"ID": "key-user", "PrivateKey": userLocked, "Primary": 1, "Active": 1, "Flags": 3}}}
	addresses := []M{{"ID": "address-synthetic", "Email": email, "Send": 1, "Receive": 1, "Status": 1, "Type": 1, "Order": 0,
		"DisplayName": "Synthetic fixture", "Keys": []M{{"ID": "key-address", "PrivateKey": addressLocked, "Primary": 1, "Active": 1,
			"Flags": 3, "Token": addressToken, "Signature": string(sign(userKR, []byte(addressPass), true))}}}}
	sharePass := token()
	shareLocked, shareKR := key(sharePass)
	shareMeta := M{"ShareID": "share-synthetic", "LinkID": "link-root", "VolumeID": "volume-synthetic", "Type": 1,
		"State": 1, "CreationTime": 1704067200, "ModifyTime": 1704067200, "Creator": email, "Flags": 1,
		"Locked": false, "VolumeSoftDeleted": false}
	share := M{}
	for k, v := range shareMeta {
		share[k] = v
	}
	share["AddressID"] = "address-synthetic"
	share["AddressKeyID"] = "key-address"
	share["Key"] = shareLocked
	share["Passphrase"] = encrypt(addrKR, nil, []byte(sharePass))
	share["PassphraseSignature"] = string(sign(addrKR, []byte(sharePass), true))
	root, rootKR := newNode("link-root", "", "Synthetic", shareKR, addrKR, 1)
	nested, nestedKR := newNode("link-nested", "link-root", "nested", rootKR, addrKR, 1)
	links := map[string]M{"link-root": root, "link-nested": nested}
	revisions := map[string]M{}
	blocks := map[string][]byte{}
	wrongSignatures := map[string]string{}
	ids := map[string]string{}
	names := []string{}
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for i, name := range names {
		payload := files[name]
		parent := "link-root"
		parentKR := rootKR
		if path.Dir(name) == "nested" {
			parent = "link-nested"
			parentKR = nestedKR
		} else if path.Dir(name) != "." {
			panic("unexpected parent")
		}
		id := fmt.Sprintf("link-file-%d", i)
		ids[name] = id
		link, nodeKR := newNode(id, parent, path.Base(name), parentKR, addrKR, 2)
		session := must(crypto.PGP().GenerateSessionKey())
		packet := must(must(crypto.PGP().Encryption().Recipients(nodeKR).New()).EncryptSessionKey(session))
		encrypted := must(must(crypto.PGP().Encryption().SessionKey(session).New()).Encrypt(payload)).Bytes()
		hash := sha256.Sum256(encrypted)
		plainHash := sha1.Sum(payload)
		xattr := must(json.Marshal(M{"Common": M{"ModificationTime": "2024-01-01T00:00:00+0000", "Size": len(payload),
			"BlockSizes": []int{len(payload)}, "Digests": M{"SHA1": hex.EncodeToString(plainHash[:])}}}))
		encryptedAttrs := encrypt(nodeKR, addrKR, xattr)
		revID := "revision-" + id
		revisionMeta := M{"ID": revID, "CreateTime": 1704067200, "Size": len(encrypted), "ManifestSignature": "",
			"SignatureEmail": email, "State": 1, "XAttr": encryptedAttrs, "Thumbnail": 0, "ThumbnailHash": ""}
		revision := M{}
		for k, v := range revisionMeta {
			revision[k] = v
		}
		revision["Blocks"] = []M{{"Index": 1, "BareURL": "https://synthetic-content.proton.invalid/blocks/" + id,
			"Token": "block-token-" + id, "Hash": base64.StdEncoding.EncodeToString(hash[:]),
			"EncSignature": encrypt(nodeKR, nil, sign(addrKR, payload, false)), "SignatureEmail": email}}
		link["Size"] = len(encrypted)
		link["XAttr"] = encryptedAttrs
		link["FileProperties"] = M{"ContentKeyPacket": base64.StdEncoding.EncodeToString(packet),
			"ContentKeyPacketSignature": string(sign(nodeKR, session.Key, true)), "ActiveRevision": revisionMeta}
		wrongPlain := append([]byte(nil), payload...)
		wrongPlain[0] ^= 1
		wrongSignatures[id] = encrypt(nodeKR, nil, sign(addrKR, wrongPlain, false))
		links[id] = link
		revisions[id] = revision
		blocks[id] = encrypted
	}
	volume := M{"VolumeID": "volume-synthetic", "CreationTime": 1704067200, "ModifyTime": 1704067200, "MaxSpace": 1048576,
		"UsedSpace": 4096, "DownloadedBytes": 0, "UploadedBytes": 0, "State": 1,
		"Share": M{"ShareID": "share-synthetic", "LinkID": "link-root"}, "RestoreStatus": nil}
	output := M{"user": user, "addresses": addresses, "share": share, "share_metadata": shareMeta, "volumes": []M{volume},
		"links": links, "revisions": revisions, "blocks": blocks, "wrong_signatures": wrongSignatures, "ids": ids, "salted_key_pass": base64.StdEncoding.EncodeToString([]byte(userPass))}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		panic(err)
	}
}
