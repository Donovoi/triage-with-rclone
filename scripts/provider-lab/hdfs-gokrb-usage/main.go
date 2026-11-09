// Synthetic, offline constructor regression. No KDC or rclone is contacted.
package main

import (
 "bytes"
 "encoding/json"
 "os"
 "runtime"
 "runtime/debug"
 "time"

 "github.com/jcmturner/gokrb5/v8/config"
 krbcrypto "github.com/jcmturner/gokrb5/v8/crypto"
 "github.com/jcmturner/gokrb5/v8/iana/flags"
 "github.com/jcmturner/gokrb5/v8/iana/patype"
 "github.com/jcmturner/gokrb5/v8/messages"
 "github.com/jcmturner/gokrb5/v8/types"
)

// Injected at compile time from a closed set by the contained build driver.
var variant = "unset"

type row struct {
 Case string `json:"case"`
 Usage int `json:"usage"`
 Checks int `json:"checks"`
 NegativeControls int `json:"negative_controls"`
 RequiredUsage bool `json:"required_usage"`
}
type dependency struct {
 Path string `json:"path"`
 Version string `json:"version"`
 Sum string `json:"sum"`
}
type report struct {
 Schema int `json:"schema_version"`
 Variant string `json:"variant"`
 Success bool `json:"success"`
 Error string `json:"error"`
 GoVersion string `json:"go_version"`
 Dependencies []dependency `json:"dependencies"`
 Cases []row `json:"cases"`
 RcloneVerified bool `json:"rclone_verified"`
 RenewalVerified bool `json:"renewal_verified"`
 ProviderAccepted bool `json:"provider_accepted"`
}
func need(ok bool, code string) { if !ok { panic(code) } }
func ok(err error) { need(err == nil, "api_failed") }
func samePrincipal(a,b types.PrincipalName) bool {
 if a.NameType != b.NameType || len(a.NameString) != len(b.NameString) { return false }
 for i := range a.NameString { if a.NameString[i] != b.NameString[i] { return false } }
 return true
}
func wipe(b []byte) { for i := range b { b[i] = 0 } }

func probe(id string, keyType int32, tgs, renewal bool, ticketService string) row {
 checks, controls := 0, 0
 check := func(v bool) { need(v,"binding_failed"); checks++ }
 cname := types.PrincipalName{NameType:1,NameString:[]string{"synthetic-reader"}}
 sname := types.PrincipalName{NameType:2,NameString:[]string{ticketService,"localhost"}}
 if ticketService == "krbtgt" { sname.NameString[1] = "SYNTHETIC.TEST" }
 keySize := 16; if keyType == 18 { keySize=32 }
 key := types.EncryptionKey{KeyType:keyType,KeyValue:bytes.Repeat([]byte{0x42},keySize)}
 defer wipe(key.KeyValue)
 ticket := messages.Ticket{TktVNO:5,Realm:"SYNTHETIC.TEST",SName:sname,
  EncPart:types.EncryptedData{EType:keyType,KVNO:1,Cipher:bytes.Repeat([]byte{0x24},48)}}
 var ap messages.APReq
 var body []byte
 if tgs {
  cfg := &config.Config{LibDefaults:config.LibDefaults{NoAddresses:true,
   TicketLifetime:time.Minute,DefaultTGSEnctypeIDs:[]int32{keyType}}}
  requested := types.PrincipalName{NameType:2,NameString:[]string{"hdfs","localhost"}}
  req,err := messages.NewTGSReq(cname,"SYNTHETIC.TEST",cfg,ticket,key,requested,renewal);ok(err)
  check(req.PVNO==5 && req.MsgType==12 && req.Renewal==renewal)
  check(types.IsFlagSet(&req.ReqBody.KDCOptions,flags.Renew)==renewal)
  check(types.IsFlagSet(&req.ReqBody.KDCOptions,flags.Renewable)==renewal)
  check(req.ReqBody.RTime.IsZero() && len(req.ReqBody.Addresses)==0)
  check(samePrincipal(req.ReqBody.SName,requested) && req.ReqBody.Realm=="SYNTHETIC.TEST")
  body,err=req.ReqBody.Marshal();ok(err)
  check(len(req.PAData)==1 && req.PAData[0].PADataType==patype.PA_TGS_REQ)
  ok(ap.Unmarshal(req.PAData[0].PADataValue))
  encoded,err:=ap.Marshal();ok(err);check(bytes.Equal(encoded,req.PAData[0].PADataValue))
 } else {
  auth,err:=types.NewAuthenticator("SYNTHETIC.TEST",cname);ok(err)
  ap,err=messages.NewAPReq(ticket,key,auth);ok(err)
  encoded,err:=ap.Marshal();ok(err)
  var decoded messages.APReq;ok(decoded.Unmarshal(encoded));ap=decoded
 }
 check(ap.PVNO==5 && ap.MsgType==14 && ap.EncryptedAuthenticator.EType==keyType)
 aTicket,err:=ap.Ticket.Marshal();ok(err);originalTicket,err:=ticket.Marshal();ok(err)
 check(bytes.Equal(aTicket,originalTicket))
 var plain []byte;usage:=0
 for _,u:=range []int{7,11} {
  b,err:=krbcrypto.DecryptEncPart(ap.EncryptedAuthenticator,key,uint32(u))
  if err==nil { need(usage==0,"usage_ambiguous");usage=u;plain=b } else { wipe(b) }
 }
 check(usage==7 || usage==11);defer wipe(plain)
 var auth types.Authenticator;ok(auth.Unmarshal(plain))
 encoded,err:=auth.Marshal();ok(err);check(bytes.Equal(encoded,plain));wipe(encoded)
 check(auth.AVNO==5 && auth.CRealm=="SYNTHETIC.TEST" && samePrincipal(auth.CName,cname))
 check(auth.Cusec>=0 && auth.Cusec<1000000 && time.Since(auth.CTime)<30*time.Second && time.Until(auth.CTime)<30*time.Second)
 check(len(auth.SubKey.KeyValue)==0 && len(auth.AuthorizationData)==0)
 wrongKey:=types.EncryptionKey{KeyType:keyType,KeyValue:bytes.Repeat([]byte{0x43},keySize)}
 defer wipe(wrongKey.KeyValue)
 wrong,err:=krbcrypto.DecryptEncPart(ap.EncryptedAuthenticator,wrongKey,uint32(usage));wipe(wrong)
 need(err!=nil,"wrong_key_accepted");controls++
 corrupt:=ap.EncryptedAuthenticator;corrupt.Cipher=append([]byte(nil),corrupt.Cipher...)
 corrupt.Cipher[len(corrupt.Cipher)-1]^=1
 wrong,err=krbcrypto.DecryptEncPart(corrupt,key,uint32(usage));wipe(wrong);wipe(corrupt.Cipher)
 need(err!=nil,"corrupt_accepted");controls++
 other:=uint32(7);if usage==7 { other=11 }
 wrong,err=krbcrypto.DecryptEncPart(ap.EncryptedAuthenticator,key,other);wipe(wrong)
 need(err!=nil,"wrong_usage_accepted");controls++
 if tgs {
  et,err:=krbcrypto.GetEtype(keyType);ok(err)
  check(auth.Cksum.CksumType==et.GetHashID() && et.VerifyChecksum(key.KeyValue,body,auth.Cksum.Checksum,6))
  changed:=append([]byte(nil),body...);changed[len(changed)-1]^=1
  need(!et.VerifyChecksum(key.KeyValue,changed,auth.Cksum.Checksum,6),"changed_body_accepted");controls++;wipe(changed)
 } else { check(auth.Cksum.CksumType==0 && len(auth.Cksum.Checksum)==0) }
 required:=11;if tgs { required=7 }
 return row{Case:id,Usage:usage,Checks:checks,NegativeControls:controls,RequiredUsage:usage==required}
}
func run(r *report) {
 need(variant=="original" || variant=="context-fix" || variant=="global-control","variant_invalid")
 need(runtime.Version()=="go1.26.10" && runtime.GOOS=="linux" && runtime.GOARCH=="amd64","toolchain_invalid")
 bi,exists:=debug.ReadBuildInfo();need(exists && bi.Main.Path=="github.com/jcmturner/gokrb5/v8","build_info_invalid")
 for _,d:=range bi.Deps { need(d.Replace==nil && d.Path!="" && d.Version!="" && d.Sum!="","build_info_invalid");r.Dependencies=append(r.Dependencies,dependency{d.Path,d.Version,d.Sum}) }
 need(len(r.Dependencies)>0 && len(r.Dependencies)<=16,"build_info_invalid")
 r.Cases=append(r.Cases,probe("tgt_tgs_aes128",17,true,false,"krbtgt"))
 r.Cases=append(r.Cases,probe("service_renew_aes128",17,true,true,"hdfs"))
 r.Cases=append(r.Cases,probe("service_renew_aes256",18,true,true,"hdfs"))
 r.Cases=append(r.Cases,probe("hdfs_ap_aes128",17,false,false,"hdfs"))
 r.Cases=append(r.Cases,probe("http_ap_aes128",17,false,false,"HTTP"))
 expected:=[]int{7,11,11,11,11}
 if variant=="context-fix" { expected=[]int{7,7,7,11,11} }
 if variant=="global-control" { expected=[]int{7,7,7,7,7} }
 for i,v:=range expected { need(r.Cases[i].Usage==v,"unexpected_usage") }
 r.Success=true;r.Error="none"
}
func main() {
 r:=report{Schema:1,Variant:variant,Error:"probe_failed",GoVersion:runtime.Version(),Dependencies:[]dependency{},Cases:[]row{}}
 func(){defer func(){if recover()!=nil { r.Success=false;r.Error="probe_failed" }}();run(&r)}()
 enc:=json.NewEncoder(os.Stdout);enc.SetEscapeHTML(true)
 if enc.Encode(r)!=nil || !r.Success { os.Exit(1) }
}
