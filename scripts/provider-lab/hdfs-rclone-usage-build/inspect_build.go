// Inspect full rclone experiment binaries without exposing version-output text.
package main

import (
 "crypto/sha256"
 "debug/buildinfo"
 "encoding/hex"
 "encoding/json"
 "io"
 "os"
 "runtime"
 "sort"
 "strings"
)

type module struct {
 Path string `json:"path"`
 Version string `json:"version"`
 Sum string `json:"sum"`
 Replacement string `json:"replacement"`
}
type binary struct {
 Variant string `json:"variant"`
 SHA256 string `json:"sha256"`
 Bytes int64 `json:"bytes"`
 Checks int `json:"checks"`
 VersionVerified bool `json:"version_verified"`
 Modules []module `json:"modules"`
}
type report struct {
 Schema int `json:"schema_version"`
 Success bool `json:"success"`
 Error string `json:"error"`
 GoVersion string `json:"go_version"`
 Binaries []binary `json:"binaries"`
 RcloneRenewalVerified bool `json:"rclone_renewal_verified"`
 ProviderAccepted bool `json:"provider_accepted"`
}
func need(v bool) { if !v { panic("probe_failed") } }
func inspect(variant string) binary {
 r:=binary{Variant:variant,Modules:[]module{}}
 check:=func(v bool){need(v);r.Checks++}
 file:="/opt/probes/rclone-"+variant
 info,err:=os.Lstat(file);need(err==nil)
 check(info.Mode().IsRegular() && info.Mode().Perm()==0555)
 check(info.Size()>1024*1024 && info.Size()<=512*1024*1024);r.Bytes=info.Size()
 f,err:=os.Open(file);need(err==nil)
 digest:=sha256.New();n,err:=io.Copy(digest,io.LimitReader(f,512*1024*1024+1));need(f.Close()==nil && err==nil && n==info.Size())
 r.SHA256=hex.EncodeToString(digest.Sum(nil))
 bi,err:=buildinfo.ReadFile(file);need(err==nil)
 check(bi.GoVersion=="go1.26.10" && bi.Path=="github.com/rclone/rclone" && bi.Main.Path=="github.com/rclone/rclone")
 settings:=map[string]string{}
 for _,s:=range bi.Settings { _,exists:=settings[s.Key];need(!exists);settings[s.Key]=s.Value }
 check(settings["CGO_ENABLED"]=="0")
 check(settings["GOOS"]=="linux")
 check(settings["GOARCH"]=="amd64")
 check(settings["-trimpath"]=="true")
 vcs:=false;for k:=range settings { if strings.HasPrefix(k,"vcs") { vcs=true } };check(!vcs)
 versionFile:="/work/"+variant+"-version"
 vi,err:=os.Lstat(versionFile);need(err==nil && vi.Mode().IsRegular() && vi.Size()>0 && vi.Size()<=8192)
 raw,err:=os.ReadFile(versionFile);need(err==nil && int64(len(raw))==vi.Size())
 lines:=strings.Split(strings.TrimSpace(string(raw)),"\n")
 check(len(lines)>=7 && len(lines)<=12 && strings.TrimSpace(lines[0])=="rclone v1.75.2-kerberos-"+variant)
 has:=func(expected string)bool { found:=0;for _,line:=range lines { if strings.TrimSpace(line)==expected { found++ } };return found==1 }
 check(has("- go/version: go1.26.10") && has("- os/type: linux") && has("- os/arch: amd64") && has("- go/linking: static"))
 r.VersionVerified=true
 check(len(bi.Deps)>0 && len(bi.Deps)<=334)
 replacements,kerberos:=0,0
 seen:=map[string]bool{}
 for _,d:=range bi.Deps {
  need(len(d.Path)>0 && len(d.Path)<=256 && len(d.Version)>0 && len(d.Version)<=128 && !seen[d.Path])
  seen[d.Path]=true
  m:=module{Path:d.Path,Version:d.Version,Sum:d.Sum}
  if d.Path=="github.com/jcmturner/gokrb5/v8" { kerberos++;need(d.Version=="v8.4.4") }
  if d.Replace!=nil {
   need(variant=="patched" && d.Path=="github.com/jcmturner/gokrb5/v8" && d.Sum=="")
   need(d.Replace.Path=="/opt/input/patched-gokrb" && (d.Replace.Version=="" || d.Replace.Version=="(devel)") && d.Replace.Sum=="")
   replacements++;m.Replacement="context-fix"
  } else { need(strings.HasPrefix(d.Sum,"h1:") && len(d.Sum)==47) }
  r.Modules=append(r.Modules,m)
 }
 check((variant=="original" && replacements==0)||(variant=="patched" && replacements==1))
 check(kerberos==1)
 sort.Slice(r.Modules,func(i,j int)bool{return r.Modules[i].Path<r.Modules[j].Path})
 return r
}
func run(r *report){
 need(runtime.Version()=="go1.26.10" && runtime.GOOS=="linux" && runtime.GOARCH=="amd64")
 r.Binaries=append(r.Binaries,inspect("original"),inspect("patched"))
 a,b:=r.Binaries[0],r.Binaries[1]
 need(a.SHA256!=b.SHA256 && len(a.Modules)==len(b.Modules))
 for i,m:=range a.Modules {
  n:=b.Modules[i];need(m.Path==n.Path && m.Version==n.Version)
  if m.Path!="github.com/jcmturner/gokrb5/v8" {need(m==n)}
 }
 r.Success=true;r.Error="none"
}
func main(){
 r:=report{Schema:1,GoVersion:runtime.Version(),Error:"probe_failed",Binaries:[]binary{}}
 func(){defer func(){if recover()!=nil{r.Success=false;r.Error="probe_failed"}}();run(&r)}()
 if json.NewEncoder(os.Stdout).Encode(r)!=nil || !r.Success { os.Exit(1) }
}
