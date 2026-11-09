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
 "regexp"
 "strconv"
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
type contextTests struct {
 Stage string `json:"stage"`
 ParserVectors int `json:"parser_vectors"`
 BinarySHA256 string `json:"binary_sha256"`
 BinaryBytes int64 `json:"binary_bytes"`
 ExitCode int `json:"exit_code"`
 StderrEmpty bool `json:"stderr_empty"`
 ProtocolValid bool `json:"protocol_valid"`
 Runs []string `json:"runs"`
 Passed []string `json:"passed"`
 Failed []string `json:"failed"`
 AllPassed bool `json:"all_passed"`
}
type report struct {
 Schema int `json:"schema_version"`
 Success bool `json:"success"`
 Error string `json:"error"`
 GoVersion string `json:"go_version"`
 Binaries []binary `json:"binaries"`
 ContextTests contextTests `json:"context_tests"`
 RcloneRenewalVerified bool `json:"rclone_renewal_verified"`
 ProviderAccepted bool `json:"provider_accepted"`
 CancellationVerified bool `json:"cancellation_verified"`
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
 expectedVersion:="rclone v1.75.2-kerberos-original";if variant=="patched"{expectedVersion="rclone v1.75.2-hdfs-context-patched"}
 check(len(lines)>=7 && len(lines)<=12 && strings.TrimSpace(lines[0])==expectedVersion)
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
   need(variant=="patched" && d.Path=="github.com/colinmarc/hdfs/v2" && d.Version=="v2.4.0" && d.Sum=="")
   need(d.Replace.Path=="/opt/input/patched-hdfs" && (d.Replace.Version=="" || d.Replace.Version=="(devel)") && d.Replace.Sum=="")
   replacements++;m.Replacement="context-cancellation"
  } else { need(strings.HasPrefix(d.Sum,"h1:") && len(d.Sum)==47) }
  r.Modules=append(r.Modules,m)
 }
 check((variant=="original" && replacements==0)||(variant=="patched" && replacements==1))
 check(kerberos==1)
 sort.Slice(r.Modules,func(i,j int)bool{return r.Modules[i].Path<r.Modules[j].Path})
 return r
}

var expectedContextTests=[]string{"TestContextAdmissionCancellationPreservesOwner","TestContextPrecancelledRequestHasNoEffects","TestContextExpiredDeadlineHasNoEffects","TestContextHeldResponseFinishesBeforeRelease","TestContextBlockedWriteFinishes","TestContextDialReceivesCancellation","TestContextHandshakeReceivesCancellation","TestContextCompletedRequestCannotCloseNextOperation","TestContextStartedCallbackIsJoinedBeforeReturn","TestContextNonCancellationErrorIsPreserved","TestContextCancelledStreamRequiresFreshDial"}

func privateBytes(file string, maximum int64) []byte {
 info,err:=os.Lstat(file);need(err==nil && info.Mode().IsRegular() && info.Mode().Perm()==0600 && info.Size()>=0 && info.Size()<=maximum)
 f,err:=os.Open(file);need(err==nil)
 raw,err:=io.ReadAll(io.LimitReader(f,maximum+1));need(f.Close()==nil && err==nil && int64(len(raw))==info.Size())
 return raw
}


func parseContextOutput(raw []byte,r *contextTests) {
 r.Stage="parse"
 valid:=len(raw)>0 && raw[len(raw)-1]=='\n';lines:=strings.Split(strings.TrimSuffix(string(raw),"\n"),"\n")
 start:=regexp.MustCompile("^=== RUN   (TestContext[A-Za-z]+)$")
 finish:=regexp.MustCompile(`^--- (PASS|FAIL): (TestContext[A-Za-z]+) \(([0-9]+\.[0-9]+)s\)$`)
 known:=map[string]bool{};for _,name:=range expectedContextTests{known[name]=true}
 seen:=map[string]bool{};active:="";terminal:=0;lastPass:=false
 for index,line:=range lines {
  if match:=start.FindStringSubmatch(line);match!=nil {
   name:=match[1]
   if !known[name] || seen[name] || active!="" || terminal!=0 || len(r.Runs)>=len(expectedContextTests) {valid=false;continue}
   if name!=expectedContextTests[len(r.Runs)]{valid=false}
   seen[name]=true;active=name;r.Runs=append(r.Runs,name);continue
  }
  if match:=finish.FindStringSubmatch(line);match!=nil {
   name:=match[2];duration,e:=strconv.ParseFloat(match[3],64)
   if !known[name] || name!=active || terminal!=0 || e!=nil || duration<0 || duration>30 {valid=false;continue}
   if match[1]=="PASS"{r.Passed=append(r.Passed,name)}else{r.Failed=append(r.Failed,name)}
   active="";continue
  }
  if line=="PASS" || line=="FAIL" {
   terminal++;lastPass=line=="PASS"
   if active!="" || index!=len(lines)-1{valid=false}
   continue
  }
  valid=false
 }
 r.ProtocolValid=valid && terminal==1 && active==""
 r.AllPassed=r.ProtocolValid && lastPass && r.ExitCode==0 && r.StderrEmpty && len(r.Runs)==len(expectedContextTests) && len(r.Passed)==len(expectedContextTests) && len(r.Failed)==0
 if r.AllPassed{r.Stage="complete"}else{r.Stage="failed"}
}

func contextParserControls() int {
 good:=""
 for _,name:=range expectedContextTests{good+="=== RUN   "+name+"\n--- PASS: "+name+" (0.00s)\n"}
 first:="=== RUN   "+expectedContextTests[0]+"\n--- PASS: "+expectedContextTests[0]+" (0.00s)\n"
 second:="=== RUN   "+expectedContextTests[1]+"\n--- PASS: "+expectedContextTests[1]+" (0.00s)\n"
 good+="PASS\n"
 cases:=[]struct{raw string;status int;stderrEmpty bool;want bool}{
  {good,0,true,true},
  {strings.TrimSuffix(good,"PASS\n")+"unexpected text\nPASS\n",0,true,false},
  {strings.Replace(good,"--- PASS:","--- FAIL:",1),0,true,false},
  {strings.Replace(good,"--- PASS:","--- SKIP:",1),0,true,false},
  {first+good,0,true,false},
  {strings.TrimPrefix(good,first),0,true,false},
  {strings.Replace(good,expectedContextTests[0],"TestContextUnknown",1),0,true,false},
  {strings.Replace(good,first+second,second+first,1),0,true,false},
  {strings.TrimSuffix(good,"PASS\n")+"FAIL\n",0,true,false},
  {strings.Replace(good," (0.00s)"," (31.00s)",1),0,true,false},
  {strings.TrimSuffix(good,"\n"),0,true,false},
  {good,1,true,false},
  {good,0,false,false},
  {strings.TrimSuffix(good,"PASS\n"),0,true,false},
 }
 checked:=0
 for _,test:=range cases {
  result:=contextTests{ExitCode:test.status,StderrEmpty:test.stderrEmpty,Runs:[]string{},Passed:[]string{},Failed:[]string{}}
  parseContextOutput([]byte(test.raw),&result);need(result.AllPassed==test.want);checked++
 }
 need(checked==14);return checked
}

func inspectContextTests(r *contextTests) {
 r.ParserVectors=contextParserControls()
 r.Stage="binary"
 info,err:=os.Lstat("/opt/probes/context-tests");need(err==nil && info.Mode().IsRegular() && info.Mode().Perm()==0555 && info.Size()>1024*1024 && info.Size()<=128*1024*1024)
 f,err:=os.Open("/opt/probes/context-tests");need(err==nil)
 digest:=sha256.New();n,err:=io.Copy(digest,io.LimitReader(f,128*1024*1024+1));need(f.Close()==nil && err==nil && n==info.Size())
 r.BinarySHA256=hex.EncodeToString(digest.Sum(nil));r.BinaryBytes=n
 bi,err:=buildinfo.ReadFile("/opt/probes/context-tests");need(err==nil && bi.GoVersion=="go1.26.10" && bi.Path=="github.com/colinmarc/hdfs/v2/internal/rpc.test")
 settings:=map[string]string{};for _,s:=range bi.Settings {_,exists:=settings[s.Key];need(!exists);settings[s.Key]=s.Value}
 need(settings["CGO_ENABLED"]=="0" && settings["GOOS"]=="linux" && settings["GOARCH"]=="amd64" && settings["-trimpath"]=="true")
 r.Stage="status"
 status:=privateBytes("/work/context-tests-status",4)
 need(regexp.MustCompile("^(0|[1-9][0-9]{0,2})\n$").Match(status))
 r.ExitCode,err=strconv.Atoi(strings.TrimSuffix(string(status),"\n"));need(err==nil && r.ExitCode>=0 && r.ExitCode<=255)
 r.Stage="stderr";r.StderrEmpty=len(privateBytes("/work/context-tests-stderr",16384))==0
 parseContextOutput(privateBytes("/work/context-tests-stdout",16384),r)
 need(r.AllPassed)
}

func run(r *report){
 need(runtime.Version()=="go1.26.10" && runtime.GOOS=="linux" && runtime.GOARCH=="amd64")
 inspectContextTests(&r.ContextTests)
 r.Binaries=append(r.Binaries,inspect("original"),inspect("patched"))
 a,b:=r.Binaries[0],r.Binaries[1]
 need(a.SHA256!=b.SHA256 && len(a.Modules)==len(b.Modules))
 for i,m:=range a.Modules {
  n:=b.Modules[i];need(m.Path==n.Path && m.Version==n.Version)
  if m.Path!="github.com/colinmarc/hdfs/v2" {need(m==n)}
 }
 r.Success=true;r.Error="none"
}
func main(){
 r:=report{Schema:1,GoVersion:runtime.Version(),Error:"probe_failed",Binaries:[]binary{},ContextTests:contextTests{Stage:"start",ExitCode:-1,Runs:[]string{},Passed:[]string{},Failed:[]string{}}}
 func(){defer func(){if recover()!=nil{r.Success=false;r.Error="probe_failed"}}();run(&r)}()
 if json.NewEncoder(os.Stdout).Encode(r)!=nil || !r.Success { os.Exit(1) }
}
