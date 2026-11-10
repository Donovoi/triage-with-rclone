// Hosted-container-only native wrapper. No host-side Go execution is required.
package main

import (
 "bytes"
 "context"
 "crypto/sha256"
 "debug/buildinfo"
 "debug/elf"
 "encoding/hex"
 "encoding/json"
 "errors"
 "io"
 "os"
 "os/exec"
 "reflect"
 "runtime"
 "sort"
 "strings"
 "time"
)

const toolFile="/opt/probes/govulncheck"
const lockFile="/opt/input/audit-tool/tool-assets-lock.json"
const lockSHA="d9cb60f32fe2c837a5ed6109403e401033b143824e4fb4a1a33e8c5c8e472917"
const sourceVersion="v1.9.0"
const sourceOrigin="e672cbe8fbc8c76e28fcb6db0efd9ce354e0dac5"
const stdoutLimit=64*1024*1024
const stderrLimit=16*1024

type fileStamp struct {
 SHA256 string `json:"sha256"`
 Bytes int64 `json:"bytes"`
}
type moduleRow struct {
 Path string `json:"path"`
 Version string `json:"version"`
 Sum string `json:"sum"`
 Replacement string `json:"replacement"`
}
type binaryIdentity struct {
 File fileStamp `json:"file"`
 GoVersion string `json:"go_version"`
 Path string `json:"path"`
 Main moduleRow `json:"main"`
 Settings map[string]string `json:"settings"`
 Modules []moduleRow `json:"modules"`
}
type toolIdentity struct {
 Binary binaryIdentity `json:"binary"`
 SourceVersion string `json:"source_version"`
 SourceOrigin string `json:"source_origin"`
 LockSHA256 string `json:"lock_sha256"`
}
type strippedEvidence struct {
 Format string `json:"format"`
 SHA256 string `json:"sha256"`
 Bytes int64 `json:"bytes"`
 SymbolTableAbsent bool `json:"symbol_table_absent"`
 StringTableAbsent bool `json:"string_table_absent"`
 DwarfSectionsAbsent bool `json:"dwarf_sections_absent"`
 PCLNPresent bool `json:"pcln_present"`
}
type result struct {
 Schema int `json:"schema_version"`
 Success bool `json:"success"`
 Error string `json:"error"`
 Mode string `json:"mode"`
 Target string `json:"target"`
 Tool toolIdentity `json:"tool"`
 TargetBefore fileStamp `json:"target_before"`
 TargetAfter fileStamp `json:"target_after"`
 TargetIdentity *binaryIdentity `json:"target_identity"`
 StrippedEvidence *strippedEvidence `json:"stripped_evidence"`
 ToolUnchanged bool `json:"tool_unchanged"`
 TargetUnchanged bool `json:"target_unchanged"`
 ExitCode int `json:"exit_code"`
 TimedOut bool `json:"timed_out"`
 WaitDelayExceeded bool `json:"wait_delay_exceeded"`
 StdoutOverflow bool `json:"stdout_overflow"`
 StderrOverflow bool `json:"stderr_overflow"`
 Stdout []byte `json:"stdout_base64"`
 Stderr []byte `json:"stderr_base64"`
 StdoutSHA256 string `json:"stdout_sha256"`
 StderrSHA256 string `json:"stderr_sha256"`
 CaptureControls int `json:"capture_controls"`
 DurationMillis int64 `json:"duration_ms"`
 VulnerabilityAuditCompleted bool `json:"vulnerability_audit_completed"`
 ProviderAccepted bool `json:"provider_accepted"`
}
func require(ok bool,code string) {if !ok {panic(code)}}
func digest(raw []byte) string {h:=sha256.Sum256(raw);return hex.EncodeToString(h[:])}
func readFile(name string,maximum int64) []byte {
 before,e:=os.Lstat(name);require(e==nil&&before.Mode().IsRegular()&&before.Size()>0&&before.Size()<=maximum,"file_invalid")
 f,e:=os.Open(name);require(e==nil,"file_invalid");defer f.Close()
 opened,e:=f.Stat();require(e==nil&&os.SameFile(before,opened),"file_changed")
 raw,e:=io.ReadAll(io.LimitReader(f,maximum+1));require(e==nil&&int64(len(raw))==before.Size(),"file_invalid")
 after,e:=f.Stat();require(e==nil&&os.SameFile(before,after)&&before.Size()==after.Size()&&before.ModTime()==after.ModTime(),"file_changed")
 end,e:=os.Lstat(name);require(e==nil&&os.SameFile(before,end)&&end.Size()==before.Size()&&end.ModTime()==before.ModTime(),"file_changed")
 return raw
}
func stamp(name string,maximum int64) fileStamp {
 before,e:=os.Lstat(name);require(e==nil&&before.Mode().IsRegular()&&before.Size()>0&&before.Size()<=maximum,"file_invalid")
 f,e:=os.Open(name);require(e==nil,"file_invalid");defer f.Close()
 opened,e:=f.Stat();require(e==nil&&os.SameFile(before,opened),"file_changed")
 h:=sha256.New();n,e:=io.Copy(h,io.LimitReader(f,maximum+1))
 require(e==nil&&n==before.Size(),"file_invalid")
 after,e:=f.Stat();require(e==nil&&os.SameFile(before,after)&&before.Size()==after.Size()&&before.ModTime()==after.ModTime(),"file_changed")
 end,e:=os.Lstat(name);require(e==nil&&os.SameFile(before,end)&&end.Size()==before.Size()&&end.ModTime()==before.ModTime(),"file_changed")
 return fileStamp{hex.EncodeToString(h.Sum(nil)),n}
}
func inspectBinary(name string) binaryIdentity {
 before:=stamp(name,256*1024*1024)
 info,e:=buildinfo.ReadFile(name);require(e==nil,"build_info")
 identity:=binaryIdentity{File:before,GoVersion:info.GoVersion,Path:info.Path,
  Main:moduleRow{info.Main.Path,info.Main.Version,info.Main.Sum,""},Settings:map[string]string{},Modules:[]moduleRow{}}
 require(info.Main.Replace==nil&&info.GoVersion=="go1.26.10","build_info")
 for _,setting:=range info.Settings {
  _,seen:=identity.Settings[setting.Key];require(!seen,"build_settings")
  identity.Settings[setting.Key]=setting.Value
 }
 for k,v:=range map[string]string{"GOOS":"linux","GOARCH":"amd64","CGO_ENABLED":"0","-buildmode":"exe","-trimpath":"true"} {
  require(identity.Settings[k]==v,"build_settings")
 }
 for _,key:=range []string{"vcs","vcs.revision","vcs.time","vcs.modified"} {
  _,present:=identity.Settings[key];require(!present,"build_settings")
 }
 seen:=map[string]bool{}
 require(len(info.Deps)>0&&len(info.Deps)<=4096,"build_info")
 for _,dep:=range info.Deps {
  require(dep!=nil&&dep.Path!=""&&!seen[dep.Path],"build_info");seen[dep.Path]=true
  row:=moduleRow{dep.Path,dep.Version,dep.Sum,""}
  if dep.Replace!=nil {
   require(dep.Replace.Replace==nil&&(dep.Replace.Version==""||dep.Replace.Version=="(devel)")&&dep.Replace.Sum=="","build_info")
   row.Replacement=dep.Replace.Path
  }
  identity.Modules=append(identity.Modules,row)
 }
 sort.Slice(identity.Modules,func(i,j int) bool{return identity.Modules[i].Path<identity.Modules[j].Path})
 require(before==stamp(name,256*1024*1024),"file_changed")
 return identity
}
func inspectStripped(name string,bound fileStamp) *strippedEvidence {
 f,e:=elf.Open(name);require(e==nil,"stripped_elf");defer f.Close()
 require(f.Class==elf.ELFCLASS64&&f.Data==elf.ELFDATA2LSB&&f.Machine==elf.EM_X86_64&&f.Type==elf.ET_EXEC,"stripped_elf")
 symbolsAbsent:=f.Section(".symtab")==nil
 stringsAbsent:=f.Section(".strtab")==nil
 dwarfAbsent:=true
 for _,section:=range f.Sections {
  if strings.HasPrefix(section.Name,".debug_")||strings.HasPrefix(section.Name,".zdebug_"){dwarfAbsent=false}
 }
 pcln:=f.Section(".gopclntab");pclnPresent:=pcln!=nil&&pcln.Size>0&&pcln.Size<=128*1024*1024
 require(symbolsAbsent&&stringsAbsent&&dwarfAbsent&&pclnPresent,"stripped_elf")
 require(bound==stamp(name,256*1024*1024),"file_changed")
 return &strippedEvidence{"ELF64-little-x86_64",bound.SHA256,bound.Bytes,symbolsAbsent,stringsAbsent,dwarfAbsent,pclnPresent}
}
func inspectTool() toolIdentity {
 raw:=readFile(lockFile,65536);require(digest(raw)==lockSHA,"tool_lock")
 var lock struct {
  Schema int `json:"schema_version"`
  Tool struct {Module string `json:"module"`;Version string `json:"version"`;Origin string `json:"originCommit"`} `json:"tool"`
  Assets []struct {
   File string `json:"file"`;Module string `json:"module"`;Version string `json:"version"`
   Kind string `json:"kind"`;URL string `json:"url"`;Bytes int64 `json:"bytes"`
   SHA string `json:"sha256"`;H1 string `json:"h1"`
  } `json:"assets"`
 }
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
 require(dec.Decode(&lock)==nil&&lock.Schema==1&&len(lock.Assets)==34,"tool_lock")
 require(lock.Tool.Module=="golang.org/x/vuln"&&lock.Tool.Version==sourceVersion&&lock.Tool.Origin==sourceOrigin,"tool_lock")
 var trailing any;require(dec.Decode(&trailing)==io.EOF,"tool_lock")
 allowed:=map[string]moduleRow{}
 for _,a:=range lock.Assets {if a.Kind=="zip" {allowed[a.Module]=moduleRow{a.Module,a.Version,a.H1,""}}}
 binary:=inspectBinary(toolFile)
 require(binary.Path=="golang.org/x/vuln/cmd/govulncheck"&&binary.Main.Path=="golang.org/x/vuln"&&
  (binary.Main.Version=="(devel)"||binary.Main.Version=="")&&binary.Main.Sum=="","tool_identity")
 require(binary.File.Bytes>=1024*1024&&binary.File.Bytes<=64*1024*1024,"tool_identity")
 compiled:=map[string]bool{}
 for _,dep:=range binary.Modules {want,exists:=allowed[dep.Path];require(exists&&dep==want,"tool_dependencies");compiled[dep.Path]=true}
 require(compiled["golang.org/x/tools"]&&compiled["golang.org/x/mod"],"tool_dependencies")
 return toolIdentity{binary,sourceVersion,sourceOrigin,lockSHA}
}
type cappedWriter struct {data []byte;maximum int;overflow bool}
func (w *cappedWriter) Write(p []byte)(int,error){
 n:=len(p);room:=w.maximum-len(w.data)
 if n>room {w.data=append(w.data,p[:room]...);w.overflow=true} else {w.data=append(w.data,p...)}
 // Drain excess bytes while recording failure; the deadline still bounds a noisy child.
 return n,nil
}
func captureControls() int {
 count:=0
 for _,tc:=range []struct{maximum int;parts []string;want string;overflow bool}{
  {3,[]string{""},"",false},{3,[]string{"abc"},"abc",false},{3,[]string{"ab","c"},"abc",false},
  {3,[]string{"abcd"},"abc",true},{3,[]string{"ab","cd"},"abc",true},
  {3,[]string{"abc","def",""},"abc",true},{0,[]string{"x"},"",true},{0,[]string{""},"",false},
 } {
  w:=cappedWriter{data:[]byte{},maximum:tc.maximum}
  for _,p:=range tc.parts {n,e:=w.Write([]byte(p));require(n==len(p)&&e==nil,"capture_control")}
  require(string(w.data)==tc.want&&w.overflow==tc.overflow,"capture_control");count++
 }
 require(digest([]byte{})=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","capture_control");count++
 return count
}
func targetPath(mode,target string)(string,bool){
 if (mode=="extract"||mode=="scan")&&target=="upgraded" {return upgradedFile,true}
 if mode=="extract"&&(target=="original"||target=="patched"||target=="stripped"){return "/opt/probes/rclone-"+target,true}
 if mode=="scan"&&(target=="original"||target=="patched"){return "/opt/probes/rclone-"+target,true}
 if mode=="scan"&&(target=="positive"||target=="negative"||target=="fallback"){return "/opt/input/control-blobs/"+target+".blob",false}
 panic("arguments")
}
func run(r *result) {
 require(runtime.Version()=="go1.26.10"&&runtime.GOOS=="linux"&&runtime.GOARCH=="amd64","runtime")
 r.CaptureControls=captureControls()
 require(len(os.Args)==3,"arguments");r.Mode=os.Args[1];r.Target=os.Args[2]
 target,isBinary:=targetPath(r.Mode,r.Target)
 r.Tool=inspectTool()
 r.TargetBefore=stamp(target,256*1024*1024)
 if isBinary {
  identity:=inspectBinary(target);r.TargetIdentity=&identity
  require(identity.Path=="github.com/rclone/rclone"&&identity.Main.Path=="github.com/rclone/rclone"&&
   (identity.Main.Version=="(devel)"||identity.Main.Version=="")&&identity.Main.Sum=="","target_identity")
  if r.Target=="original" {
   require(identity.File==fileStamp{"37ef48307cbaae684126fe8e2f5d6ca3717fce679fd36c34fc4ba584295ea0d3",119830724},"target_identity")
  } else if r.Target=="patched" {
   require(identity.File==fileStamp{"8c72cfd7f7a8f0a7e62c7f527155e0e55bb391cf8bffdb1ada6009416d74e27b",119848207},"target_identity")
  } else if r.Target=="upgraded" {
   require(identity.File.Bytes>=1024*1024&&identity.File.Bytes<=256*1024*1024,"target_identity")
  } else {
   require(identity.File.Bytes>=1024*1024&&identity.File.Bytes<119830724,"target_identity")
   r.StrippedEvidence=inspectStripped(target,identity.File)
  }
 } else {require(r.TargetBefore.Bytes<16384,"control_identity")}
 require(os.Mkdir("/work/home",0700)==nil,"work_directory")
 args:=[]string{"-mode=extract",target}
 if r.Mode=="scan" {
  db:="file:///opt/input/advisories";if !isBinary {db="file:///opt/input/control-db"}
  args=[]string{"-mode=binary","-scan=symbol","-json","-db="+db,target}
 }
 ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second);defer cancel()
 cmd:=exec.CommandContext(ctx,toolFile,args...);cmd.WaitDelay=2*time.Second;cmd.Dir="/work"
 cmd.Env=[]string{"HOME=/work/home","PATH=/opt/go/bin:/usr/bin:/bin","GOROOT=/opt/go",
  "GOENV=off","GOTOOLCHAIN=local","GOWORK=off","GOTELEMETRY=off","GOPROXY=off","GOSUMDB=off",
  "GOMAXPROCS=2","GOMEMLIMIT=1GiB","LANG=C","LC_ALL=C"}
 out:=cappedWriter{data:[]byte{},maximum:stdoutLimit};errout:=cappedWriter{data:[]byte{},maximum:stderrLimit}
 cmd.Stdout=&out;cmd.Stderr=&errout
 err:=cmd.Run()
 r.ExitCode=-1;if cmd.ProcessState!=nil {r.ExitCode=cmd.ProcessState.ExitCode()}
 r.TimedOut=errors.Is(ctx.Err(),context.DeadlineExceeded)
 r.WaitDelayExceeded=errors.Is(err,exec.ErrWaitDelay)
 r.StdoutOverflow=out.overflow;r.StderrOverflow=errout.overflow
 r.Stdout=out.data;r.Stderr=errout.data;r.StdoutSHA256=digest(out.data);r.StderrSHA256=digest(errout.data)
 r.TargetAfter=stamp(target,256*1024*1024)
 r.TargetUnchanged=r.TargetBefore==r.TargetAfter
 after:=inspectTool();r.ToolUnchanged=reflect.DeepEqual(r.Tool,after)
 require(!r.TimedOut&&!r.WaitDelayExceeded,"scanner_deadline")
 require(!r.StdoutOverflow&&!r.StderrOverflow,"scanner_output")
 require(err==nil&&r.ExitCode==0&&len(r.Stderr)==0&&len(r.Stdout)>0,"scanner_process")
 require(r.TargetUnchanged&&r.ToolUnchanged,"file_changed")
 r.Success=true;r.Error="none"
}
func main(){
 if len(os.Args)==2&&os.Args[1]=="identity" {remediationIdentityMain();return}
 r:=result{Schema:1,Error:"unexpected",ExitCode:-1,Stdout:[]byte{},Stderr:[]byte{}}
 started:=time.Now()
 func(){
  defer func(){if e:=recover();e!=nil {
   if code,ok:=e.(string);ok {
    switch code {case "file_invalid","file_changed","build_info","build_settings","tool_lock","tool_identity","tool_dependencies",
     "capture_control","arguments","runtime","target_identity","control_identity","work_directory",
     "scanner_deadline","scanner_output","scanner_process","stripped_elf":r.Error=code}
   }
  }}()
  run(&r)
 }()
 r.DurationMillis=time.Since(started).Milliseconds()
 if json.NewEncoder(os.Stdout).Encode(r)!=nil {os.Exit(2)}
 if !r.Success {os.Exit(1)}
}
