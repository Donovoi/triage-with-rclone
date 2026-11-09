// Hosted-only upgraded module graph and binary identity reporter.
package main

import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "io"
 "os"
 "os/exec"
 "reflect"
 "runtime"
 "sort"
 "time"
)

const upgradedFile="/opt/probes/rclone-upgraded"
const graphFile="/opt/probes/upgraded-module-graph.json"
type graphModule struct {
 Path string `json:"path"`
 Version string `json:"version"`
 Sum string `json:"sum"`
 GoModSum string `json:"go_mod_sum"`
 Main bool `json:"main"`
 Indirect bool `json:"indirect"`
 GoVersion string `json:"go_version"`
 Replacement string `json:"replacement"`
}
// Fields are the public ModulePublic API in the pinned Go 1.26.10 source.
// No checksum is synthesized when the native resolver omits one.
type resolverModule struct {
 Path string
 Version string
 Query string
 Versions []string
 Replace *resolverModule
 Time *time.Time
 Update *resolverModule
 Main bool
 Indirect bool
 Dir string
 GoMod string
 GoVersion string
 Retracted []string
 Deprecated string
 Error json.RawMessage
 Sum string
 GoModSum string
 Origin json.RawMessage
 Reuse bool
}
type remediationIdentity struct {
 Schema int `json:"schema_version"`
 Success bool `json:"success"`
 Error string `json:"error"`
 Variant string `json:"variant"`
 Target string `json:"target"`
 Binary binaryIdentity `json:"binary"`
 Graph []graphModule `json:"graph"`
 SourceFiles map[string]fileStamp `json:"source_files"`
 GraphFile fileStamp `json:"graph_file"`
 VersionStdout string `json:"version_stdout"`
 VersionStderr string `json:"version_stderr"`
 VersionExitCode int `json:"version_exit_code"`
 VersionTimedOut bool `json:"version_timed_out"`
 VersionWaitDelayExceeded bool `json:"version_wait_delay_exceeded"`
 VersionStdoutOverflow bool `json:"version_stdout_overflow"`
 VersionStderrOverflow bool `json:"version_stderr_overflow"`
 TargetUnchanged bool `json:"target_unchanged"`
 SourcesUnchanged bool `json:"sources_unchanged"`
 GraphUnchanged bool `json:"graph_unchanged"`
 CaptureControls int `json:"capture_controls"`
 DurationMillis int64 `json:"duration_ms"`
 VulnerabilityAuditCompleted bool `json:"vulnerability_audit_completed"`
 ProviderAccepted bool `json:"provider_accepted"`
}
func remediationVariant() string {
 raw:=readFile("/opt/input/remediation-variant.txt",16)
 require(string(raw)=="original\n"||string(raw)=="patched\n","remediation_variant")
 return string(raw[:len(raw)-1])
}
func sourceStamps() map[string]fileStamp {
 stamps:=map[string]fileStamp{}
 for _,name:=range []string{"upgraded-rclone.mod","upgraded-rclone.sum","remediation-variant.txt"} {
  stamps[name]=stamp("/opt/input/"+name,131072)
 }
 return stamps
}
func validResolver(row resolverModule) {
 require(row.Path!=""&&len(row.Path)<=4096&&row.Query==""&&len(row.Versions)==0&&row.Update==nil&&
  len(row.Retracted)==0&&row.Deprecated==""&&!row.Reuse&&
  (len(row.Error)==0||string(row.Error)=="null"),"remediation_graph")
 for _,value:=range []string{row.Version,row.Sum,row.GoModSum,row.GoVersion,row.Dir,row.GoMod} {
  require(len(value)<=4096,"remediation_graph")
 }
}
func resolverGraph(raw []byte,variant string) []graphModule {
 require(len(raw)>0&&len(raw)<=4*1024*1024&&(variant=="original"||variant=="patched"),"remediation_graph")
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
 rows:=[]graphModule{};seen:=map[string]bool{};mains:=0;replacements:=0
 for {
  var m resolverModule
  err:=dec.Decode(&m);if err==io.EOF {break};require(err==nil,"remediation_graph")
  validResolver(m);require(!seen[m.Path]&&len(rows)<336,"remediation_graph");seen[m.Path]=true
  row:=graphModule{m.Path,m.Version,m.Sum,m.GoModSum,m.Main,m.Indirect,m.GoVersion,""}
  if m.Main {
   mains++
   require(m.Path=="github.com/rclone/rclone"&&m.Version==""&&m.Sum==""&&m.GoModSum==""&&
    !m.Indirect&&m.Replace==nil&&m.GoVersion=="1.26.0","remediation_graph")
  }
  if m.Replace!=nil {
   replacement:=m.Replace;validResolver(*replacement)
   require(variant=="patched"&&m.Path=="github.com/colinmarc/hdfs/v2"&&!m.Main&&
    m.Sum==""&&m.GoModSum==""&&replacement.Path=="/opt/input/patched-hdfs"&&
    replacement.Version==""&&replacement.Sum==""&&replacement.GoModSum==""&&
    replacement.Replace==nil&&!replacement.Main&&!replacement.Indirect&&
    replacement.Dir=="/opt/input/patched-hdfs"&&replacement.GoMod=="/opt/input/patched-hdfs/go.mod",
    "remediation_graph")
   row.Replacement=replacement.Path;replacements++
  }
  rows=append(rows,row)
 }
 wantReplacements:=0;if variant=="patched" {wantReplacements=1}
 require(len(rows)>=276&&mains==1&&replacements==wantReplacements,"remediation_graph")
 sort.Slice(rows,func(i,j int)bool{return rows[i].Path<rows[j].Path})
 return rows
}
func runRemediationIdentity(r *remediationIdentity) {
 require(runtime.Version()=="go1.26.10"&&runtime.GOOS=="linux"&&runtime.GOARCH=="amd64","runtime")
 r.CaptureControls=captureControls();r.Variant=remediationVariant();r.Target="upgraded"
 r.SourceFiles=sourceStamps();r.GraphFile=stamp(graphFile,4*1024*1024)
 raw:=readFile(graphFile,4*1024*1024)
 require(digest(raw)==r.GraphFile.SHA256&&int64(len(raw))==r.GraphFile.Bytes,"file_changed")
 r.Graph=resolverGraph(raw,r.Variant);r.Binary=inspectBinary(upgradedFile)
 require(r.Binary.Path=="github.com/rclone/rclone"&&r.Binary.Main.Path=="github.com/rclone/rclone"&&
  (r.Binary.Main.Version=="(devel)"||r.Binary.Main.Version=="")&&r.Binary.Main.Sum=="","target_identity")
 ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second);defer cancel()
 cmd:=exec.CommandContext(ctx,upgradedFile,"version");cmd.WaitDelay=2*time.Second;cmd.Dir="/work"
 cmd.Env=[]string{"HOME=/work/home","PATH=/usr/bin:/bin","GOENV=off","GOTOOLCHAIN=local","GOWORK=off",
  "GOTELEMETRY=off","GOPROXY=off","GOSUMDB=off","GOMAXPROCS=2","GOMEMLIMIT=512MiB","LANG=C","LC_ALL=C"}
 out:=cappedWriter{data:[]byte{},maximum:4096};errout:=cappedWriter{data:[]byte{},maximum:16384}
 cmd.Stdout=&out;cmd.Stderr=&errout;err:=cmd.Run()
 if cmd.ProcessState!=nil {r.VersionExitCode=cmd.ProcessState.ExitCode()}
 r.VersionTimedOut=errors.Is(ctx.Err(),context.DeadlineExceeded)
 r.VersionWaitDelayExceeded=errors.Is(err,exec.ErrWaitDelay)
 r.VersionStdoutOverflow=out.overflow;r.VersionStderrOverflow=errout.overflow
 r.VersionStdout=string(out.data);r.VersionStderr=string(errout.data)
 r.TargetUnchanged=reflect.DeepEqual(r.Binary,inspectBinary(upgradedFile))
 r.SourcesUnchanged=reflect.DeepEqual(r.SourceFiles,sourceStamps())
 r.GraphUnchanged=r.GraphFile==stamp(graphFile,4*1024*1024)
 require(!r.VersionTimedOut&&!r.VersionWaitDelayExceeded&&!r.VersionStdoutOverflow&&!r.VersionStderrOverflow&&
  err==nil&&r.VersionExitCode==0&&len(out.data)>0&&len(errout.data)==0,"remediation_version")
 require(r.TargetUnchanged&&r.SourcesUnchanged&&r.GraphUnchanged,"file_changed")
 r.Success=true;r.Error="none"
}
func remediationIdentityMain() {
 r:=remediationIdentity{Schema:1,Error:"unexpected",VersionExitCode:-1,Graph:[]graphModule{},SourceFiles:map[string]fileStamp{}}
 started:=time.Now()
 func(){defer func(){if e:=recover();e!=nil {if code,ok:=e.(string);ok {
  switch code {case "runtime","file_invalid","file_changed","build_info","build_settings","target_identity",
   "capture_control","remediation_variant","remediation_graph","remediation_version":r.Error=code}
 }}}();runRemediationIdentity(&r)}()
 r.DurationMillis=time.Since(started).Milliseconds()
 if json.NewEncoder(os.Stdout).Encode(r)!=nil {os.Exit(2)}
 if !r.Success {os.Exit(1)}
}
