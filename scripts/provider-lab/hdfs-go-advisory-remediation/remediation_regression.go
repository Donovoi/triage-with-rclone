// Benign fixtures run only inside the owned, network-none hosted container.
package main
import (
 "archive/tar"
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "io"
 "net"
 "net/http"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "sync/atomic"
 "time"
 "github.com/andybalholm/brotli"
)
type fileStamp struct {SHA256 string `json:"sha256"`;Bytes int64 `json:"bytes"`}
type childResult struct {
 Case string `json:"case"`
 ExitCode int `json:"exit_code"`
 TimedOut bool `json:"timed_out"`
 WaitDelayExceeded bool `json:"wait_delay_exceeded"`
 StdoutOverflow bool `json:"stdout_overflow"`
 StderrOverflow bool `json:"stderr_overflow"`
 Stdout fileStamp `json:"stdout"`
 Stderr fileStamp `json:"stderr"`
 DurationMillis int64 `json:"duration_ms"`
}
type regressionResult struct {
 Schema int `json:"schema_version"`
 Success bool `json:"success"`
 Error string `json:"error"`
 Variant string `json:"variant"`
 TargetBefore fileStamp `json:"target_before"`
 TargetAfter fileStamp `json:"target_after"`
 TargetUnchanged bool `json:"target_unchanged"`
 Payload fileStamp `json:"payload"`
 BrotliArchive fileStamp `json:"brotli_archive"`
 ZstdObject fileStamp `json:"zstd_object"`
 ContextBinary *fileStamp `json:"context_binary"`
 ContextTests int `json:"context_tests"`
 HTTPRequests int64 `json:"http_requests"`
 ServerJoined bool `json:"server_joined"`
 Controls []string `json:"controls"`
 Children []childResult `json:"children"`
 DurationMillis int64 `json:"duration_ms"`
 VulnerabilityAuditCompleted bool `json:"vulnerability_audit_completed"`
 ProviderAccepted bool `json:"provider_accepted"`
}
const target="/opt/probes/rclone-upgraded"
var contextNames=[]string{"TestContextAdmissionCancellationPreservesOwner","TestContextPrecancelledRequestHasNoEffects",
 "TestContextExpiredDeadlineHasNoEffects","TestContextHeldResponseFinishesBeforeRelease","TestContextBlockedWriteFinishes",
 "TestContextDialReceivesCancellation","TestContextHandshakeReceivesCancellation","TestContextCompletedRequestCannotCloseNextOperation",
 "TestContextStartedCallbackIsJoinedBeforeReturn","TestContextNonCancellationErrorIsPreserved","TestContextCancelledStreamRequiresFreshDial"}
func need(ok bool,code string){if !ok {panic(code)}}
func digest(raw []byte)fileStamp {h:=sha256.Sum256(raw);return fileStamp{hex.EncodeToString(h[:]),int64(len(raw))}}
func stamp(name string,maximum int64)fileStamp {
 before,e:=os.Lstat(name);need(e==nil&&before.Mode().IsRegular()&&before.Size()>0&&before.Size()<=maximum,"file_invalid")
 f,e:=os.Open(name);need(e==nil,"file_invalid");defer f.Close();opened,e:=f.Stat()
 need(e==nil&&os.SameFile(before,opened),"file_changed");h:=sha256.New();n,e:=io.Copy(h,io.LimitReader(f,maximum+1))
 need(e==nil&&n==before.Size(),"file_invalid");after,e:=f.Stat();end,ee:=os.Lstat(name)
 need(e==nil&&ee==nil&&os.SameFile(before,after)&&os.SameFile(before,end)&&after.Size()==before.Size()&&end.Size()==before.Size()&&
  before.ModTime()==after.ModTime()&&before.ModTime()==end.ModTime(),"file_changed")
 return fileStamp{hex.EncodeToString(h.Sum(nil)),n}
}
func write(name string,raw []byte){f,e:=os.OpenFile(name,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);need(e==nil,"fixture_write")
 n,e:=f.Write(raw);closed:=f.Close();need(e==nil&&closed==nil&&n==len(raw),"fixture_write")}
func read(name string,maximum int64)[]byte {before:=stamp(name,maximum);f,e:=os.Open(name);need(e==nil,"file_invalid")
 raw,e:=io.ReadAll(io.LimitReader(f,maximum+1));closed:=f.Close();need(e==nil&&closed==nil&&digest(raw)==before&&stamp(name,maximum)==before,"file_changed");return raw}
type cappedWriter struct{data []byte;maximum int;overflow bool}
func(w *cappedWriter)Write(p []byte)(int,error){n:=len(p);room:=w.maximum-len(w.data)
 if n>room {w.data=append(w.data,p[:room]...);w.overflow=true}else{w.data=append(w.data,p...)};return n,nil}
func child(r *regressionResult,name,program string,args ...string)[]byte {
 started:=time.Now();ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second);defer cancel()
 cmd:=exec.CommandContext(ctx,program,args...);cmd.WaitDelay=2*time.Second;cmd.Dir="/work"
 cmd.Env=[]string{"HOME=/work/home","PATH=/usr/bin:/bin","TMPDIR=/work/temp","GOENV=off","GOWORK=off","GOTOOLCHAIN=local",
  "GOTELEMETRY=off","GOPROXY=off","GOSUMDB=off","GOMAXPROCS=2","GOMEMLIMIT=512MiB","LANG=C","LC_ALL=C"}
 out:=cappedWriter{maximum:131072};errout:=cappedWriter{maximum:16384};cmd.Stdout=&out;cmd.Stderr=&errout;err:=cmd.Run()
 result:=childResult{Case:name,ExitCode:-1,TimedOut:errors.Is(ctx.Err(),context.DeadlineExceeded),WaitDelayExceeded:errors.Is(err,exec.ErrWaitDelay),
  StdoutOverflow:out.overflow,StderrOverflow:errout.overflow,Stdout:digest(out.data),Stderr:digest(errout.data),DurationMillis:time.Since(started).Milliseconds()}
 if cmd.ProcessState!=nil {result.ExitCode=cmd.ProcessState.ExitCode()};r.Children=append(r.Children,result)
 need(!result.TimedOut&&!result.WaitDelayExceeded&&!result.StdoutOverflow&&!result.StderrOverflow&&err==nil&&result.ExitCode==0&&len(errout.data)==0,"child_failed")
 return out.data
}
func rclone(r *regressionResult,name string,args ...string)[]byte {
 flags:=[]string{"--config","/work/empty.conf","--cache-dir","/work/cache","--temp-dir","/work/temp",
  "--retries","1","--low-level-retries","1","--timeout","5s","--contimeout","2s","--stats","0","--log-level","ERROR"}
 return child(r,name,target,append(flags,args...)...)
}
func httpControl(r *regressionResult,payload []byte) {
 listener,e:=net.Listen("tcp4","127.0.0.1:0");need(e==nil,"http_fixture")
 var requests atomic.Int64
 server:=&http.Server{ReadHeaderTimeout:2*time.Second,ReadTimeout:2*time.Second,WriteTimeout:2*time.Second,IdleTimeout:2*time.Second,MaxHeaderBytes:4096}
 server.Handler=http.HandlerFunc(func(w http.ResponseWriter,q *http.Request){
  if requests.Add(1)>16 {http.Error(w,"limit",429);return}
  if q.Method!="GET"&&q.Method!="HEAD" {http.Error(w,"method",405);return}
  switch q.URL.Path {case "/":w.Header().Set("Content-Type","text/html; charset=utf-8");_,_=io.WriteString(w,"<!doctype html><html><body>benign <b>listing</b><a href=\"fixture.txt\">fixture</a></body></html>")
   case "/fixture.txt":w.Header().Set("Content-Type","text/plain");_,_=w.Write(payload)
   default:http.NotFound(w,q)}
 })
 done:=make(chan error,1);go func(){done<-server.Serve(listener)}()
 defer func(){closeErr:=server.Close();select{case serveErr:=<-done:r.ServerJoined=closeErr==nil&&errors.Is(serveErr,http.ErrServerClosed)
  case <-time.After(2*time.Second):r.ServerJoined=false};r.HTTPRequests=requests.Load();need(r.ServerJoined,"http_cleanup")}()
 out:=rclone(r,"http_directory","lsf",":http:","--http-url","http://"+listener.Addr().String()+"/","--http-no-head")
 need(string(out)=="fixture.txt\n"&&requests.Load()>=1,"http_fixture");r.Controls=append(r.Controls,"http_directory_parse")
}
func brotliControl(r *regressionResult,payload []byte) {
 var packed bytes.Buffer
 writer:=brotli.NewWriterLevel(&packed,4);archive:=tar.NewWriter(writer)
 need(archive.WriteHeader(&tar.Header{Name:"fixture.txt",Mode:0600,Size:int64(len(payload)),ModTime:time.Unix(1000,0)})==nil,"brotli_fixture")
 n,e:=archive.Write(payload);need(e==nil&&n==len(payload)&&archive.Close()==nil&&writer.Close()==nil,"brotli_fixture")
 need(packed.Len()>0&&packed.Len()<=131072,"brotli_fixture");write("/work/fixture.tar.br",packed.Bytes());r.BrotliArchive=digest(packed.Bytes())
 out:=rclone(r,"brotli_archive","archive","extract","/work/fixture.tar.br","/work/extracted")
 need(len(out)==0&&bytes.Equal(read("/work/extracted/fixture.txt",131072),payload),"brotli_fixture")
 entries,e:=os.ReadDir("/work/extracted");need(e==nil&&len(entries)==1&&entries[0].Name()=="fixture.txt"&&!entries[0].IsDir(),"brotli_fixture")
 r.Controls=append(r.Controls,"brotli_archive_extract")
}
func zstdControl(r *regressionResult,payload []byte) {
 write("/work/plain.txt",payload)
 flags:=[]string{"--compress-remote","/work/store","--compress-mode","zstd","--compress-level","2"}
 out:=rclone(r,"zstd_write",append([]string{"copyto","/work/plain.txt",":compress:fixture.txt"},flags...)...);need(len(out)==0,"zstd_fixture")
 out=rclone(r,"zstd_read",append([]string{"cat",":compress:fixture.txt"},flags...)...);need(bytes.Equal(out,payload),"zstd_fixture")
 count:=0;compressed:=0;total:=int64(0)
 err:=filepath.WalkDir("/work/store",func(name string,entry os.DirEntry,err error)error{
  need(err==nil&&entry.Type()&os.ModeSymlink==0,"zstd_fixture");count++;need(count<=8,"zstd_fixture")
  if !entry.IsDir(){s:=stamp(name,1024*1024);total+=s.Bytes;need(total<=1024*1024,"zstd_fixture")
   if strings.HasSuffix(name,".zst"){compressed++;r.ZstdObject=s;need(s.Bytes<int64(len(payload)),"zstd_fixture")}}
  return nil
 });need(err==nil&&compressed==1,"zstd_fixture");r.Controls=append(r.Controls,"zstd_object_roundtrip")
}
func contextControl(r *regressionResult) {
 binary:="/opt/probes/upgraded-context-tests";before:=stamp(binary,128*1024*1024);r.ContextBinary=&before
 out:=child(r,"upgraded_hdfs_context",binary,"-test.v","-test.timeout=8s","-test.run","^("+strings.Join(contextNames,"|")+")$")
 runs:=map[string]int{};passes:=map[string]int{}
 for _,line:=range strings.Split(string(out),"\n"){
  if strings.HasPrefix(line,"=== RUN   "){runs[strings.TrimPrefix(line,"=== RUN   ")]++}
  if strings.HasPrefix(line,"--- PASS: "){fields:=strings.Fields(line);need(len(fields)==4,"context_fixture");passes[fields[2]]++}
  need(!strings.HasPrefix(line,"--- FAIL:")&&!strings.HasPrefix(line,"--- SKIP:"),"context_fixture")
 }
 need(len(runs)==11&&len(passes)==11&&strings.HasSuffix(string(out),"PASS\n")&&before==stamp(binary,128*1024*1024),"context_fixture")
 for _,name:=range contextNames{need(runs[name]==1&&passes[name]==1,"context_fixture")}
 r.ContextTests=11;r.Controls=append(r.Controls,"upgraded_hdfs_context")
}
func run(r *regressionResult) {
 variant:=string(read("/opt/input/remediation-variant.txt",16));need(variant=="original\n"||variant=="patched\n","variant")
 r.Variant=strings.TrimSuffix(variant,"\n");r.TargetBefore=stamp(target,256*1024*1024)
 for _,dir:=range []string{"/work/home","/work/cache","/work/temp","/work/store"}{need(os.Mkdir(dir,0700)==nil,"fixture_write")}
 write("/work/empty.conf",[]byte{})
 payload:=bytes.Repeat([]byte("benign dependency compatibility fixture 0123456789\n"),1024);r.Payload=digest(payload)
 httpControl(r,payload);brotliControl(r,payload);zstdControl(r,payload)
 if r.Variant=="patched"{contextControl(r)}
 r.TargetAfter=stamp(target,256*1024*1024);r.TargetUnchanged=r.TargetBefore==r.TargetAfter;need(r.TargetUnchanged,"file_changed")
 r.Success=true;r.Error="none"
}
func main(){
 r:=regressionResult{Schema:1,Error:"unexpected",Controls:[]string{},Children:[]childResult{}};start:=time.Now()
 func(){defer func(){if e:=recover();e!=nil {if code,ok:=e.(string);ok{switch code{
  case "file_invalid","file_changed","fixture_write","child_failed","http_fixture","http_cleanup","brotli_fixture","zstd_fixture","context_fixture","variant":r.Error=code}}}}();run(&r)}()
 r.DurationMillis=time.Since(start).Milliseconds();if json.NewEncoder(os.Stdout).Encode(r)!=nil{os.Exit(2)};if !r.Success{os.Exit(1)}
}
