// Hosted offline build helper. Errors remain fatal and raw messages never escape.
package main
import (
 "bytes"
 "encoding/json"
 "fmt"
 "io"
 "os"
 "sort"
 "strings"
)
var diagnosticPhase="coordinate_read"
var graphBytes,graphModules,errorModules,coordinateCount int
func emitState(){
 fmt.Println("GO_REMEDIATION_DIAGNOSTIC_STAGE="+diagnosticPhase)
 fmt.Printf("GO_REMEDIATION_GRAPH_BYTES=%d\nGO_REMEDIATION_GRAPH_MODULES=%d\nGO_REMEDIATION_ERROR_MODULES=%d\nGO_REMEDIATION_COORDINATES=%d\n",graphBytes,graphModules,errorModules,coordinateCount)
}
type coordinate struct {Module string `json:"module"`;Version string `json:"version"`}
type module struct {Path string;Version string;Error json.RawMessage;Replace *module}
func need(ok bool){if !ok {panic("invalid")}}
func read(name string,maximum int64)[]byte {
 before,e:=os.Lstat(name);need(e==nil&&before.Mode().IsRegular()&&before.Size()>0&&before.Size()<=maximum)
 f,e:=os.Open(name);need(e==nil);defer f.Close();opened,e:=f.Stat();need(e==nil&&os.SameFile(before,opened))
 raw,e:=io.ReadAll(io.LimitReader(f,maximum+1));need(e==nil&&int64(len(raw))==before.Size())
 after,e:=f.Stat();end,ee:=os.Lstat(name)
 need(e==nil&&ee==nil&&os.SameFile(before,after)&&os.SameFile(before,end)&&before.Size()==after.Size()&&
  before.Size()==end.Size()&&before.ModTime()==after.ModTime()&&before.ModTime()==end.ModTime());return raw
}
func kind(raw json.RawMessage)string {
 if len(raw)==0||string(raw)=="null" {return ""}
 var value struct{Err string};decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.DisallowUnknownFields()
 need(decoder.Decode(&value)==nil&&value.Err!=""&&len(value.Err)<=8192)
 var tail any;need(decoder.Decode(&tail)==io.EOF)
 if strings.Contains(value.Err,"module lookup disabled by GOPROXY=off"){return "lookup_disabled"}
 if strings.Contains(value.Err,"missing go.sum entry"){return "sum_missing"}
 return "unclassified"
}
func run()bool {
 raw:=read("/opt/input/remediation-coordinate-pins.json",2*1024*1024)
 diagnosticPhase="coordinate_parse"
 var coordinates []coordinate;decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.DisallowUnknownFields()
 need(decoder.Decode(&coordinates)==nil&&len(coordinates)>0&&len(coordinates)<=20000)
 var tail any;need(decoder.Decode(&tail)==io.EOF);coordinateCount=len(coordinates);allowed:=map[coordinate]bool{}
 for _,c:=range coordinates {need(c.Module!=""&&c.Version!=""&&len(c.Module)<=4096&&len(c.Version)<=256&&!allowed[c]);allowed[c]=true}
 diagnosticPhase="graph_read"
 graph:=read("/opt/probes/upgraded-module-graph.json",4*1024*1024);graphBytes=len(graph);diagnosticPhase="graph_parse"
 decoder=json.NewDecoder(bytes.NewReader(graph));failures:=map[string]bool{};seen:=map[string]bool{};count:=0
 for {var row module;err:=decoder.Decode(&row);if err==io.EOF{break};need(err==nil&&row.Path!=""&&len(row.Path)<=4096&&len(row.Version)<=256&&!seen[row.Path]);seen[row.Path]=true
  count++;need(count<=2048);graphModules=count;diagnosticPhase="graph_error_parse";reason:=kind(row.Error)
  if row.Replace!=nil {need(row.Replace.Replace==nil);replacementReason:=kind(row.Replace.Error);if reason==""{reason=replacementReason}}
  if reason!="" {
   errorModules++
   if allowed[coordinate{row.Path,row.Version}] {failures[row.Path+"@"+row.Version+":"+reason]=true} else {failures["unbound"]=true}
  }
  diagnosticPhase="graph_parse"
 }
 need(count>0);diagnosticPhase="graph_summary";ordered:=[]string{};for failure:=range failures{ordered=append(ordered,failure)};sort.Strings(ordered)
 for i,failure:=range ordered{if i>=32{break};fmt.Println("GO_REMEDIATION_MODULE_ERROR="+failure)}
 if len(ordered)>32 {fmt.Println("GO_REMEDIATION_GRAPH_STATUS=errors_truncated");return false}
 if len(ordered)>0 {fmt.Println("GO_REMEDIATION_GRAPH_STATUS=errors");return false}
 fmt.Println("GO_REMEDIATION_GRAPH_STATUS=complete");return true
}
func main(){success:=false;func(){defer func(){if recover()!=nil{fmt.Println("GO_REMEDIATION_GRAPH_STATUS=invalid")}}();success=run()}();emitState();if !success{os.Exit(1)}}
