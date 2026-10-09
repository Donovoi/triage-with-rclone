// Hosted Windows acceptance transport. Loading/compiling this file launches nothing.
// Native execution is reserved for the isolated hosted acceptance job.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace TriageApplicationLab {
    public sealed class HostedConPtySession : IDisposable {
        [StructLayout(LayoutKind.Sequential)] struct Coord { public short x,y; }
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Startup {
            public int cb; public string reserved,desktop,title;
            public int x,y,xSize,ySize,xCount,yCount,fill,flags;
            public short show,reserved2; public IntPtr reservedPtr,input,output,error;
        }
        [StructLayout(LayoutKind.Sequential)] struct StartupEx { public Startup startup; public IntPtr attributes; }
        [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr process,thread; public int pid,tid; }
        [StructLayout(LayoutKind.Sequential)] struct BasicLimit {
            public long processTime,jobTime; public uint flags; public UIntPtr min,max;
            public uint activeLimit; public UIntPtr affinity; public uint priority,scheduling;
        }
        [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong a,b,c,d,e,f; }
        [StructLayout(LayoutKind.Sequential)] struct ExtendedLimit {
            public BasicLimit basic; public IoCounters io; public UIntPtr a,b,c,d;
        }
        [StructLayout(LayoutKind.Sequential)] struct Accounting {
            public long a,b,c,d; public uint faults,total,active,terminated;
        }
        [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint low,high; }
        [StructLayout(LayoutKind.Sequential)] struct FileInfo {
            public uint attributes; public FileTime created,accessed,written;
            public uint volume,sizeHigh,sizeLow,links,indexHigh,indexLow;
        }
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool CreatePipe(out IntPtr read,out IntPtr write,IntPtr security,uint size);
        [DllImport("kernel32.dll")] static extern int CreatePseudoConsole(Coord size,IntPtr input,IntPtr output,uint flags,out IntPtr console);
        [DllImport("kernel32.dll")] static extern void ClosePseudoConsole(IntPtr console);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,uint flags,ref IntPtr size);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr previous,IntPtr returned);
        [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessW(string app,StringBuilder command,IntPtr a,IntPtr b,bool inherit,uint flags,IntPtr environment,string cwd,ref StartupEx startup,out ProcessInfo info);
        [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObjectW(IntPtr security,string name);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,ref ExtendedLimit info,uint size);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,out Accounting info,uint size,IntPtr returned);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,IntPtr info,uint size,out uint returned);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool belongs);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint exitCode);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint exitCode);
        [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageNameW(IntPtr process,uint flags,StringBuilder path,ref uint length);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out FileTime created,out FileTime exited,out FileTime kernel,out FileTime user);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
        [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr file,out FileInfo info);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandleW(IntPtr file,StringBuilder path,uint length,uint flags);

        sealed class Child { public IntPtr handle; public ulong created; public uint pid; }
        readonly object api=new object(), errorLock=new object();
        readonly List<string> errors=new List<string>();
        readonly List<Child> children=new List<Child>();
        readonly Stopwatch elapsed=Stopwatch.StartNew();
        IntPtr process,job,console;
        FileStream input,output,transcript;
        Thread reader,writer,closer;
        Timer watchdog;
        string caseRoot;
        int deadlineMs,maxOutput;
        long outputBytes;
        volatile bool closing,finished,limitExceeded,forced,ctrlSent,readerJoined,consoleClosed;
        bool appExited,childrenExited,jobZero,runtimeObserved;
        string runtimeSha;
        long? appExit;

        static void Require(bool value) { if(!value) throw new InvalidOperationException("invalid_request"); }
        static bool Sha(string value) {
            if(value==null || value.Length!=64) return false;
            foreach(char c in value) if(!((c>='0'&&c<='9')||(c>='a'&&c<='f'))) return false;
            return true;
        }
        static bool PlainText(string value,int maximum) {
            if(value==null || value.Length>maximum) return false;
            foreach(char c in value) if(char.IsControl(c) || char.IsSurrogate(c)) return false;
            return true;
        }
        static string FullPath(string value) {
            Require(PlainText(value,2048) && Path.IsPathRooted(value) && !value.StartsWith(@"\\") && value.Length>=3 && value[1]==':' && (value[2]=='\\'||value[2]=='/'));
            string full=Path.GetFullPath(value);
            Require(full.IndexOf(':',2)<0);
            return full.TrimEnd(Path.DirectorySeparatorChar);
        }
        static bool Inside(string root,string path) { return path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase); }
        static void PlainExisting(string path,bool directory) {
            Require(directory?Directory.Exists(path):File.Exists(path));
            for(string p=path; !String.IsNullOrEmpty(p); p=Path.GetDirectoryName(p))
                Require((File.GetAttributes(p)&FileAttributes.ReparsePoint)==0);
        }
        static void PrivateRoot(string path) {
            PlainExisting(path,true);
            var acl=Directory.GetAccessControl(path,AccessControlSections.Access|AccessControlSections.Owner);
            string sid=WindowsIdentity.GetCurrent().User.Value;
            Require(acl.AreAccessRulesProtected && acl.GetOwner(typeof(SecurityIdentifier)).Value==sid);
            bool user=false,system=false;
            foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier))) {
                string who=rule.IdentityReference.Value;
                Require(rule.AccessControlType==AccessControlType.Allow && (who==sid||who=="S-1-5-18"));
                Require((rule.FileSystemRights&FileSystemRights.FullControl)==FileSystemRights.FullControl);
                Require((rule.InheritanceFlags&(InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit))==(InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit));
                Require((rule.PropagationFlags&PropagationFlags.InheritOnly)==0);
                if(who==sid) user=true; else system=true;
            }
            Require(user && system);
        }
        static FileStream CreateTranscript(string path) {
            // Assign ownership in CREATE_NEW itself. Inherited permissions do
            // not override the process token's default owner on Windows.
            var sid=WindowsIdentity.GetCurrent().User;
            var acl=new FileSecurity(); acl.SetOwner(sid); acl.SetAccessRuleProtection(true,false);
            foreach(var principal in new SecurityIdentifier[]{sid,new SecurityIdentifier("S-1-5-18")})
                acl.AddAccessRule(new FileSystemAccessRule(principal,FileSystemRights.FullControl,AccessControlType.Allow));
            var stream=new FileStream(path,FileMode.CreateNew,FileSystemRights.Write|FileSystemRights.ReadPermissions,
                FileShare.Read,4096,FileOptions.None,acl);
            try {
                FileInfo info; Require(GetFileInformationByHandle(stream.SafeFileHandle.DangerousGetHandle(),out info));
                Require(info.links==1 && info.sizeHigh==0 && info.sizeLow==0 &&
                    (info.attributes&((uint)FileAttributes.ReparsePoint|(uint)FileAttributes.Directory))==0);
                var finalPath=new StringBuilder(4096);
                uint n=GetFinalPathNameByHandleW(stream.SafeFileHandle.DangerousGetHandle(),finalPath,4096,0);
                Require(n>0 && n<4096); string actual=finalPath.ToString();
                if(actual.StartsWith(@"\\?\")) actual=actual.Substring(4);
                Require(String.Equals(FullPath(actual),path,StringComparison.OrdinalIgnoreCase));
                var observed=stream.GetAccessControl();
                Require(observed.AreAccessRulesProtected && observed.GetOwner(typeof(SecurityIdentifier)).Value==sid.Value);
                bool user=false,system=false;
                foreach(FileSystemAccessRule rule in observed.GetAccessRules(true,true,typeof(SecurityIdentifier))) {
                    string who=rule.IdentityReference.Value;
                    Require(rule.AccessControlType==AccessControlType.Allow && (who==sid.Value||who=="S-1-5-18"));
                    Require((rule.FileSystemRights&FileSystemRights.FullControl)==FileSystemRights.FullControl &&
                        rule.InheritanceFlags==InheritanceFlags.None && rule.PropagationFlags==PropagationFlags.None);
                    if(who==sid.Value) user=true; else system=true;
                }
                Require(user && system);
                return stream;
            } catch { stream.Dispose(); throw; }
        }
        public static string Quote(string value) {
            Require(PlainText(value,4096));
            var result=new StringBuilder("\""); int slashes=0;
            foreach(char c in value) {
                if(c=='\\') { slashes++; continue; }
                if(c=='\"') result.Append('\\',slashes*2+1).Append(c);
                else result.Append('\\',slashes).Append(c);
                slashes=0;
            }
            return result.Append('\\',slashes*2).Append('"').ToString();
        }
        public static string BuildEnvironment(string root,IDictionary<string,string> environment) {
            root=FullPath(root); Require(environment!=null && environment.Count<=13);
            var map=new SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase);
            string windows=Environment.GetFolderPath(Environment.SpecialFolder.Windows), system=Environment.SystemDirectory;
            var privateNames=new HashSet<string>(new string[]{"TEMP","TMP","HOME","USERPROFILE","APPDATA","LOCALAPPDATA"},StringComparer.OrdinalIgnoreCase);
            foreach(var item in environment) {
                Require(PlainText(item.Key,32) && PlainText(item.Value,4096) && !map.ContainsKey(item.Key));
                string key=item.Key.ToUpperInvariant(), value=item.Value;
                if(privateNames.Contains(key)) { string path=FullPath(value); Require(Inside(root,path)); PlainExisting(path,true); }
                else if(key=="SYSTEMROOT" || key=="WINDIR") Require(String.Equals(FullPath(value),windows,StringComparison.OrdinalIgnoreCase));
                else if(key=="SYSTEMDRIVE") Require(String.Equals(value,Path.GetPathRoot(windows).TrimEnd('\\'),StringComparison.OrdinalIgnoreCase));
                else if(key=="COMSPEC") Require(String.Equals(FullPath(value),Path.Combine(system,"cmd.exe"),StringComparison.OrdinalIgnoreCase));
                else if(key=="PATH") Require(String.Equals(value,system,StringComparison.OrdinalIgnoreCase) || String.Equals(value,system+";"+windows,StringComparison.OrdinalIgnoreCase));
                else throw new InvalidOperationException("invalid_request");
                map.Add(key,value);
            }
            Require(map.ContainsKey("SYSTEMROOT") && map.ContainsKey("PATH"));
            foreach(string key in privateNames) Require(map.ContainsKey(key));
            var block=new StringBuilder(); foreach(var item in map) block.Append(item.Key).Append('=').Append(item.Value).Append('\0');
            return block.Append('\0').ToString();
        }
        void Error(string code) { lock(errorLock) { if(!errors.Contains(code) && errors.Count<24) errors.Add(code); } }
        bool Deadline { get { return elapsed.ElapsedMilliseconds>=deadlineMs; } }
        static string Image(IntPtr handle) { var value=new StringBuilder(4096); uint n=4096; if(!QueryFullProcessImageNameW(handle,0,value,ref n)) throw new Win32Exception(); return FullPath(value.ToString()); }
        static ulong Created(IntPtr handle) { FileTime a,b,c,d; if(!GetProcessTimes(handle,out a,out b,out c,out d)) throw new Win32Exception(); return ((ulong)a.high<<32)|a.low; }
        static bool Exited(IntPtr handle) { uint value=WaitForSingleObject(handle,0); if(value==0xffffffff) throw new Win32Exception(); return value==0; }
        static string HashFile(string path,Func<bool> expired) {
            PlainExisting(path,false);
            using(var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read|FileShare.Delete))
            using(var hash=SHA256.Create()) {
                Require(stream.Length>0 && stream.Length<=268435456);
                FileInfo info; Require(GetFileInformationByHandle(stream.SafeFileHandle.DangerousGetHandle(),out info));
                Require(info.links==1 && (info.attributes&((uint)FileAttributes.ReparsePoint|(uint)FileAttributes.Directory))==0);
                var finalPath=new StringBuilder(4096); uint n=GetFinalPathNameByHandleW(stream.SafeFileHandle.DangerousGetHandle(),finalPath,4096,0);
                Require(n>0 && n<4096); string actual=finalPath.ToString();
                if(actual.StartsWith(@"\\?\")) actual=actual.Substring(4);
                Require(String.Equals(FullPath(actual),path,StringComparison.OrdinalIgnoreCase));
                byte[] data=new byte[65536]; int count;
                while((count=stream.Read(data,0,data.Length))>0) { Require(!expired()); hash.TransformBlock(data,0,count,data,0); }
                hash.TransformFinalBlock(data,0,0);
                return BitConverter.ToString(hash.Hash).Replace("-","").ToLowerInvariant();
            }
        }
        public static HostedConPtySession Start(string appPath,string appSha256,string[] arguments,string root,IDictionary<string,string> environment,string transcriptPath,int maxOutputBytes,int deadlineMilliseconds) {
            Require(Sha(appSha256) && arguments!=null && arguments.Length<=64 && maxOutputBytes>=1024 && maxOutputBytes<=8388608 && deadlineMilliseconds>=1000 && deadlineMilliseconds<=180000);
            root=FullPath(root); PrivateRoot(root); appPath=FullPath(appPath); PlainExisting(appPath,false);
            transcriptPath=FullPath(transcriptPath); Require(Inside(root,transcriptPath) && !File.Exists(transcriptPath) && !Directory.Exists(transcriptPath));
            PlainExisting(Path.GetDirectoryName(transcriptPath),true);
            string block=BuildEnvironment(root,environment);
            var command=new StringBuilder(Quote(appPath)); foreach(string argument in arguments) command.Append(' ').Append(Quote(argument));
            Require(command.Length<=16384);
            var s=new HostedConPtySession {caseRoot=root,maxOutput=maxOutputBytes,deadlineMs=deadlineMilliseconds};
            IntPtr inRead=IntPtr.Zero,inWrite=IntPtr.Zero,outRead=IntPtr.Zero,outWrite=IntPtr.Zero,attrs=IntPtr.Zero,env=IntPtr.Zero;
            ProcessInfo pi=new ProcessInfo(); bool initialized=false;
            FileStream appLock=null;
            try {
                // Retain a non-delete/non-write sharing lock from hash verification
                // through creation of the suspended image and its identity check.
                appLock=new FileStream(appPath,FileMode.Open,FileAccess.Read,FileShare.Read);
                Require(HashFile(appPath,delegate { return s.Deadline; })==appSha256);
                s.job=CreateJobObjectW(IntPtr.Zero,null); Require(s.job!=IntPtr.Zero);
                var limits=new ExtendedLimit(); limits.basic.flags=0x2000;
                Require(SetInformationJobObject(s.job,9,ref limits,(uint)Marshal.SizeOf(typeof(ExtendedLimit))));
                Require(CreatePipe(out inRead,out inWrite,IntPtr.Zero,0) && CreatePipe(out outRead,out outWrite,IntPtr.Zero,0));
                Require(CreatePseudoConsole(new Coord {x=120,y=34},inRead,outWrite,0,out s.console)==0);
                s.input=new FileStream(new SafeFileHandle(inWrite,true),FileAccess.Write,4096,false); inWrite=IntPtr.Zero;
                s.output=new FileStream(new SafeFileHandle(outRead,true),FileAccess.Read,4096,false); outRead=IntPtr.Zero;
                s.transcript=CreateTranscript(transcriptPath);
                s.reader=new Thread(s.ReadLoop); s.reader.IsBackground=true; s.reader.Start();
                IntPtr size=IntPtr.Zero; InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref size); Require(size!=IntPtr.Zero);
                attrs=Marshal.AllocHGlobal(size); Require(InitializeProcThreadAttributeList(attrs,1,0,ref size)); initialized=true;
                Require(UpdateProcThreadAttribute(attrs,0,new IntPtr(0x00020016),s.console,new IntPtr(IntPtr.Size),IntPtr.Zero,IntPtr.Zero));
                var startup=new StartupEx(); startup.startup.cb=Marshal.SizeOf(typeof(StartupEx)); startup.startup.flags=0x100; startup.attributes=attrs;
                env=Marshal.StringToHGlobalUni(block);
                // EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED.
                Require(CreateProcessW(appPath,command,IntPtr.Zero,IntPtr.Zero,false,0x80404,env,root,ref startup,out pi));
                s.process=pi.process;
                if(!AssignProcessToJobObject(s.job,s.process)) {
                    s.forced=true; s.Error("job_assignment_failed");
                    if(!TerminateProcess(s.process,99)) s.Error("termination_failed");
                    throw new InvalidOperationException("start_failed");
                }
                Require(String.Equals(Image(s.process),appPath,StringComparison.OrdinalIgnoreCase));
                Require(!s.Deadline && ResumeThread(pi.thread)!=0xffffffff);
                s.watchdog=new Timer(delegate { if(s.Deadline && !s.finished) { s.Error("deadline_exceeded"); s.Finish(0); } },null,100,100);
                return s;
            } catch {
                s.Error("start_failed");
                // Release parent copies before waiting for ConPTY/reader EOF.
                if(inRead!=IntPtr.Zero) { CloseHandle(inRead); inRead=IntPtr.Zero; }
                if(outWrite!=IntPtr.Zero) { CloseHandle(outWrite); outWrite=IntPtr.Zero; }
                s.Finish(0); return s;
            }
            finally {
                if(appLock!=null) appLock.Dispose();
                if(pi.thread!=IntPtr.Zero) CloseHandle(pi.thread);
                if(initialized) DeleteProcThreadAttributeList(attrs); if(attrs!=IntPtr.Zero) Marshal.FreeHGlobal(attrs);
                if(env!=IntPtr.Zero) Marshal.FreeHGlobal(env);
                foreach(IntPtr handle in new IntPtr[]{inRead,inWrite,outRead,outWrite}) if(handle!=IntPtr.Zero) CloseHandle(handle);
            }
        }
        void ReadLoop() {
            try {
                byte[] data=new byte[8192]; int count;
                while((count=output.Read(data,0,data.Length))>0) {
                    long total=Interlocked.Add(ref outputBytes,count);
                    if(total>maxOutput) {
                        if(!limitExceeded) { limitExceeded=true; Error("output_limit_exceeded"); ThreadPool.QueueUserWorkItem(delegate { Finish(0); }); }
                        continue; // Keep draining without writing bytes beyond the cap.
                    }
                    transcript.Write(data,0,count);
                }
            } catch(IOException e) { if(!closing || ((e.HResult&65535)!=109 && (e.HResult&65535)!=232 && (e.HResult&65535)!=233)) Error("reader_failed"); }
            catch(ObjectDisposedException) { if(!closing) Error("reader_failed"); }
            catch { Error("reader_failed"); }
        }
        bool RefreshJob() {
            if(job==IntPtr.Zero) return jobZero;
            Accounting value;
            if(!QueryInformationJobObject(job,1,out value,(uint)Marshal.SizeOf(typeof(Accounting)),IntPtr.Zero)) { Error("job_query_failed"); return false; }
            jobZero=value.active==0;
            return jobZero;
        }
        void ObserveChildren() {
            if(job==IntPtr.Zero) return;
            const int maximum=64; int bytes=8+maximum*IntPtr.Size; IntPtr buffer=Marshal.AllocHGlobal(bytes);
            try {
                uint returned;
                if(!QueryInformationJobObject(job,3,buffer,(uint)bytes,out returned)) throw new Win32Exception();
                int assigned=Marshal.ReadInt32(buffer), count=Marshal.ReadInt32(buffer,4);
                Require(count>=0 && count<=maximum && assigned<=maximum && assigned==count);
                for(int i=0;i<count;i++) {
                    long number=Marshal.ReadIntPtr(buffer,8+i*IntPtr.Size).ToInt64(); Require(number>0 && number<=UInt32.MaxValue);
                    uint pid=(uint)number; bool already=false;
                    foreach(Child old in children) if(old.pid==pid && !Exited(old.handle)) { already=true; break; }
                    if(already) continue;
                    IntPtr handle=OpenProcess(0x00101000,false,pid);
                    if(handle==IntPtr.Zero) { if(Marshal.GetLastWin32Error()==87) continue; throw new Win32Exception(); }
                    try {
                        bool belongs; Require(IsProcessInJob(handle,job,out belongs));
                        if(!belongs && Exited(handle)) continue;
                        Require(belongs);
                        if(children.Count>=128) throw new InvalidOperationException();
                        children.Add(new Child {handle=handle,pid=pid,created=Created(handle)}); handle=IntPtr.Zero;
                    } finally { if(handle!=IntPtr.Zero) CloseHandle(handle); }
                }
            } finally { Marshal.FreeHGlobal(buffer); }
        }
        public Dictionary<string,object> Poll() {
            lock(api) {
                if(!finished) {
                    try { ObserveChildren(); RefreshJob(); if(process!=IntPtr.Zero && Exited(process)) { appExited=true; uint code; Require(GetExitCodeProcess(process,out code)); appExit=code; } }
                    catch { Error("process_observation_failed"); return Finish(0); }
                    if(Deadline) { Error("deadline_exceeded"); return Finish(0); }
                }
                return Snapshot();
            }
        }
        public Dictionary<string,object> ObserveOwnedRuntime(string extractionRoot,string expectedSha256) {
            lock(api) {
                try {
                    Require(!closing && !finished && !Deadline && Sha(expectedSha256));
                    string root=FullPath(extractionRoot); Require(Inside(caseRoot,root)); PlainExisting(root,true);
                    Require(process!=IntPtr.Zero && !Exited(process)); ObserveChildren();
                    int matches=0;
                    foreach(Child child in children) {
                        if(Exited(child.handle)) continue;
                        string path=Image(child.handle);
                        if(!Inside(root,path)) continue;
                        Require(Path.GetFileName(path).Equals("rclone.exe",StringComparison.OrdinalIgnoreCase));
                        bool belongs; Require(IsProcessInJob(child.handle,job,out belongs) && belongs && Created(child.handle)==child.created);
                        string sha=HashFile(path,delegate { return Deadline; });
                        Require(sha==expectedSha256 && !Exited(child.handle) && Created(child.handle)==child.created);
                        matches++;
                    }
                    Require(matches==1); runtimeObserved=true; runtimeSha=expectedSha256;
                } catch { Error("runtime_observation_failed"); return Finish(0); }
                return Snapshot();
            }
        }
        public Dictionary<string,object> SendCtrlCOnce() {
            lock(api) {
                if(closing || finished || ctrlSent || !runtimeObserved || Deadline || process==IntPtr.Zero || Exited(process)) { Error("ctrl_c_refused"); return Finish(0); }
                bool wrote=false;
                writer=new Thread(delegate() { try { input.WriteByte(3); input.Flush(); wrote=true; } catch { Error("input_failed"); } }); writer.IsBackground=true; writer.Start();
                if(!writer.Join(1000)) { Error("input_timeout"); return Finish(0); }
                ctrlSent=wrote;
                return Snapshot();
            }
        }
        public Dictionary<string,object> Abort() { Error("protocol_invalid"); return Finish(0); }
        public Dictionary<string,object> Finish(int graceMilliseconds) {
            lock(api) {
                if(finished) return Snapshot();
                if(graceMilliseconds<0 || graceMilliseconds>15000) { Error("protocol_invalid"); graceMilliseconds=0; }
                if(Deadline) Error("deadline_exceeded");
                closing=true;
                if(watchdog!=null) watchdog.Dispose();
                long end=Math.Min((long)deadlineMs,elapsed.ElapsedMilliseconds+graceMilliseconds);
                try {
                    while(elapsed.ElapsedMilliseconds<end) {
                        ObserveChildren(); if(process!=IntPtr.Zero && Exited(process) && RefreshJob()) break;
                        Thread.Sleep(25);
                    }
                    if(Deadline) Error("deadline_exceeded");
                    if(process!=IntPtr.Zero && (!Exited(process)||!RefreshJob())) {
                        forced=true; Error("forced_termination");
                        if(job==IntPtr.Zero || !TerminateJobObject(job,99)) Error("termination_failed");
                    }
                } catch { Error("process_observation_failed"); forced=true; if(job==IntPtr.Zero || !TerminateJobObject(job,99)) Error("termination_failed"); }
                long reapEnd=elapsed.ElapsedMilliseconds+5000;
                try {
                    do { appExited=process==IntPtr.Zero||Exited(process); if(appExited && RefreshJob()) break; Thread.Sleep(25); } while(elapsed.ElapsedMilliseconds<reapEnd);
                    childrenExited=true; foreach(Child child in children) if(!Exited(child.handle)) childrenExited=false;
                    if(!appExited || !childrenExited || !jobZero) Error("process_cleanup_failed");
                    if(process!=IntPtr.Zero && appExited) { uint code; Require(GetExitCodeProcess(process,out code)); appExit=code; }
                } catch { Error("process_cleanup_failed"); }
                if(job!=IntPtr.Zero) { if(!jobZero) forced=true; CloseHandle(job); job=IntPtr.Zero; }
                closer=new Thread(delegate() {
                    try {
                        if(console!=IntPtr.Zero) { ClosePseudoConsole(console); console=IntPtr.Zero; }
                        consoleClosed=true;
                        if(input!=null) input.Dispose();
                        if(writer!=null && !writer.Join(1000)) Error("input_cleanup_failed");
                        readerJoined=reader==null||reader.Join(2000);
                        if(!readerJoined) { Error("reader_cleanup_failed"); if(output!=null) output.Dispose(); readerJoined=reader.Join(1000); }
                        if(output!=null) output.Dispose(); if(transcript!=null) transcript.Dispose();
                    } catch { Error("console_cleanup_failed"); }
                }); closer.IsBackground=true; closer.Start();
                if(!closer.Join(10000)) Error("console_cleanup_timeout");
                foreach(Child child in children) CloseHandle(child.handle);
                if(process!=IntPtr.Zero) { CloseHandle(process); process=IntPtr.Zero; }
                finished=true; return Snapshot();
            }
        }
        public Dictionary<string,object> Snapshot() {
            string[] current; lock(errorLock) current=errors.ToArray();
            return new Dictionary<string,object> {
                {"schema_version",1},{"ok",current.Length==0},{"state",finished?"finished":"running"},
                {"app_exit_code",appExit},{"runtime_image_observed",runtimeObserved},{"runtime_sha256",runtimeSha},
                {"ctrl_c_sent",ctrlSent},{"output_bytes",Interlocked.Read(ref outputBytes)}, {"output_limit_exceeded",limitExceeded},
                {"forced_termination",forced},{"app_exited",appExited},{"observed_children_exited",childrenExited},
                {"job_zero_confirmed",jobZero},{"reader_joined",readerJoined},{"conpty_closed",consoleClosed},{"errors",current}
            };
        }
        public void Dispose() { Finish(0); }
    }

    // Small closed JSON reader: no duplicate keys, floats, nonfinite values,
    // lone surrogates, unbounded lines, or permissive PowerShell JSON coercion.
    public static class HostedProtocol {
        sealed class Parser {
            readonly string text; int offset;
            public Parser(string value) { text=value; }
            void Need(bool value) { if(!value) throw new FormatException("protocol_invalid"); }
            void Space() { while(offset<text.Length && (text[offset]==' '||text[offset]=='\t'||text[offset]=='\r')) offset++; }
            string String() {
                Need(offset<text.Length && text[offset++]=='"'); var value=new StringBuilder();
                while(offset<text.Length) {
                    char c=text[offset++]; if(c=='"') return value.ToString();
                    Need(c>=32 && !char.IsSurrogate(c));
                    if(c=='\\') {
                        Need(offset<text.Length); c=text[offset++];
                        if(c=='"'||c=='\\'||c=='/') value.Append(c);
                        else if(c=='u') { Need(offset+4<=text.Length); int code; Need(Int32.TryParse(text.Substring(offset,4),System.Globalization.NumberStyles.HexNumber,System.Globalization.CultureInfo.InvariantCulture,out code)); offset+=4; Need(code>=32 && !(code>=0xd800&&code<=0xdfff)); value.Append((char)code); }
                        else throw new FormatException("protocol_invalid");
                    } else value.Append(c);
                }
                throw new FormatException("protocol_invalid");
            }
            object Value(int depth) {
                Need(depth<=4); Space(); Need(offset<text.Length); char c=text[offset];
                if(c=='"') return String();
                if(c=='{') {
                    offset++; Space(); var result=new Dictionary<string,object>(StringComparer.OrdinalIgnoreCase);
                    if(offset<text.Length && text[offset]=='}') {offset++;return result;}
                    while(true) { Space(); string key=String(); Need(!result.ContainsKey(key)&&result.Count<64); Space(); Need(offset<text.Length&&text[offset++]==':'); result.Add(key,Value(depth+1)); Space(); Need(offset<text.Length); c=text[offset++]; if(c=='}') return result; Need(c==','); }
                }
                if(c=='[') {
                    offset++; Space(); var result=new List<object>();
                    if(offset<text.Length && text[offset]==']') {offset++;return result.ToArray();}
                    while(true) { Need(result.Count<64); result.Add(Value(depth+1)); Space(); Need(offset<text.Length); c=text[offset++]; if(c==']') return result.ToArray(); Need(c==','); }
                }
                int start=offset; if(c=='-') offset++;
                while(offset<text.Length && text[offset]>='0'&&text[offset]<='9') offset++;
                string number=text.Substring(start,offset-start); long parsed=0;
                Need(number.Length>0 && number.Length<=10 && !(number.Length>1&&number[0]=='0') && !(number.Length>2&&number[0]=='-'&&number[1]=='0') && Int64.TryParse(number,out parsed));
                return parsed;
            }
            public Dictionary<string,object> Parse() { object value=Value(0); Space(); Need(offset==text.Length && value is Dictionary<string,object>); return (Dictionary<string,object>)value; }
        }
        public static Dictionary<string,object> Parse(string value) { if(value==null||value.Length>65536) throw new FormatException("protocol_invalid"); return new Parser(value).Parse(); }
        public static Dictionary<string,object> Read(TextReader reader) {
            var line=new StringBuilder(); int c;
            while((c=reader.Read())!=-1) { if(c==10) return Parse(line.ToString()); if(line.Length>=65536) throw new FormatException("protocol_invalid"); line.Append((char)c); }
            if(line.Length!=0) throw new FormatException("protocol_invalid"); return null;
        }
        public static void Keys(Dictionary<string,object> value,string names) {
            string[] keys=names.Split(','); if(value.Count!=keys.Length) throw new FormatException("protocol_invalid");
            foreach(string key in keys) if(!value.ContainsKey(key)) throw new FormatException("protocol_invalid");
            // Canonical key spellings are required even though duplicates compare case-insensitively.
            foreach(string key in value.Keys) if(Array.IndexOf(keys,key)<0) throw new FormatException("protocol_invalid");
        }
        public static string Text(Dictionary<string,object> value,string key) { if(!(value[key] is string)) throw new FormatException("protocol_invalid"); return (string)value[key]; }
        public static int Integer(Dictionary<string,object> value,string key) { if(!(value[key] is long) || (long)value[key]<0 || (long)value[key]>Int32.MaxValue) throw new FormatException("protocol_invalid"); return (int)(long)value[key]; }
        public static string[] Arguments(Dictionary<string,object> value) { var array=value["args"] as object[]; if(array==null) throw new FormatException("protocol_invalid"); var result=new string[array.Length]; for(int i=0;i<array.Length;i++) { if(!(array[i] is string)) throw new FormatException("protocol_invalid"); result[i]=(string)array[i]; } return result; }
        public static Dictionary<string,string> EnvironmentMap(Dictionary<string,object> value) { var map=value["environment"] as Dictionary<string,object>; if(map==null) throw new FormatException("protocol_invalid"); var result=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase); foreach(var item in map) { if(!(item.Value is string)) throw new FormatException("protocol_invalid"); result.Add(item.Key,(string)item.Value); } return result; }
        public static Dictionary<string,object> Failure() {
            return new Dictionary<string,object> {{"schema_version",1},{"ok",false},{"state","finished"},{"app_exit_code",null},
                {"runtime_image_observed",false},{"runtime_sha256",null},{"ctrl_c_sent",false},{"output_bytes",0L},
                {"output_limit_exceeded",false},{"forced_termination",false},{"app_exited",false},{"observed_children_exited",false},
                {"job_zero_confirmed",false},{"reader_joined",false},{"conpty_closed",false},{"errors",new string[]{"protocol_invalid"}}};
        }
    }
}
