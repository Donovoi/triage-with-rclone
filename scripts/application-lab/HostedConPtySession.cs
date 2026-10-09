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
        [DllImport("kernel32.dll")] static extern int ResizePseudoConsole(IntPtr console,Coord size);
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
        Thread reader,writer,closer,resizer;
        LaunchObserver launch;
        Timer watchdog;
        string caseRoot;
        HostedSourceDirectory sourceDirectory;
        int deadlineMs,maxOutput,maxRuntimeProcesses;
        int? runtimeProcessCount;
        long outputBytes;
        volatile bool closing,finished,limitExceeded,forced,ctrlSent,readerJoined,consoleClosed;
        bool appExited,childrenExited,jobZero,runtimeObserved;
        string runtimeSha;
        long? appExit;
        bool tui;
        readonly HostedTuiInputBudget tuiBudget=new HostedTuiInputBudget();
        int columns=120,rows=34;

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
        public static bool RuntimeCountAllowed(int maximum,int count) { return maximum>=1 && maximum<=4 && count>=1 && count<=maximum; }
        public static bool SameRuntimeImage(string first,string next) { return !String.IsNullOrEmpty(next) && (first==null || String.Equals(first,next,StringComparison.OrdinalIgnoreCase)); }
        public static HostedConPtySession Start(string appPath,string appSha256,string[] arguments,string root,IDictionary<string,string> environment,string transcriptPath,int maxOutputBytes,int deadlineMilliseconds,int maxRuntimeProcesses) {
            return StartCore(appPath,appSha256,arguments,root,environment,transcriptPath,maxOutputBytes,deadlineMilliseconds,maxRuntimeProcesses,false,false);
        }
        public static HostedConPtySession StartSource(string appPath,string appSha256,string[] arguments,string root,IDictionary<string,string> environment,string transcriptPath,int maxOutputBytes,int deadlineMilliseconds,int maxRuntimeProcesses) {
            return StartCore(appPath,appSha256,arguments,root,environment,transcriptPath,maxOutputBytes,deadlineMilliseconds,maxRuntimeProcesses,false,true);
        }
        public static HostedConPtySession StartTui(string appPath,string appSha256,string[] arguments,string root,IDictionary<string,string> environment,string transcriptPath,int maxOutputBytes,int deadlineMilliseconds,int maxRuntimeProcesses) {
            return StartCore(appPath,appSha256,arguments,root,environment,transcriptPath,maxOutputBytes,deadlineMilliseconds,maxRuntimeProcesses,true,false);
        }
        public static HostedConPtySession StartSourceObserved(string appPath,string appSha256,string[] arguments,string root,IDictionary<string,string> environment,string transcriptPath,int maxOutputBytes,int deadlineMilliseconds,int maxRuntimeProcesses,string expectedRuntimeSha256,int maxRuntimeLaunches) {
            Require(Sha(expectedRuntimeSha256) && maxRuntimeLaunches>=1 && maxRuntimeLaunches<=32);
            return StartCore(appPath,appSha256,arguments,root,environment,transcriptPath,maxOutputBytes,deadlineMilliseconds,maxRuntimeProcesses,false,true,expectedRuntimeSha256,maxRuntimeLaunches);
        }
        static HostedConPtySession StartCore(string appPath,string appSha256,string[] arguments,string root,IDictionary<string,string> environment,string transcriptPath,int maxOutputBytes,int deadlineMilliseconds,int maxRuntimeProcesses,bool tui,bool sourceCwd,string launchSha=null,int maxLaunches=0) {
            Require(Sha(appSha256) && arguments!=null && arguments.Length<=64 && maxOutputBytes>=1024 && maxOutputBytes<=8388608 && deadlineMilliseconds>=1000 && deadlineMilliseconds<=180000 && RuntimeCountAllowed(maxRuntimeProcesses,1));
            if(sourceCwd) HostedSourceDirectory.SourcePath(root);
            root=FullPath(root); PrivateRoot(root); appPath=FullPath(appPath); PlainExisting(appPath,false);
            transcriptPath=FullPath(transcriptPath); Require(Inside(root,transcriptPath) && !File.Exists(transcriptPath) && !Directory.Exists(transcriptPath));
            PlainExisting(Path.GetDirectoryName(transcriptPath),true);
            string block=BuildEnvironment(root,environment);
            var command=new StringBuilder(Quote(appPath)); foreach(string argument in arguments) command.Append(' ').Append(Quote(argument));
            Require(command.Length<=16384);
            var s=new HostedConPtySession {caseRoot=root,maxOutput=maxOutputBytes,deadlineMs=deadlineMilliseconds,maxRuntimeProcesses=maxRuntimeProcesses,tui=tui};
            if(launchSha!=null) {
                Require(sourceCwd && !tui);
                s.launch=new LaunchObserver(s,appPath,appSha256,launchSha,maxRuntimeProcesses,maxLaunches);
                s.launch.Start(delegate { s.StartNative(appPath,appSha256,command,block,transcriptPath,sourceCwd); });
                if(!s.launch.WaitStarted(Math.Min(20000,deadlineMilliseconds))) { s.Error("debug_start_failed"); s.Finish(0); }
            } else s.StartNative(appPath,appSha256,command,block,transcriptPath,sourceCwd);
            return s;
        }
        void StartNative(string appPath,string appSha256,StringBuilder command,string block,string transcriptPath,bool sourceCwd) {
            var s=this; string root=caseRoot;
            IntPtr inRead=IntPtr.Zero,inWrite=IntPtr.Zero,outRead=IntPtr.Zero,outWrite=IntPtr.Zero,attrs=IntPtr.Zero,env=IntPtr.Zero;
            ProcessInfo pi=new ProcessInfo(); bool initialized=false;
            FileStream appLock=null;
            try {
                if(s.launch!=null) s.launch.CheckStarting();
                if(sourceCwd) s.sourceDirectory=HostedSourceDirectory.Acquire(root);
                if(s.launch!=null) s.launch.AcquireTemp();
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
                if(s.sourceDirectory!=null) s.sourceDirectory.Verify();
                if(s.launch!=null) s.launch.CheckStarting();
                // EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED.
                Require(CreateProcessW(appPath,command,IntPtr.Zero,IntPtr.Zero,false,s.launch==null?0x80404u:0x80405u,env,s.sourceDirectory==null?root:s.sourceDirectory.Path,ref startup,out pi));
                if(s.launch==null) s.process=pi.process;
                else s.process=s.launch.CaptureCreation(pi);
                if(!AssignProcessToJobObject(s.job,s.process)) {
                    s.forced=true; s.Error("job_assignment_failed");
                    if(!TerminateProcess(s.process,99)) s.Error("termination_failed");
                    throw new InvalidOperationException("start_failed");
                }
                if(s.launch!=null) s.launch.Assigned();
                Require(String.Equals(Image(s.process),appPath,StringComparison.OrdinalIgnoreCase));
                if(s.sourceDirectory!=null) s.sourceDirectory.Verify();
                if(s.launch!=null) s.launch.VerifyTemp();
                if(s.launch!=null) s.launch.CheckStarting();
                Require(!s.Deadline && ResumeThread(pi.thread)!=0xffffffff);
                // The debug creator/pump enforces the same session deadline.
                // Do not create a late timer after Finish has stopped startup.
                if(s.launch==null) s.watchdog=new Timer(delegate { if(s.Deadline && !s.finished) { s.Error("deadline_exceeded"); s.Finish(0); } },null,100,100);
                return;
            } catch(Exception e) {
                if(s.launch!=null) s.launch.SourceFailure(e);
                else foreach(string code in HostedSourceDirectory.FailureCodes(e)) s.Error(code);
                s.Error("start_failed");
                // Release parent copies before waiting for ConPTY/reader EOF.
                if(inRead!=IntPtr.Zero) { CloseHandle(inRead); inRead=IntPtr.Zero; }
                if(outWrite!=IntPtr.Zero) { CloseHandle(outWrite); outWrite=IntPtr.Zero; }
                if(s.launch==null) s.Finish(0); else s.launch.StartFailed();
                return;
            }
            finally {
                if(appLock!=null) appLock.Dispose();
                if(s.launch==null && pi.thread!=IntPtr.Zero) CloseHandle(pi.thread);
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
                    // Only this reader owns the transcript writer. Short TUI
                    // prompts must be visible without waiting for its buffer.
                    if(tui) transcript.Flush();
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
                runtimeProcessCount=null;
                try {
                    Require(launch==null && !closing && !finished && !Deadline && Sha(expectedSha256));
                    string root=FullPath(extractionRoot); Require(Inside(caseRoot,root)); PlainExisting(root,true);
                    Require(process!=IntPtr.Zero && !Exited(process)); ObserveChildren();
                    int matches=0; string runtimePath=null;
                    foreach(Child child in children) {
                        if(Exited(child.handle)) continue;
                        string path=Image(child.handle);
                        if(!Inside(root,path)) continue;
                        Require(Path.GetFileName(path).Equals("rclone.exe",StringComparison.OrdinalIgnoreCase));
                        Require(SameRuntimeImage(runtimePath,path)); runtimePath=path;
                        bool belongs; Require(IsProcessInJob(child.handle,job,out belongs) && belongs && Created(child.handle)==child.created);
                        string sha=HashFile(path,delegate { return Deadline; });
                        Require(sha==expectedSha256 && !Exited(child.handle) && Created(child.handle)==child.created);
                        matches++;
                    }
                    // The first HTTP request is held, but other acquisition workers
                    // may already be live. Every observed instance must be verified.
                    runtimeProcessCount=matches;
                    Require(RuntimeCountAllowed(maxRuntimeProcesses,matches)); runtimeObserved=true; runtimeSha=expectedSha256;
                } catch { Error("runtime_observation_failed"); return Finish(0); }
                return Snapshot();
            }
        }
        public Dictionary<string,object> SendCtrlCOnce() {
            lock(api) {
                if(launch!=null || closing || finished || ctrlSent || !runtimeObserved || Deadline || process==IntPtr.Zero || Exited(process)) { Error("ctrl_c_refused"); return Finish(0); }
                bool wrote=false;
                writer=new Thread(delegate() { try { input.WriteByte(3); input.Flush(); wrote=true; } catch { Error("input_failed"); } }); writer.IsBackground=true; writer.Start();
                if(!writer.Join(1000)) { Error("input_timeout"); return Finish(0); }
                ctrlSent=wrote;
                return Snapshot();
            }
        }
        void RequireTuiLive() {
            Require(tui && !closing && !finished && !ctrlSent && !Deadline && process!=IntPtr.Zero && console!=IntPtr.Zero && job!=IntPtr.Zero);
            lock(errorLock) Require(errors.Count==0);
            bool belongs; Require(!Exited(process) && IsProcessInJob(process,job,out belongs) && belongs);
            ObserveChildren();
        }
        Dictionary<string,object> TuiFailure(string code) {
            Error(code); Finish(0); return TuiSnapshot();
        }
        int TuiWaitBudget() { return (int)Math.Max(0,Math.Min(1000,(long)deadlineMs-elapsed.ElapsedMilliseconds)); }
        Dictionary<string,object> SendTuiInput(byte[] bytes) {
            RequireTuiLive(); tuiBudget.ReserveInput(bytes.Length);
            Require(writer==null || !writer.IsAlive);
            bool wrote=false;
            writer=new Thread(delegate() {
                try { input.Write(bytes,0,bytes.Length); input.Flush(); wrote=true; }
                catch { Error("input_failed"); }
            });
            writer.IsBackground=true;
            try { writer.Start(); } catch { writer=null; throw; }
            if(!writer.Join(TuiWaitBudget())) return TuiFailure("input_timeout");
            if(Deadline) return TuiFailure("deadline_exceeded");
            if(!wrote) return TuiFailure("input_failed");
            return TuiSnapshot();
        }
        public Dictionary<string,object> SendTuiKey(string key) {
            lock(api) {
                try { return SendTuiInput(HostedTuiProtocol.KeyBytes(key)); }
                catch { return TuiFailure("tui_input_refused"); }
            }
        }
        public Dictionary<string,object> SendTuiText(string text) {
            lock(api) {
                try { return SendTuiInput(HostedTuiProtocol.TextBytes(text)); }
                catch { return TuiFailure("tui_input_refused"); }
            }
        }
        public Dictionary<string,object> ResizeTui(int width,int height) {
            lock(api) {
                try {
                    RequireTuiLive(); tuiBudget.ReserveResize(width,height);
                    Require(resizer==null || !resizer.IsAlive);
                    bool resized=false;
                    resizer=new Thread(delegate() {
                        try { resized=ResizePseudoConsole(console,new Coord {x=(short)width,y=(short)height})==0; }
                        catch { Error("resize_failed"); }
                    });
                    resizer.IsBackground=true;
                    try { resizer.Start(); } catch { resizer=null; throw; }
                    if(!resizer.Join(TuiWaitBudget())) return TuiFailure("resize_timeout");
                    if(Deadline) return TuiFailure("deadline_exceeded");
                    if(!resized) return TuiFailure("resize_failed");
                    columns=width; rows=height; return TuiSnapshot();
                } catch { return TuiFailure("tui_resize_refused"); }
            }
        }
        public Dictionary<string,object> Abort() { Error("protocol_invalid"); return Finish(0); }
        public Dictionary<string,object> Finish(int graceMilliseconds) {
            lock(api) {
                if(finished) return Snapshot();
                if(graceMilliseconds<0 || graceMilliseconds>15000) { Error("protocol_invalid"); graceMilliseconds=0; }
                if(Deadline) Error("deadline_exceeded");
                closing=true;
                bool noProcess=process==IntPtr.Zero;
                if(watchdog!=null) watchdog.Dispose();
                if(launch!=null) {
                    // The creator must continue EXIT events before process waits
                    // and before any common handle/lease can be closed. It never
                    // acquires api, including on errors or during this join.
                    if(!launch.JoinForFinish(graceMilliseconds)) {
                        Error("debug_cleanup_failed"); finished=true; return Snapshot();
                    }
                    launch.CheckQualification(); noProcess=process==IntPtr.Zero;
                }
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
                if(job!=IntPtr.Zero) { if(!jobZero) forced=true; if(!CloseHandle(job) && launch!=null) launch.CommonCloseFailed(); job=IntPtr.Zero; }
                closer=new Thread(delegate() {
                    try {
                        // Never close a ConPTY handle still in a resize call.
                        // Uncertain completion retains its handles/transcript.
                        if(resizer!=null && !resizer.Join(1000)) { Error("resize_cleanup_failed"); return; }
                        if(console!=IntPtr.Zero) { ClosePseudoConsole(console); console=IntPtr.Zero; }
                        consoleClosed=true;
                        if(input!=null) input.Dispose();
                        if(writer!=null && !writer.Join(1000)) Error("input_cleanup_failed");
                        readerJoined=reader==null||reader.Join(2000);
                        if(!readerJoined) { Error("reader_cleanup_failed"); if(output!=null) output.Dispose(); readerJoined=reader.Join(1000); }
                        if(output!=null) output.Dispose(); if(transcript!=null) transcript.Dispose();
                    } catch { Error("console_cleanup_failed"); }
                }); closer.IsBackground=true; closer.Start();
                bool closerJoined=closer.Join(10000);
                if(!closerJoined) Error("console_cleanup_timeout");
                foreach(Child child in children) if(!CloseHandle(child.handle) && launch!=null) launch.CommonCloseFailed();
                if(process!=IntPtr.Zero) { if(!CloseHandle(process) && launch!=null) launch.CommonCloseFailed(); process=IntPtr.Zero; }
                bool quiet=(noProcess || (appExited && childrenExited && jobZero)) &&
                    closerJoined && consoleClosed && readerJoined &&
                    (writer==null || !writer.IsAlive) && (resizer==null || !resizer.IsAlive);
                if(launch!=null) { if(quiet) launch.CloseTemp(); else Error("debug_cleanup_failed"); quiet=quiet && launch.Released; }
                if(sourceDirectory!=null) {
                    // A failed launch may own pins before it owns a process/job.
                    // Uncertain process or reader/console lifetime retains the pins.
                    if(quiet) {
                        try { sourceDirectory.Verify(); } catch(Exception e) {
                            foreach(string code in HostedSourceDirectory.FailureCodes(e)) Error(code);
                            Error("source_directory_invalid");
                        }
                        try { sourceDirectory.Dispose(); sourceDirectory=null; } catch { Error("source_directory_cleanup_failed"); }
                    } else Error("source_directory_cleanup_failed");
                }
                finished=true; return Snapshot();
            }
        }
        public Dictionary<string,object> Snapshot() {
            string[] current; lock(errorLock) current=errors.ToArray();
            return new Dictionary<string,object> {
                {"schema_version",1},{"ok",current.Length==0},{"state",finished?"finished":"running"},
                {"app_exit_code",appExit},{"runtime_image_observed",runtimeObserved},{"runtime_sha256",runtimeSha},{"runtime_process_count",runtimeProcessCount},
                {"ctrl_c_sent",ctrlSent},{"output_bytes",Interlocked.Read(ref outputBytes)}, {"output_limit_exceeded",limitExceeded},
                {"forced_termination",forced},{"app_exited",appExited},{"observed_children_exited",childrenExited},
                {"job_zero_confirmed",jobZero},{"reader_joined",readerJoined},{"conpty_closed",consoleClosed},{"errors",current}
            };
        }
        public Dictionary<string,object> TuiSnapshot() {
            lock(api) {
                var result=Snapshot(); result["schema_version"]=2;
                result.Add("input_commands",tuiBudget.InputCommands); result.Add("input_bytes",tuiBudget.InputBytes);
                result.Add("resize_count",tuiBudget.ResizeCount); result.Add("columns",columns); result.Add("rows",rows);
                return result;
            }
        }
        public Dictionary<string,object> LaunchSnapshot() {
            lock(api) {
                Require(launch!=null);
                var result=Snapshot(); result["schema_version"]=3;
                launch.AddSnapshot(result); return result;
            }
        }
        public Dictionary<string,object> LaunchFailureDiagnostic() {
            lock(api) { Require(launch!=null); return launch.FailureDiagnostic(); }
        }
        // DEBUG_PROCESS is opt-in. All debug APIs run on the creator thread.
        // That thread never takes api or calls Finish: Finish may be joining it.
        sealed class LaunchObserver {
            [StructLayout(LayoutKind.Sequential)] internal struct ExceptionRecord {
                public uint code,flags; public IntPtr record,address; public uint count;
                public UIntPtr p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14;
            }
            [StructLayout(LayoutKind.Sequential)] internal struct ExceptionInfo { public ExceptionRecord record; public uint first; }
            [StructLayout(LayoutKind.Sequential)] internal struct CreateInfo {
                public IntPtr file,process,thread,baseAddress; public uint offset,size;
                public IntPtr local,start,name; public ushort unicode;
            }
            [StructLayout(LayoutKind.Sequential)] internal struct LoadInfo {
                public IntPtr file,baseAddress; public uint offset,size; public IntPtr name; public ushort unicode;
            }
            [StructLayout(LayoutKind.Explicit)] internal struct EventInfo {
                [FieldOffset(0)] public ExceptionInfo exception;
                [FieldOffset(0)] public CreateInfo create;
                [FieldOffset(0)] public LoadInfo load;
                [FieldOffset(0)] public uint exit;
            }
            [StructLayout(LayoutKind.Sequential)] internal struct DebugEvent { public uint code,pid,tid; public EventInfo info; }
            [DllImport("kernel32.dll",SetLastError=true)] static extern bool WaitForDebugEvent(out DebugEvent value,uint milliseconds);
            [DllImport("kernel32.dll",SetLastError=true)] static extern bool ContinueDebugEvent(uint pid,uint tid,uint status);
            [DllImport("kernel32.dll",SetLastError=true)] static extern bool DuplicateHandle(IntPtr sourceProcess,IntPtr source,IntPtr targetProcess,out IntPtr target,uint access,bool inherit,uint options);
            [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFileW(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
            sealed class OwnedProcess { public IntPtr handle; public ulong created; }
            readonly HostedConPtySession session;
            readonly string appPath,appSha,expected;
            readonly string systemDirectory=Environment.SystemDirectory;
            readonly object sync=new object();
            readonly HostedLaunchState state;
            readonly Dictionary<uint,OwnedProcess> processes=new Dictionary<uint,OwnedProcess>();
            readonly List<IntPtr> uncertainHandles=new List<IntPtr>();
            Dictionary<string,object> failedCreate;
            readonly object startSignal=new object();
            bool startSignaled;
            Thread pump;
            HostedSourceDirectory temp,imageParent,systemParent;
            IntPtr systemFile;
            FileInfo systemInfo;
            string systemPath,systemSha;
            bool systemClosed;
            IntPtr initialProcess,initialThread;
            uint initialPid,initialTid;
            bool assigned,creationSeen,terminationRequested,tempClosed;
            volatile bool startupFailed,startOkay,joined,handlesFailed;
            long finishAt=Int64.MaxValue;
            public LaunchObserver(HostedConPtySession s,string path,string appHash,string hash,int concurrent,int launches) {
                session=s; appPath=path; appSha=appHash; expected=hash;
                state=new HostedLaunchState(concurrent,launches);
            }
            public static Dictionary<string,int> Layout() {
                return new Dictionary<string,int> {
                    {"pointer",IntPtr.Size},{"event_size",Marshal.SizeOf(typeof(DebugEvent))},
                    {"union_offset",Marshal.OffsetOf(typeof(DebugEvent),"info").ToInt32()},
                    {"create_size",Marshal.SizeOf(typeof(CreateInfo))},
                    {"create_process_offset",Marshal.OffsetOf(typeof(CreateInfo),"process").ToInt32()},
                    {"create_thread_offset",Marshal.OffsetOf(typeof(CreateInfo),"thread").ToInt32()},
                    {"exception_first_offset",Marshal.OffsetOf(typeof(ExceptionInfo),"first").ToInt32()}
                };
            }
            void Fail(string code) { lock(sync) state.Fail(code); session.Error(code); }
            public void CheckStarting() { lock(sync) state.CheckStarting(session.closing || session.finished,session.Deadline); }
            public void SourceFailure(Exception error) {
                string[] codes;
                lock(sync) { codes=state.ObserveSourceFailure(error); if(state.CleanupUncertain) handlesFailed=true; }
                foreach(string code in codes) session.Error(code);
                if(handlesFailed) session.Error("debug_cleanup_failed");
            }
            public void AcquireTemp() {
                temp=HostedSourceDirectory.AcquireRuntimeTemp(session.caseRoot); temp.Verify();
                CheckStarting();
                // An installed-object reference, not a signer/publisher proof.
                // This fixed system file may legitimately have multiple links.
                systemPath=FullPath(Path.Combine(systemDirectory,"conhost.exe"));
                systemParent=HostedSourceDirectory.AcquireInstalledImageParent(systemPath);
                CheckStarting();
                // Noninheritable OPEN_EXISTING; real read access and READ-only
                // sharing prevent replacement/writes while the reference lives.
                // learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilew
                systemFile=CreateFileW(systemPath,0x80000000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
                Require(systemFile!=IntPtr.Zero && systemFile!=new IntPtr(-1));
                Require(GetFileInformationByHandle(systemFile,out systemInfo));
                systemSha=ReadImage(systemFile,systemPath,true);
                VerifySystemReference(); CheckStarting();
            }
            public void VerifyTemp() { Require(temp!=null); temp.Verify(); }
            static IntPtr Duplicate(IntPtr handle,bool sameAccess) {
                IntPtr result; Require(DuplicateHandle(new IntPtr(-1),handle,new IntPtr(-1),out result,sameAccess?0u:0x00101000u,false,sameAccess?2u:0u));
                Require(result!=IntPtr.Zero && result!=new IntPtr(-1)); return result;
            }
            public IntPtr CaptureCreation(ProcessInfo pi) {
                // Keep PI originals live until CREATE permits an alias comparison.
                initialProcess=pi.process; initialThread=pi.thread; initialPid=(uint)pi.pid; initialTid=(uint)pi.tid;
                lock(sync) state.SetRoot(initialPid);
                return Duplicate(initialProcess,true);
            }
            public void Assigned() { assigned=true; }
            public void StartFailed() { startupFailed=true; Fail("debug_start_failed"); Terminate(); }
            public void Start(Action create) {
                pump=new Thread(delegate() {
                    try { create(); Pump(); }
                    catch(Exception error) { SourceFailure(error); handlesFailed=true; Fail("debug_cleanup_failed"); Terminate(); }
                    finally { SignalStarted(); }
                });
                pump.IsBackground=true;
                try { pump.Start(); } catch { pump=null; joined=true; startupFailed=true; Fail("debug_start_failed"); SignalStarted(); }
            }
            void SignalStarted() { lock(startSignal) { startSignaled=true; Monitor.PulseAll(startSignal); } }
            public bool WaitStarted(int milliseconds) {
                // A managed condition avoids adding an unreported kernel event
                // handle whose lifetime could race Finish's bounded join.
                var wait=Stopwatch.StartNew();
                lock(startSignal) {
                    while(!startSignaled) {
                        int remaining=milliseconds-(int)wait.ElapsedMilliseconds;
                        if(remaining<=0) return false;
                        Monitor.Wait(startSignal,remaining);
                    }
                    return startOkay && !startupFailed;
                }
            }
            public bool JoinForFinish(int grace) {
                lock(sync) state.StopStarting();
                Interlocked.Exchange(ref finishAt,Math.Min((long)session.deadlineMs,session.elapsed.ElapsedMilliseconds+grace));
                joined=pump==null || pump.Join(grace+6000);
                if(!joined) Fail("debug_cleanup_failed");
                return joined && EventResourcesClosed;
            }
            void CloseOwned(ref IntPtr handle) {
                if(handle==IntPtr.Zero) return;
                IntPtr value=handle; handle=IntPtr.Zero;
                if(!CloseHandle(value)) { uncertainHandles.Add(value); handlesFailed=true; Fail("debug_cleanup_failed"); }
            }
            void ResolveOriginals(CreateInfo info) {
                Require(!creationSeen && initialProcess!=IntPtr.Zero && initialThread!=IntPtr.Zero);
                // Live equal values identify one handle-table entry, whose OS
                // event lifecycle must own the only close. Never compare after close.
                if(HostedLaunchState.EventOwnsCreationHandle(initialProcess,info.process)) initialProcess=IntPtr.Zero;
                else CloseOwned(ref initialProcess);
                if(HostedLaunchState.EventOwnsCreationHandle(initialThread,info.thread)) initialThread=IntPtr.Zero;
                else CloseOwned(ref initialThread);
                creationSeen=true;
            }
            void Terminate() {
                if(terminationRequested) return;
                terminationRequested=true;
                IntPtr root=session.process!=IntPtr.Zero?session.process:initialProcess;
                try {
                    bool live=assigned?!session.RefreshJob():root!=IntPtr.Zero && !Exited(root);
                    if(live) {
                        session.forced=true; session.Error("forced_termination");
                        if(assigned) { if(!TerminateJobObject(session.job,99)) session.Error("termination_failed"); }
                        else if(!TerminateProcess(root,99)) session.Error("termination_failed");
                    }
                } catch { Fail("debug_cleanup_failed"); }
            }
            static bool SameInfo(FileInfo a,FileInfo b) {
                return a.attributes==b.attributes && a.volume==b.volume && a.indexHigh==b.indexHigh && a.indexLow==b.indexLow &&
                    a.sizeHigh==b.sizeHigh && a.sizeLow==b.sizeLow && a.links==b.links && a.written.high==b.written.high && a.written.low==b.written.low;
            }
            string FilePath(IntPtr handle) {
                var value=new StringBuilder(4096); uint n=GetFinalPathNameByHandleW(handle,value,4096,0);
                Require(n>0 && n<4096); string result=value.ToString();
                if(result.StartsWith(@"\\?\")) result=result.Substring(4);
                return FullPath(result);
            }
            static HostedInstalledImageIdentity Identity(FileInfo info) {
                return new HostedInstalledImageIdentity(info.attributes,info.volume,((ulong)info.indexHigh<<32)|info.indexLow,
                    ((ulong)info.sizeHigh<<32)|info.sizeLow,((ulong)info.written.high<<32)|info.written.low,info.links);
            }
            string ReadImage(IntPtr handle,string path,bool installed) {
                Require(handle!=IntPtr.Zero && handle!=new IntPtr(-1));
                FileInfo before,after; Require(GetFileInformationByHandle(handle,out before));
                Require((installed?before.links>=1:before.links==1) && (before.attributes&((uint)FileAttributes.ReparsePoint|(uint)FileAttributes.Directory))==0 &&
                    String.Equals(FilePath(handle),path,StringComparison.OrdinalIgnoreCase));
                long end=Math.Min((long)session.deadlineMs,session.elapsed.ElapsedMilliseconds+10000);
                string hash;
                using(var stream=new FileStream(new SafeFileHandle(handle,false),FileAccess.Read,65536,false))
                using(var sha=SHA256.Create()) {
                    Require(stream.Length>0 && stream.Length<=268435456); stream.Position=0;
                    byte[] buffer=new byte[65536]; int count;
                    while((count=stream.Read(buffer,0,buffer.Length))>0) {
                        Require(session.elapsed.ElapsedMilliseconds<end);
                        sha.TransformBlock(buffer,0,count,buffer,0);
                    }
                    sha.TransformFinalBlock(buffer,0,0);
                    Require(session.elapsed.ElapsedMilliseconds<end);
                    hash=BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();
                }
                Require(GetFileInformationByHandle(handle,out after) && SameInfo(before,after) && String.Equals(FilePath(handle),path,StringComparison.OrdinalIgnoreCase));
                return hash;
            }
            void HashImage(IntPtr handle,string path,string hash) { Require(ReadImage(handle,path,false)==hash); }
            void VerifySystemReference() {
                Require(systemParent!=null && systemFile!=IntPtr.Zero && systemFile!=new IntPtr(-1) && !systemClosed);
                systemParent.Verify(); FileInfo current;
                Require(GetFileInformationByHandle(systemFile,out current) && SameInfo(systemInfo,current) &&
                    String.Equals(FilePath(systemFile),systemPath,StringComparison.OrdinalIgnoreCase));
            }
            void VerifySystemImage(IntPtr file,string image) {
                VerifySystemReference(); FileInfo before,after;
                Require(GetFileInformationByHandle(file,out before) && SameInfo(systemInfo,before));
                string hash=ReadImage(file,image,true);
                Require(GetFileInformationByHandle(file,out after) && SameInfo(before,after) &&
                    HostedLaunchState.InstalledImageMatches(Identity(systemInfo),Identity(after),systemPath,image,systemSha,hash));
                VerifySystemReference();
            }
            void Create(DebugEvent value) {
                CreateInfo info=value.info.create;
                Require(info.process!=IntPtr.Zero && info.thread!=IntPtr.Zero && processes.Count<34);
                var owned=new OwnedProcess {handle=Duplicate(info.process,false)}; processes.Add(value.pid,owned);
                owned.created=Created(owned.handle);
                bool root=value.pid==initialPid;
                if(root) { Require(value.tid==initialTid); ResolveOriginals(info); }
                bool belongs; Require(IsProcessInJob(owned.handle,session.job,out belongs) && belongs);
                string image=Image(owned.handle);
                HostedLaunchRole role=root?HostedLaunchRole.Root:
                    HostedLaunchState.RuntimeImagePathAllowed(session.caseRoot,image)?HostedLaunchRole.Runtime:
                    String.Equals(image,systemPath,StringComparison.OrdinalIgnoreCase)?HostedLaunchRole.ConsoleHelper:HostedLaunchRole.Rejected;
                lock(sync) state.Create(role);
                if(role==HostedLaunchRole.Runtime) {
                    VerifyTemp();
                    // These descendant pins are transient. Keeping them after
                    // continuation would block the application's runtime removal.
                    Require(imageParent==null);
                    imageParent=HostedSourceDirectory.AcquireRuntimeImageParent(session.caseRoot,image);
                    try { HashImage(info.file,image,expected); imageParent.Verify(); }
                    catch(Exception primary) {
                        try { imageParent.Dispose(); imageParent=null; }
                        catch { throw HostedSourceDirectory.CleanupFailure(primary); }
                        throw;
                    }
                    // Preserve the lease reference on failed close; uncertainty
                    // forbids releasing the fixed temp/source ownership leases.
                    imageParent.Dispose(); imageParent=null;
                    VerifyTemp();
                } else if(role==HostedLaunchRole.ConsoleHelper) {
                    VerifySystemImage(info.file,image);
                } else {
                    Require(String.Equals(image,appPath,StringComparison.OrdinalIgnoreCase)); HashImage(info.file,image,appSha);
                }
                Require(IsProcessInJob(owned.handle,session.job,out belongs) && belongs && Created(owned.handle)==owned.created);
                lock(sync) state.Verified();
            }
            void CaptureFailedCreate(DebugEvent value) {
                // Diagnostic only, before the failing CREATE's hFile is closed.
                // The existing launch limit, error, termination and drain remain
                // authoritative. No extra image bytes, paths or PIDs are emitted.
                lock(sync) if(failedCreate!=null) return;
                string role="unavailable",image=null;
                bool? ownedJob=null,pathMatches=null;
                try {
                    OwnedProcess owned;
                    if(processes.TryGetValue(value.pid,out owned) && owned.handle!=IntPtr.Zero && Created(owned.handle)==owned.created) {
                        try { bool belongs; if(IsProcessInJob(owned.handle,session.job,out belongs)) ownedJob=belongs; } catch { }
                        try {
                            image=Image(owned.handle);
                            role=HostedLaunchState.FailureImageRole(session.caseRoot,appPath,systemDirectory,image);
                        } catch { }
                        if(image!=null && value.info.create.file!=IntPtr.Zero && value.info.create.file!=new IntPtr(-1)) {
                            try { pathMatches=String.Equals(FilePath(value.info.create.file),image,StringComparison.OrdinalIgnoreCase); } catch { }
                        }
                    }
                } catch { }
                lock(sync) if(failedCreate==null) failedCreate=HostedLaunchState.CreateFailureDiagnostic(state.Events,role,ownedJob,pathMatches);
            }
            public Dictionary<string,object> FailureDiagnostic() {
                lock(sync) return failedCreate==null?null:new Dictionary<string,object>(failedCreate);
            }
            void Pump() {
                if(initialPid==0) return;
                long drainEnd=Int64.MaxValue;
                while(true) {
                    if(startupFailed || session.Deadline || session.elapsed.ElapsedMilliseconds>=Interlocked.Read(ref finishAt)) {
                        if(session.Deadline) session.Error("deadline_exceeded");
                        Terminate();
                        if(drainEnd==Int64.MaxValue) drainEnd=session.elapsed.ElapsedMilliseconds+5000;
                    }
                    if(session.elapsed.ElapsedMilliseconds>=drainEnd) { Fail("debug_cleanup_failed"); return; }
                    DebugEvent value;
                    if(!WaitForDebugEvent(out value,100)) {
                        if(Marshal.GetLastWin32Error()==121) continue;
                        Fail("debug_event_failed"); Terminate(); return;
                    }
                    IntPtr image=value.code==3?value.info.create.file:value.code==6?value.info.load.file:IntPtr.Zero;
                    uint disposition=value.code==1?0x80010001u:0x00010002u;
                    try {
                        Require(image!=new IntPtr(-1));
                        lock(sync) state.Begin(value.code,value.pid,value.tid);
                        if(value.code==3) {
                            try { Create(value); }
                            catch { try { CaptureFailedCreate(value); } catch { } throw; }
                        }
                        else if(value.code==1) lock(sync) disposition=state.ExceptionDisposition(value.info.exception.record.code,value.info.exception.first);
                        else if(value.code==9) Fail("debug_event_failed");
                        lock(sync) { if(state.Failure!=null) { session.Error(state.Failure); startupFailed=true; } }
                    } catch(Exception error) {
                        SourceFailure(error);
                        string code; lock(sync) code=state.Failure;
                        Fail(code??(value.code==3?"debug_image_invalid":"debug_event_failed")); startupFailed=true;
                    } finally {
                        // CREATE and LOAD_DLL hFile are debugger-owned. No DLL
                        // bytes, target strings or target memory are read.
                        if(image!=IntPtr.Zero && image!=new IntPtr(-1)) CloseOwned(ref image);
                    }
                    if(startupFailed || handlesFailed) { startupFailed=true; Terminate(); if(drainEnd==Int64.MaxValue) drainEnd=session.elapsed.ElapsedMilliseconds+5000; }
                    if(!ContinueDebugEvent(value.pid,value.tid,disposition)) { Fail("debug_event_failed"); Terminate(); return; }
                    try {
                        lock(sync) state.Continued();
                        if(value.code==5) {
                            OwnedProcess owned=processes[value.pid];
                            Require(WaitForSingleObject(owned.handle,1000)==0 && Created(owned.handle)==owned.created);
                            CloseOwned(ref owned.handle);
                        }
                    } catch { handlesFailed=true; Fail("debug_cleanup_failed"); Terminate(); return; }
                    if(value.code==3 && value.pid==initialPid) { startOkay=!startupFailed && !handlesFailed; SignalStarted(); }
                    lock(sync) if(state.Drained) return;
                }
            }
            bool EventResourcesClosed { get {
                if(!joined || handlesFailed || imageParent!=null || initialProcess!=IntPtr.Zero || initialThread!=IntPtr.Zero || uncertainHandles.Count!=0) return false;
                foreach(OwnedProcess owned in processes.Values) if(owned.handle!=IntPtr.Zero) return false;
                lock(sync) return initialPid==0 || state.Drained;
            } }
            public void CloseTemp() {
                if(!EventResourcesClosed) { Fail("debug_cleanup_failed"); return; }
                try {
                    if(systemFile!=IntPtr.Zero && systemFile!=new IntPtr(-1)) {
                        VerifySystemReference(); CloseOwned(ref systemFile);
                        if(handlesFailed) return;
                    } else systemFile=IntPtr.Zero;
                    if(systemParent!=null) { systemParent.Verify(); systemParent.Dispose(); systemParent=null; }
                    systemClosed=true;
                    if(temp!=null) { temp.Verify(); temp.Dispose(); temp=null; } tempClosed=true;
                }
                catch { handlesFailed=true; Fail("debug_cleanup_failed"); }
            }
            public bool Released { get { return EventResourcesClosed && tempClosed && systemClosed; } }
            public void CommonCloseFailed() { handlesFailed=true; Fail("debug_cleanup_failed"); }
            public void CheckQualification() { lock(sync) if(!state.Qualified) session.Error(state.Failure??"debug_image_invalid"); }
            public void AddSnapshot(Dictionary<string,object> result) {
                lock(sync) {
                    result.Add("observation_kind","launch_image"); result.Add("launch_image_observed",state.VerifiedLaunches>0);
                    result.Add("launch_sha256",state.VerifiedLaunches>0?expected:null); result.Add("runtime_launch_count",state.Launches);
                    result.Add("peak_runtime_processes",state.Peak); result.Add("debug_event_count",state.Events);
                    result.Add("debug_events_drained",initialPid==0?joined:state.Drained);
                    result.Add("debug_pump_joined",joined); result.Add("debug_handles_closed",Released);
                    state.AddHelperSnapshot(result,systemSha,systemClosed);
                }
            }
        }
        // Size/offset inspection only: safe for pure tests on either pointer width.
        public static Dictionary<string,int> LaunchDebugLayout() { return LaunchObserver.Layout(); }
        public void Dispose() { Finish(0); }
    }

    public enum HostedLaunchRole { Rejected,Root,Runtime,ConsoleHelper }
    public sealed class HostedInstalledImageIdentity {
        public readonly uint Attributes,Volume,Links;
        public readonly ulong Index,Size,Written;
        public HostedInstalledImageIdentity(uint attributes,uint volume,ulong index,ulong size,ulong written,uint links) {
            Attributes=attributes; Volume=volume; Index=index; Size=size; Written=written; Links=links;
        }
    }
    // Pure event-order/limit model. It owns no handles and performs no native calls.
    // The pump uses this same model; tests inject only typed event observations.
    public sealed class HostedLaunchState {
        sealed class Process { public uint initialThread; public HostedLaunchRole role; public bool classified,verified,exited,breakpoint; }
        readonly Dictionary<uint,Process> processes=new Dictionary<uint,Process>();
        readonly int maximumConcurrent,maximumLaunches;
        uint root,code,pid,tid;
        bool pending,startStopped;
        int active,helperActive;
        public int Launches { get; private set; }
        public int VerifiedLaunches { get; private set; }
        public int HelperLaunches { get; private set; }
        public int VerifiedHelpers { get; private set; }
        public int HelperPeak { get; private set; }
        public int Peak { get; private set; }
        public int Events { get; private set; }
        public string Failure { get; private set; }
        public bool CleanupUncertain { get; private set; }
        public HostedLaunchState(int concurrent,int launches) {
            if(concurrent<1 || concurrent>4 || launches<1 || launches>32) throw new ArgumentException("debug_launch_limit");
            maximumConcurrent=concurrent; maximumLaunches=launches;
        }
        void Need(bool value,string error) { if(!value) { Fail(error); throw new InvalidOperationException(error); } }
        public void Fail(string error) {
            if(error!="debug_start_failed" && error!="debug_event_failed" && error!="debug_image_invalid" && error!="debug_launch_limit" && error!="debug_exception_failed" && error!="debug_event_limit" && error!="debug_cleanup_failed") throw new ArgumentException("debug_event_failed");
            if(Failure==null) Failure=error;
        }
        public void SetRoot(uint value) { Need(root==0 && value!=0,"debug_event_failed"); root=value; }
        public void StopStarting() { startStopped=true; }
        public void CheckStarting(bool closing,bool expired) { Need(!startStopped && !closing && !expired && Failure==null,"debug_start_failed"); }
        public string[] ObserveSourceFailure(Exception error) {
            string[] codes=HostedSourceDirectory.FailureCodes(error);
            foreach(string code in codes) if(code=="source_directory_cleanup_failed") { CleanupUncertain=true; Fail("debug_cleanup_failed"); }
            return codes;
        }
        public void Begin(uint eventCode,uint processId,uint threadId) {
            Need(!pending && root!=0 && processId!=0 && threadId!=0 && eventCode>=1 && eventCode<=9,"debug_event_failed");
            Need(Events<4096,"debug_event_limit");
            Process process;
            Need(eventCode==3?!processes.ContainsKey(processId):processes.TryGetValue(processId,out process) && !process.exited,"debug_event_failed");
            code=eventCode; pid=processId; tid=threadId; pending=true; Events++;
            if(code==3) {
                // Reserve the rejected record before any fallible image/handle
                // inspection. A failed CREATE can still receive its EXIT event.
                // Exhausting the absolute storage cap retains the whole session.
                Need(processes.Count<34,"debug_launch_limit");
                processes.Add(pid,new Process {initialThread=tid,role=HostedLaunchRole.Rejected});
            }
        }
        public void Create(HostedLaunchRole role) {
            Need(pending && code==3 && processes.ContainsKey(pid) && !processes[pid].classified,"debug_event_failed");
            Need(Enum.IsDefined(typeof(HostedLaunchRole),role) && (processes.Count==1)==(pid==root) &&
                (pid==root)==(role==HostedLaunchRole.Root),"debug_event_failed");
            Process process=processes[pid]; process.role=role; process.classified=true;
            if(role==HostedLaunchRole.Runtime) { Launches++; active++; Peak=Math.Max(Peak,active); }
            if(role==HostedLaunchRole.ConsoleHelper) { HelperLaunches++; helperActive++; HelperPeak=Math.Max(HelperPeak,helperActive); }
            Need(role!=HostedLaunchRole.Rejected,"debug_image_invalid");
            // Two live helpers is a conservative qualification budget, not a
            // Windows guarantee or a claim that a runtime parented each helper.
            Need(processes.Count<=1+2*maximumLaunches && Launches<=maximumLaunches && active<=maximumConcurrent && HelperLaunches<=maximumLaunches &&
                HelperLaunches<=VerifiedLaunches && helperActive<=2,"debug_launch_limit");
        }
        public void Verified() {
            Need(pending && code==3 && Failure==null,"debug_image_invalid");
            Process process=processes[pid];
            Need(process.classified && !process.verified && process.role!=HostedLaunchRole.Rejected,"debug_image_invalid");
            process.verified=true;
            if(process.role==HostedLaunchRole.Runtime) VerifiedLaunches++;
            if(process.role==HostedLaunchRole.ConsoleHelper) VerifiedHelpers++;
        }
        public uint ExceptionDisposition(uint exceptionCode,uint firstChance) {
            Need(pending && code==1 && firstChance<=1,"debug_event_failed");
            Process process=processes[pid];
            // Only the OS initial first-chance breakpoint on the CREATE thread
            // is consumed. Application exceptions retain their normal handlers.
            if(exceptionCode==0x80000003 && firstChance==1 && tid==process.initialThread && !process.breakpoint) {
                process.breakpoint=true; return 0x00010002;
            }
            if(firstChance==0 || exceptionCode==0x80000003) Fail("debug_exception_failed");
            return 0x80010001;
        }
        public void Continued() {
            Need(pending,"debug_event_failed");
            if(code==3) Need(processes.ContainsKey(pid),"debug_event_failed");
            if(code==3 && !processes[pid].verified) Fail("debug_image_invalid");
            if(code==5) {
                Process process=processes[pid]; process.exited=true;
                if(process.role==HostedLaunchRole.Runtime) active--;
                if(process.role==HostedLaunchRole.ConsoleHelper) helperActive--;
            }
            pending=false;
        }
        public bool Drained { get {
            if(pending || processes.Count==0 || !processes.ContainsKey(root)) return false;
            foreach(Process process in processes.Values) if(!process.exited) return false;
            return true;
        } }
        public bool Qualified { get {
            if(Failure!=null || !Drained || Launches<1 || Launches>maximumLaunches || VerifiedLaunches!=Launches || VerifiedHelpers!=HelperLaunches) return false;
            foreach(Process process in processes.Values) if(!process.breakpoint || !process.verified || process.role==HostedLaunchRole.Rejected) return false;
            return true;
        } }
        public void AddHelperSnapshot(Dictionary<string,object> result,string hash,bool referenceClosed) {
            bool observed=HelperLaunches>0 && HelperLaunches==VerifiedHelpers;
            result.Add("system_helper_image_observed",observed); result.Add("system_helper_sha256",observed?hash:null);
            result.Add("system_helper_launch_count",HelperLaunches); result.Add("peak_system_helper_processes",HelperPeak);
            result.Add("system_helper_reference_closed",referenceClosed);
        }
        public static bool InstalledImageMatches(HostedInstalledImageIdentity reference,HostedInstalledImageIdentity image,
                string expectedPath,string actualPath,string expectedSha,string actualSha) {
            if(reference==null || image==null || reference.Links<1 || reference.Size<1 || reference.Size>268435456 ||
                (reference.Attributes&0x410)!=0 || String.IsNullOrEmpty(expectedPath) ||
                !String.Equals(expectedPath,actualPath,StringComparison.OrdinalIgnoreCase) || expectedSha==null || expectedSha.Length!=64 || expectedSha!=actualSha) return false;
            foreach(char c in expectedSha) if(!((c>='0'&&c<='9') || (c>='a'&&c<='f'))) return false;
            return reference.Attributes==image.Attributes && reference.Volume==image.Volume && reference.Index==image.Index &&
                reference.Size==image.Size && reference.Written==image.Written && reference.Links==image.Links;
        }
        public static bool EventOwnsCreationHandle(IntPtr creation,IntPtr debugEvent) {
            if(creation==IntPtr.Zero || creation==new IntPtr(-1) || debugEvent==IntPtr.Zero || debugEvent==new IntPtr(-1)) throw new ArgumentException("debug_event_failed");
            return creation==debugEvent;
        }
        public static Dictionary<string,object> CreateFailureDiagnostic(int ordinal,string role,bool? ownedJob,bool? pathMatches) {
            if(ordinal<1 || ordinal>4096 || (role!="application_path" && role!="runtime_path" && role!="system_console_host" && role!="other" && role!="unavailable")) throw new ArgumentException("debug_event_failed");
            return new Dictionary<string,object> {
                {"schema_version",1},{"event_ordinal",ordinal},{"image_role",role},
                {"owned_job",ownedJob},{"image_path_matches",pathMatches}
            };
        }
        public static string FailureImageRole(string root,string application,string systemDirectory,string image) {
            // Location classification is never admission or a runtime hash proof.
            try {
                if(String.IsNullOrEmpty(image) || image.Length>4096 || !String.Equals(System.IO.Path.GetFullPath(image),image,StringComparison.OrdinalIgnoreCase)) return "unavailable";
                foreach(char value in image) if(Char.IsControl(value) || Char.IsSurrogate(value)) return "unavailable";
                if(String.Equals(image,application,StringComparison.OrdinalIgnoreCase)) return "application_path";
                if(RuntimeImagePathAllowed(root,image)) return "runtime_path";
                if(!String.IsNullOrEmpty(systemDirectory) && String.Equals(image,System.IO.Path.Combine(systemDirectory,"conhost.exe"),StringComparison.OrdinalIgnoreCase)) return "system_console_host";
                return "other";
            } catch { return "unavailable"; }
        }
        public static string RuntimeTempPath(string root) {
            return System.IO.Path.Combine(System.IO.Path.GetDirectoryName(HostedSourceDirectory.SourcePath(root)),"temp");
        }
        public static bool RuntimeImagePathAllowed(string root,string image) {
            if(image==null || image.Length>2048) return false;
            try {
                string temp=RuntimeTempPath(root),parent=System.IO.Path.GetDirectoryName(image);
                if(parent==null || !String.Equals(System.IO.Path.GetDirectoryName(parent),temp,StringComparison.OrdinalIgnoreCase) ||
                    System.IO.Path.GetFileName(image)!="rclone.exe" || System.IO.Path.GetFullPath(image)!=image) return false;
                string name=System.IO.Path.GetFileName(parent);
                if(!name.StartsWith("rclone-triage-",StringComparison.Ordinal) || name.Length<=14 || name.Length>128) return false;
                foreach(char c in name) if(!((c>='a'&&c<='z') || (c>='A'&&c<='Z') || (c>='0'&&c<='9') || c=='-' || c=='_')) return false;
                return true;
            } catch { return false; }
        }
    }

    // Fixed source cwd, not a filesystem sandbox. Pins prevent path replacement;
    // the producer must independently recheck source bytes and its full inventory.
    // Loading this class is inert. Acquire/Verify/Dispose are hosted-only probes.
    public sealed class HostedSourceDirectory : IDisposable {
        [StructLayout(LayoutKind.Sequential)] struct Time { public uint low,high; }
        [StructLayout(LayoutKind.Sequential)] struct Info {
            public uint attributes; public Time created,accessed,written;
            public uint volume,sizeHigh,sizeLow,links,indexHigh,indexLow;
        }
        sealed class Pin { public IntPtr handle; public string path; public Info info; public bool owned; }
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFileW(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr file,out Info info);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandleW(IntPtr file,StringBuilder path,uint length,uint flags);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
        [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(IntPtr handle,int kind,uint information,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
        readonly List<Pin> pins=new List<Pin>();
        bool closed,invalid,closeFailed;
        public string Path { get; private set; }
        HostedSourceDirectory() { }
        static void Need(bool value) { if(!value) throw new InvalidOperationException("source_directory_invalid"); }
        // Preserve the primary failure privately; only fixed categories escape.
        internal static Exception CleanupFailure(Exception primary) {
            return new InvalidOperationException("source_directory_cleanup_failed",primary);
        }
        public static string[] FailureCodes(Exception error) {
            var codes=new List<string>();
            for(int depth=0; error!=null && depth<8; depth++,error=error.InnerException) {
                string code=error.Message;
                if((code=="source_directory_invalid" || code=="source_directory_cleanup_failed") && !codes.Contains(code)) codes.Add(code);
            }
            return codes.ToArray();
        }
        public static string SourcePath(string root) {
            Need(root!=null && root.Length>3 && root.Length<=2000 &&
                ((root[0]>='A' && root[0]<='Z') || (root[0]>='a' && root[0]<='z')) &&
                root[1]==':' && (root[2]=='\\' || root[2]=='/') && root.IndexOf(':',2)<0);
            foreach(char c in root) Need(!Char.IsControl(c) && !Char.IsSurrogate(c));
            string full=System.IO.Path.GetFullPath(root).TrimEnd('\\');
            Need(full.Length>3 && String.Equals(full,root.Replace('/','\\').TrimEnd('\\'),StringComparison.OrdinalIgnoreCase));
            return System.IO.Path.Combine(full,"source");
        }
        static Info Check(Pin pin) {
            Info info; Need(GetFileInformationByHandle(pin.handle,out info));
            Need((info.attributes&((uint)FileAttributes.Directory|(uint)FileAttributes.ReparsePoint))==(uint)FileAttributes.Directory);
            var path=new StringBuilder(4096); uint length=GetFinalPathNameByHandleW(pin.handle,path,4096,0);
            Need(length>0 && length<4096); string actual=path.ToString();
            if(actual.StartsWith(@"\\?\")) actual=actual.Substring(4);
            Need(String.Equals(actual.TrimEnd('\\'),pin.path.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase));
            if(pin.owned) CheckAcl(pin.handle);
            return info;
        }
        static void CheckAcl(IntPtr handle) {
            IntPtr owner,group,dacl,sacl,descriptor;
            Need(GetSecurityInfo(handle,1,5,out owner,out group,out dacl,out sacl,out descriptor)==0);
            Exception primary=null;
            try {
                Need(descriptor!=IntPtr.Zero && owner!=IntPtr.Zero && dacl!=IntPtr.Zero);
                uint length=GetSecurityDescriptorLength(descriptor); Need(length>0 && length<=65536);
                byte[] bytes=new byte[length]; Marshal.Copy(descriptor,bytes,0,(int)length);
                var acl=new DirectorySecurity(); acl.SetSecurityDescriptorBinaryForm(bytes,AccessControlSections.Access|AccessControlSections.Owner);
                string sid; using(var identity=WindowsIdentity.GetCurrent()) sid=identity.User.Value;
                Need(acl.AreAccessRulesProtected && acl.GetOwner(typeof(SecurityIdentifier)).Value==sid);
                bool user=false,system=false;
                foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier))) {
                    string who=rule.IdentityReference.Value;
                    Need(rule.AccessControlType==AccessControlType.Allow && (who==sid || who=="S-1-5-18") &&
                        (rule.FileSystemRights&FileSystemRights.FullControl)==FileSystemRights.FullControl &&
                        (rule.InheritanceFlags&(InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit))==(InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit) &&
                        (rule.PropagationFlags&PropagationFlags.InheritOnly)==0);
                    if(who==sid) user=true; else system=true;
                }
                Need(user && system);
            } catch(Exception e) { primary=e; throw; }
            finally { if(descriptor!=IntPtr.Zero && LocalFree(descriptor)!=IntPtr.Zero) throw CleanupFailure(primary); }
        }
        public static HostedSourceDirectory Acquire(string root) {
            string source=SourcePath(root); root=System.IO.Path.GetDirectoryName(source);
            return AcquirePath(root,source);
        }
        internal static HostedSourceDirectory AcquireRuntimeTemp(string root) {
            string temp=HostedLaunchState.RuntimeTempPath(root);
            return AcquirePath(System.IO.Path.GetDirectoryName(temp),temp);
        }
        internal static HostedSourceDirectory AcquireRuntimeImageParent(string root,string image) {
            Need(HostedLaunchState.RuntimeImagePathAllowed(root,image));
            return AcquirePath(System.IO.Path.GetDirectoryName(HostedLaunchState.RuntimeTempPath(root)),System.IO.Path.GetDirectoryName(image));
        }
        internal static HostedSourceDirectory AcquireInstalledImageParent(string image) {
            // Caller supplies only its internal SystemDirectory/conhost.exe.
            // Installed ancestors use identity/final-path/no-reparse checks,
            // never the private case ACL policy or permission repair.
            Need(String.Equals(image,System.IO.Path.Combine(Environment.SystemDirectory,"conhost.exe"),StringComparison.OrdinalIgnoreCase));
            return AcquirePath(null,System.IO.Path.GetDirectoryName(image));
        }
        static HostedSourceDirectory AcquirePath(string root,string source) {
            var chain=new List<string>();
            for(string path=source; !String.IsNullOrEmpty(path); path=System.IO.Path.GetDirectoryName(path)) {
                Need(chain.Count<64); chain.Add(path);
            }
            chain.Reverse(); var lease=new HostedSourceDirectory {Path=source};
            try {
                foreach(string path in chain) {
                    bool owned=root!=null && (String.Equals(path,root,StringComparison.OrdinalIgnoreCase) || path.StartsWith(root+System.IO.Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase));
                    // LIST_DIRECTORY participates in sharing checks; metadata-only
                    // access does not. Add READ_ATTRIBUTES and owned READ_CONTROL.
                    // MS-FSA 2.1.5.1.2.2: omit DELETE sharing to hold each name.
                    IntPtr handle=CreateFileW(path,owned?0x20081u:0x81u,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
                    Need(handle!=IntPtr.Zero && handle!=new IntPtr(-1));
                    var pin=new Pin {handle=handle,path=path,owned=owned}; lease.pins.Add(pin);
                    pin.info=Check(pin);
                }
                lease.Verify(); return lease;
            } catch(Exception primary) {
                try { lease.Dispose(); } catch { throw CleanupFailure(primary); }
                throw;
            }
        }
        public void Verify() {
            Need(!closed && !invalid && pins.Count>0);
            try {
                foreach(Pin pin in pins) {
                    Info info=Check(pin);
                    Need(info.volume==pin.info.volume && info.indexHigh==pin.info.indexHigh && info.indexLow==pin.info.indexLow);
                }
            } catch { invalid=true; throw; }
        }
        public void Dispose() {
            if(!closed) {
                for(int index=pins.Count-1; index>=0; index--) if(!CloseHandle(pins[index].handle)) closeFailed=true;
                closed=true;
            }
            if(closeFailed) throw new InvalidOperationException("source_directory_cleanup_failed");
        }
    }

    // Pure state/encoding helpers used by the separate TUI bridge. None calls
    // native APIs; a rejected budget is sticky and cannot be reused.
    public sealed class HostedTuiInputBudget {
        int inputCommands,resizeCount;
        long inputBytes;
        bool failed;
        public int InputCommands { get { return inputCommands; } }
        public long InputBytes { get { return inputBytes; } }
        public int ResizeCount { get { return resizeCount; } }
        void Need(bool value) { if(failed || !value) { failed=true; throw new FormatException("protocol_invalid"); } }
        public void ReserveInput(int length) {
            Need(length>=1 && length<=256 && inputCommands<256 && inputBytes+length<=8192);
            inputCommands++; inputBytes+=length;
        }
        public void ReserveResize(int columns,int rows) {
            Need(HostedTuiProtocol.SizeAllowed(columns,rows) && resizeCount<16); resizeCount++;
        }
    }

    public sealed class HostedTuiProtocol {
        int commands;
        long bytes;
        bool failed;
        public int CommandCount { get { return commands; } }
        public long RequestBytes { get { return bytes; } }
        public static bool SizeAllowed(int columns,int rows) { return (columns==120 && rows==34) || (columns==80 && rows==24); }
        public static byte[] KeyBytes(string key) {
            string value;
            switch(key) {
                case "enter": value="\r"; break; case "escape": value="\x1b"; break;
                case "up": value="\x1b[A"; break; case "down": value="\x1b[B"; break;
                case "right": value="\x1b[C"; break; case "left": value="\x1b[D"; break;
                case "tab": value="\t"; break; case "backspace": value="\x7f"; break;
                case "home": value="\x1b[H"; break; case "end": value="\x1b[F"; break;
                case "page_up": value="\x1b[5~"; break; case "page_down": value="\x1b[6~"; break;
                case "space": value=" "; break;
                default: throw new FormatException("protocol_invalid");
            }
            return Encoding.ASCII.GetBytes(value);
        }
        public static byte[] TextBytes(string text) {
            if(text==null || text.Length<1 || text.Length>256) throw new FormatException("protocol_invalid");
            foreach(char c in text) if(c<32 || c>126) throw new FormatException("protocol_invalid");
            return Encoding.ASCII.GetBytes(text);
        }
        public Dictionary<string,object> Read(TextReader reader) {
            try {
                if(failed || reader==null) throw new FormatException("protocol_invalid");
                var line=new StringBuilder(); int c;
                while((c=reader.Read())!=-1) {
                    if(bytes>=1048576 || c>127) throw new FormatException("protocol_invalid");
                    bytes++;
                    if(c==10) {
                        if(commands>=1024) throw new FormatException("protocol_invalid");
                        commands++; return HostedProtocol.Parse(line.ToString());
                    }
                    if(line.Length>=65536) throw new FormatException("protocol_invalid");
                    line.Append((char)c);
                }
                if(line.Length!=0) throw new FormatException("protocol_invalid");
                return null;
            } catch { failed=true; throw new FormatException("protocol_invalid"); }
        }
        public Dictionary<string,object> Counters(Dictionary<string,object> value) {
            value.Add("protocol_commands",commands); value.Add("protocol_bytes",bytes); return value;
        }
        public Dictionary<string,object> Failure() {
            var result=HostedProtocol.Failure(); result["schema_version"]=2;
            result.Add("input_commands",0); result.Add("input_bytes",0L); result.Add("resize_count",0);
            result.Add("columns",120); result.Add("rows",34); return Counters(result);
        }
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
        public static int RuntimeProcessLimit(Dictionary<string,object> value) { int limit=Integer(value,"max_runtime_processes"); if(limit<1 || limit>4) throw new FormatException("protocol_invalid"); return limit; }
        public static string[] Arguments(Dictionary<string,object> value) { var array=value["args"] as object[]; if(array==null) throw new FormatException("protocol_invalid"); var result=new string[array.Length]; for(int i=0;i<array.Length;i++) { if(!(array[i] is string)) throw new FormatException("protocol_invalid"); result[i]=(string)array[i]; } return result; }
        public static Dictionary<string,string> EnvironmentMap(Dictionary<string,object> value) { var map=value["environment"] as Dictionary<string,object>; if(map==null) throw new FormatException("protocol_invalid"); var result=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase); foreach(var item in map) { if(!(item.Value is string)) throw new FormatException("protocol_invalid"); result.Add(item.Key,(string)item.Value); } return result; }
        public static Dictionary<string,object> Failure() {
            return new Dictionary<string,object> {{"schema_version",1},{"ok",false},{"state","finished"},{"app_exit_code",null},
                {"runtime_image_observed",false},{"runtime_sha256",null},{"runtime_process_count",null},{"ctrl_c_sent",false},{"output_bytes",0L},
                {"output_limit_exceeded",false},{"forced_termination",false},{"app_exited",false},{"observed_children_exited",false},
                {"job_zero_confirmed",false},{"reader_joined",false},{"conpty_closed",false},{"errors",new string[]{"protocol_invalid"}}};
        }
    }
}
