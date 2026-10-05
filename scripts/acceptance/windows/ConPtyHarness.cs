// Native Windows ConPTY acceptance support. No application is launched by loading this file.
// API/lifetime reference: https://learn.microsoft.com/windows/console/creating-a-pseudoconsole-session
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace TriageLab {
    // A text-cell reconstruction of actual VT output, not an app/TestBackend renderer.
    // SGR colors/font metrics are intentionally not evaluated; exact bytes remain in .vt.
    public sealed class VtScreen {
        private char[,] cells;
        private int rows, columns, row, column, savedRow, savedColumn, state;
        private int scrollTop, scrollBottom;
        private bool wrapPending;
        private char previousPrintable=' ';
        private readonly StringBuilder sequence = new StringBuilder();
        private readonly HashSet<string> unsupported = new HashSet<string>();
        public VtScreen(int width, int height) { Resize(width, height); }
        public string[] Unsupported { get { lock(this) { var r=new string[unsupported.Count]; unsupported.CopyTo(r); return r; } } }
        public void Resize(int width, int height) {
            lock(this) {
                char[,] next = new char[height,width];
                for(int y=0;y<height;y++) for(int x=0;x<width;x++) next[y,x]=' ';
                if(cells!=null) for(int y=0;y<Math.Min(rows,height);y++) for(int x=0;x<Math.Min(columns,width);x++) next[y,x]=cells[y,x];
                cells=next; columns=width; rows=height; scrollTop=0; scrollBottom=height-1;
                row=Math.Min(row,height-1); column=Math.Min(column,width-1); wrapPending=false;
            }
        }
        public string Snapshot() {
            lock(this) {
                var result=new StringBuilder();
                for(int y=0;y<rows;y++) { for(int x=0;x<columns;x++) result.Append(cells[y,x]); result.Append('\n'); }
                return result.ToString();
            }
        }
        private void ClearLine(int y,int from,int to) { for(int x=Math.Max(0,from);x<=Math.Min(columns-1,to);x++) cells[y,x]=' '; }
        private void Scroll(int count) {
            count=Math.Min(Math.Abs(count),scrollBottom-scrollTop+1)*Math.Sign(count);
            if(count>0) { for(int y=scrollTop;y<=scrollBottom-count;y++) for(int x=0;x<columns;x++) cells[y,x]=cells[y+count,x]; for(int y=scrollBottom-count+1;y<=scrollBottom;y++) ClearLine(y,0,columns-1); }
            else if(count<0) { int n=-count; for(int y=scrollBottom;y>=scrollTop+n;y--) for(int x=0;x<columns;x++) cells[y,x]=cells[y-n,x]; for(int y=scrollTop;y<scrollTop+n;y++) ClearLine(y,0,columns-1); }
        }
        private void LineFeed() { if(row==scrollBottom) Scroll(1); else row=Math.Min(rows-1,row+1); }
        private void Put(char ch) {
            if(wrapPending) { column=0; LineFeed(); wrapPending=false; }
            cells[row,column]=ch; previousPrintable=ch;
            if(column==columns-1) wrapPending=true; else column++;
        }
        private static int Arg(string[] args,int index,int fallback) { int n; return index<args.Length && Int32.TryParse(args[index],out n) ? n : fallback; }
        private void Csi(char final,string body) {
            string[] p=body.TrimStart('?','>','!').Split(';'); int n=Math.Max(1,Arg(p,0,1)); bool privateMode=body.StartsWith("?");
            switch(final) {
                case 'H': case 'f': row=Math.Max(0,Math.Min(rows-1,Arg(p,0,1)-1)); column=Math.Max(0,Math.Min(columns-1,Arg(p,1,1)-1)); break;
                case 'G': case '`': column=Math.Max(0,Math.Min(columns-1,n-1)); break;
                case 'd': row=Math.Max(0,Math.Min(rows-1,n-1)); break;
                case 'A': row=Math.Max(0,row-n); break;
                case 'B': row=Math.Min(rows-1,row+n); break;
                case 'C': column=Math.Min(columns-1,column+n); break;
                case 'D': column=Math.Max(0,column-n); break;
                case 'E': row=Math.Min(rows-1,row+n); column=0; break;
                case 'F': row=Math.Max(0,row-n); column=0; break;
                case 'J':
                    int mode=Arg(p,0,0);
                    if(mode==2 || mode==3) { for(int y=0;y<rows;y++) ClearLine(y,0,columns-1); }
                    else if(mode==0) { ClearLine(row,column,columns-1); for(int y=row+1;y<rows;y++) ClearLine(y,0,columns-1); }
                    else if(mode==1) { for(int y=0;y<row;y++) ClearLine(y,0,columns-1); ClearLine(row,0,column); }
                    break;
                case 'K': int lineMode=Arg(p,0,0); ClearLine(row,lineMode==0?column:0,lineMode==1?column:columns-1); break;
                case 'X': ClearLine(row,column,column+n-1); break;
                case '@': n=Math.Min(n,columns-column); for(int x=columns-1;x>=column+n;x--) cells[row,x]=cells[row,x-n]; ClearLine(row,column,column+n-1); break;
                case 'P': n=Math.Min(n,columns-column); for(int x=column;x<columns-n;x++) cells[row,x]=cells[row,x+n]; ClearLine(row,columns-n,columns-1); break;
                case 'L': case 'M': int oldTop=scrollTop; scrollTop=row; Scroll(final=='L'?-n:n); scrollTop=oldTop; break;
                case 'b': for(int repeat=0;repeat<n;repeat++) Put(previousPrintable); break;
                case 'S': Scroll(n); break;
                case 'T': Scroll(-n); break;
                case 'r': scrollTop=Math.Max(0,Math.Min(rows-1,Arg(p,0,1)-1)); scrollBottom=Math.Max(scrollTop,Math.Min(rows-1,Arg(p,1,rows)-1)); row=0; column=0; break;
                case 's': savedRow=row; savedColumn=column; break;
                case 'u': row=Math.Min(rows-1,savedRow); column=Math.Min(columns-1,savedColumn); break;
                case 'm': case 'n': case 'c': case 't': case 'q': break;
                case 'h': case 'l':
                    if(privateMode && body.Contains("1049") && final=='h') { for(int y=0;y<rows;y++) ClearLine(y,0,columns-1); row=0; column=0; }
                    break;
                default: if(unsupported.Count<32) unsupported.Add("CSI "+body+final); break;
            }
            if(final!='m' && final!='h' && final!='l' && final!='q' && final!='n' && final!='c' && final!='t' && final!='b') wrapPending=false;
        }
        public void Feed(string text) {
            lock(this) foreach(char ch in text) {
                if(state==4) { if(ch=='\\') state=0; else state=3; continue; }
                if(state==3) { if(ch=='\a') state=0; else if(ch=='\x1b') state=4; continue; }
                if(state==5) { state=0; continue; }
                if(state==2) {
                    if(ch>='@' && ch<='~') { Csi(ch,sequence.ToString()); sequence.Clear(); state=0; }
                    else if(sequence.Length<256) sequence.Append(ch); else { sequence.Clear(); state=0; }
                    continue;
                }
                if(state==1) {
                    state=0;
                    switch(ch) {
                        case '[': state=2; sequence.Clear(); break;
                        case ']': state=3; break;
                        case '(': case ')': state=5; break;
                        case '7': savedRow=row; savedColumn=column; break;
                        case '8': row=Math.Min(rows-1,savedRow); column=Math.Min(columns-1,savedColumn); break;
                        case 'D': LineFeed(); break;
                        case 'M': if(row==scrollTop) Scroll(-1); else row=Math.Max(0,row-1); break;
                        case 'E': column=0; LineFeed(); break;
                        case 'c': for(int y=0;y<rows;y++) ClearLine(y,0,columns-1); row=0; column=0; break;
                        case '=': case '>': break;
                        default: if(unsupported.Count<32) unsupported.Add("ESC "+ch); break;
                    }
                    continue;
                }
                if(ch=='\x1b') { state=1; continue; }
                if(ch=='\r') { column=0; wrapPending=false; continue; }
                if(ch=='\n') { LineFeed(); wrapPending=false; continue; }
                if(ch=='\b') { column=Math.Max(0,column-1); wrapPending=false; continue; }
                if(ch=='\t') { column=Math.Min(columns-1,(column/8+1)*8); wrapPending=false; continue; }
                if(ch<' ') continue;
                Put(ch);
            }
        }
    }

    public sealed class ConPtySession : IDisposable {
        [StructLayout(LayoutKind.Sequential)] struct COORD { public short X,Y; public COORD(short x,short y){X=x;Y=y;} }
        [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct STARTUPINFO { public int cb; public string reserved,desktop,title; public int x,y,xSize,ySize,xCountChars,yCountChars,fillAttribute,flags; public short showWindow,reserved2; public IntPtr reservedPtr,stdInput,stdOutput,stdError; }
        [StructLayout(LayoutKind.Sequential)] struct STARTUPINFOEX { public STARTUPINFO startup; public IntPtr attributes; }
        [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION { public IntPtr process,thread; public int processId,threadId; }
        [StructLayout(LayoutKind.Sequential)] struct BASIC_LIMIT { public long processTime,jobTime; public uint flags; public UIntPtr minWorkingSet,maxWorkingSet; public uint activeLimit; public UIntPtr affinity; public uint priority,scheduling; }
        [StructLayout(LayoutKind.Sequential)] struct IO_COUNTERS { public ulong readOps,writeOps,otherOps,readBytes,writeBytes,otherBytes; }
        [StructLayout(LayoutKind.Sequential)] struct EXTENDED_LIMIT { public BASIC_LIMIT basic; public IO_COUNTERS io; public UIntPtr processMemory,jobMemory,peakProcessMemory,peakJobMemory; }
        [StructLayout(LayoutKind.Sequential)] struct ACCOUNTING { public long user,kernel,periodUser,periodKernel; public uint faults,totalProcesses,activeProcesses,terminatedProcesses; }
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool CreatePipe(out IntPtr read,out IntPtr write,IntPtr security,uint size);
        [DllImport("kernel32.dll")] static extern int CreatePseudoConsole(COORD size,IntPtr input,IntPtr output,uint flags,out IntPtr console);
        [DllImport("kernel32.dll")] static extern int ResizePseudoConsole(IntPtr console,COORD size);
        [DllImport("kernel32.dll")] static extern void ClosePseudoConsole(IntPtr console);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,int flags,ref IntPtr size);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr previous,IntPtr returned);
        [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessW(string app,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,bool inherit,uint flags,IntPtr environment,string cwd,ref STARTUPINFOEX startup,out PROCESS_INFORMATION process);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObjectW(IntPtr security,string name);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int infoClass,ref EXTENDED_LIMIT info,uint size);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int infoClass,out ACCOUNTING info,uint size,IntPtr returned);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
        [DllImport("kernel32.dll")] static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
        delegate bool EnumWindowProc(IntPtr window,IntPtr parameter);
        [DllImport("user32.dll")] static extern bool EnumWindows(EnumWindowProc callback,IntPtr parameter);
        [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window,out uint process);
        [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetWindowTextW(IntPtr window,StringBuilder title,int count);
        [DllImport("user32.dll",SetLastError=true)] static extern bool PostMessageW(IntPtr window,uint message,IntPtr wParam,IntPtr lParam);

        private IntPtr console,process,job;
        private FileStream input,output,transcript;
        private Thread reader;
        private bool disposed;
        private readonly object inputLock=new object();
        public VtScreen Screen { get; private set; }
        public int ProcessId { get; private set; }
        public string ReaderError { get; private set; }
        public bool ForcedTermination { get; private set; }
        public uint ResidualProcessesAtClose { get; private set; }
        public long OutputBytes { get; private set; }
        public bool HasExited { get { return process!=IntPtr.Zero && WaitForSingleObject(process,0)==0; } }
        public uint ExitCode { get { uint code; if(!GetExitCodeProcess(process,out code)) throw new Win32Exception(); return code; } }
        public bool WaitForExit(int milliseconds) { return WaitForSingleObject(process,(uint)milliseconds)==0; }
        public static string Quote(string value) {
            var b=new StringBuilder("\""); int slashes=0;
            foreach(char c in value) { if(c=='\\') {slashes++;continue;} if(c=='\"') {b.Append('\\',slashes*2+1);b.Append(c);} else {b.Append('\\',slashes);b.Append(c);} slashes=0; }
            b.Append('\\',slashes*2); b.Append('"'); return b.ToString();
        }
        public static ConPtySession Start(string executable,string[] arguments,string workingDirectory,string transcriptPath,int width,int height) {
            var s=new ConPtySession(); s.Screen=new VtScreen(width,height);
            IntPtr inputRead=IntPtr.Zero,inputWrite=IntPtr.Zero,outputRead=IntPtr.Zero,outputWrite=IntPtr.Zero,attributes=IntPtr.Zero;
            PROCESS_INFORMATION pi=new PROCESS_INFORMATION(); bool listInitialized=false;
            try {
                if(!CreatePipe(out inputRead,out inputWrite,IntPtr.Zero,0) || !CreatePipe(out outputRead,out outputWrite,IntPtr.Zero,0)) throw new Win32Exception();
                int hr=CreatePseudoConsole(new COORD((short)width,(short)height),inputRead,outputWrite,0,out s.console); if(hr!=0) Marshal.ThrowExceptionForHR(hr);
                s.input=new FileStream(new SafeFileHandle(inputWrite,true),FileAccess.Write,4096,false); inputWrite=IntPtr.Zero;
                s.output=new FileStream(new SafeFileHandle(outputRead,true),FileAccess.Read,4096,false); outputRead=IntPtr.Zero;
                s.transcript=new FileStream(transcriptPath,FileMode.CreateNew,FileAccess.Write,FileShare.Read);
                s.reader=new Thread(s.ReadLoop); s.reader.IsBackground=true; s.reader.Start();
                IntPtr size=IntPtr.Zero; InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref size); attributes=Marshal.AllocHGlobal(size);
                if(!InitializeProcThreadAttributeList(attributes,1,0,ref size)) throw new Win32Exception(); listInitialized=true;
                if(!UpdateProcThreadAttribute(attributes,0,new IntPtr(0x00020016),s.console,new IntPtr(IntPtr.Size),IntPtr.Zero,IntPtr.Zero)) throw new Win32Exception();
                s.job=CreateJobObjectW(IntPtr.Zero,null); if(s.job==IntPtr.Zero) throw new Win32Exception();
                var limits=new EXTENDED_LIMIT(); limits.basic.flags=0x2000;
                if(!SetInformationJobObject(s.job,9,ref limits,(uint)Marshal.SizeOf(typeof(EXTENDED_LIMIT)))) throw new Win32Exception();
                var startup=new STARTUPINFOEX(); startup.startup.cb=Marshal.SizeOf(typeof(STARTUPINFOEX)); startup.attributes=attributes;
                // Parent PowerShell output is redirected. Without this flag Windows
                // duplicates those file handles even with inherit=false, bypassing
                // ConPTY. Null standard handles ask the PTY to establish its own.
                // https://github.com/microsoft/terminal/discussions/15814
                startup.startup.flags=0x00000100; // STARTF_USESTDHANDLES
                var command=new StringBuilder(Quote(executable)); foreach(string argument in arguments) command.Append(' ').Append(Quote(argument));
                if(!CreateProcessW(executable,command,IntPtr.Zero,IntPtr.Zero,false,0x00080004,IntPtr.Zero,workingDirectory,ref startup,out pi)) throw new Win32Exception();
                s.process=pi.process; s.ProcessId=pi.processId;
                if(!AssignProcessToJobObject(s.job,s.process)) { TerminateProcess(s.process,99); throw new Win32Exception(); }
                if(ResumeThread(pi.thread)==0xffffffff) throw new Win32Exception();
                return s;
            } catch { s.Dispose(); throw; }
            finally {
                if(pi.thread!=IntPtr.Zero) CloseHandle(pi.thread);
                if(listInitialized) DeleteProcThreadAttributeList(attributes); if(attributes!=IntPtr.Zero) Marshal.FreeHGlobal(attributes);
                if(inputRead!=IntPtr.Zero) CloseHandle(inputRead); if(outputWrite!=IntPtr.Zero) CloseHandle(outputWrite);
                if(inputWrite!=IntPtr.Zero) CloseHandle(inputWrite); if(outputRead!=IntPtr.Zero) CloseHandle(outputRead);
            }
        }
        private void ReadLoop() {
            byte[] bytes=new byte[8192]; char[] chars=new char[8192]; Decoder decoder=Encoding.UTF8.GetDecoder();
            try { int count; while((count=output.Read(bytes,0,bytes.Length))>0) {
                transcript.Write(bytes,0,count); transcript.Flush(); OutputBytes+=count;
                int decoded=decoder.GetChars(bytes,0,count,chars,0,false); Screen.Feed(new string(chars,0,decoded));
            } } catch(IOException) { } catch(ObjectDisposedException) { } catch(Exception e) { ReaderError=e.ToString(); }
        }
        public void Send(string text) { byte[] bytes=Encoding.UTF8.GetBytes(text); lock(inputLock) {input.Write(bytes,0,bytes.Length);input.Flush();} }
        public void Resize(int width,int height) { Screen.Resize(width,height); int hr=ResizePseudoConsole(console,new COORD((short)width,(short)height)); if(hr!=0) Marshal.ThrowExceptionForHR(hr); }
        public static int CloseConfigPickerWindows(int pickerProcessId) {
            int count=0; EnumWindows(delegate(IntPtr window,IntPtr parameter) {
                uint pid; GetWindowThreadProcessId(window,out pid); if(pid!=(uint)pickerProcessId) return true;
                var title=new StringBuilder(512); GetWindowTextW(window,title,title.Capacity);
                if(title.ToString().IndexOf("Select rclone config file",StringComparison.OrdinalIgnoreCase)>=0 && PostMessageW(window,0x0010,IntPtr.Zero,IntPtr.Zero)) count++;
                return true;
            },IntPtr.Zero); return count;
        }
        public void Dispose() {
            if(disposed) return; disposed=true;
            if(process!=IntPtr.Zero && !HasExited) ForcedTermination=true;
            if(job!=IntPtr.Zero) { ACCOUNTING accounting; if(QueryInformationJobObject(job,1,out accounting,(uint)Marshal.SizeOf(typeof(ACCOUNTING)),IntPtr.Zero)) ResidualProcessesAtClose=accounting.activeProcesses; CloseHandle(job); job=IntPtr.Zero; }
            if(process!=IntPtr.Zero) WaitForSingleObject(process,5000);
            // Output reader remains alive until ConPTY shutdown has flushed its final frame.
            if(console!=IntPtr.Zero) { ClosePseudoConsole(console); console=IntPtr.Zero; }
            if(input!=null) input.Dispose();
            if(reader!=null && !reader.Join(5000)) { if(output!=null) output.Dispose(); reader.Join(1000); }
            if(output!=null) output.Dispose(); if(transcript!=null) transcript.Dispose();
            if(process!=IntPtr.Zero) { CloseHandle(process); process=IntPtr.Zero; }
        }
    }
}
