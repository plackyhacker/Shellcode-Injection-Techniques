using System;
using System.Runtime.InteropServices;

namespace ShellcodeInjectionTechniques
{
    class Native
    {
        public enum MemoryProtection : UInt32
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

		public enum ThreadCreationFlags : UInt32
        {
			NORMAL = 0x0,
			CREATE_SUSPENDED = 0x00000004,
			STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000
		}

		[Flags]
		public enum AllocationType
		{
			Commit = 0x1000,
			Reserve = 0x2000,
			Decommit = 0x4000,
			Release = 0x8000,
			Reset = 0x80000,
			Physical = 0x400000,
			TopDown = 0x100000,
			WriteWatch = 0x200000,
			LargePages = 0x20000000
		}

		[Flags]
        public enum ThreadAccess : UInt32
        {
            TERMINATE = 0x0001,
            SUSPEND_RESUME = 0x0002,
            GET_CONTEXT = 0x0008,
            SET_CONTEXT = 0x0010,
            SET_INFORMATION = 0x0020,
            QUERY_INFORMATION = 0x0040,
            SET_THREAD_TOKEN = 0x0080,
            IMPERSONATE = 0x0100,
            DIRECT_IMPERSONATION = 0x0200,
            THREAD_ALL_ACCESS = 0x1fffff
        }

		[StructLayout(LayoutKind.Sequential)]
		public struct M128A
		{
			public ulong High;
			public long Low;

			public override string ToString()
			{
				return string.Format("High:{0}, Low:{1}", this.High, this.Low);
			}
		}

		[StructLayout(LayoutKind.Sequential, Pack = 16)]
		public struct XSAVE_FORMAT64
		{
			public ushort ControlWord;
			public ushort StatusWord;
			public byte TagWord;
			public byte Reserved1;
			public ushort ErrorOpcode;
			public uint ErrorOffset;
			public ushort ErrorSelector;
			public ushort Reserved2;
			public uint DataOffset;
			public ushort DataSelector;
			public ushort Reserved3;
			public uint MxCsr;
			public uint MxCsr_Mask;

			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
			public M128A[] FloatRegisters;

			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
			public M128A[] XmmRegisters;

			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
			public byte[] Reserved4;
		}

		[StructLayout(LayoutKind.Sequential, Pack = 16)]
		public struct CONTEXT64
		{
			public ulong P1Home;
			public ulong P2Home;
			public ulong P3Home;
			public ulong P4Home;
			public ulong P5Home;
			public ulong P6Home;

			public uint ContextFlags;
			public uint MxCsr;

			public ushort SegCs;
			public ushort SegDs;
			public ushort SegEs;
			public ushort SegFs;
			public ushort SegGs;
			public ushort SegSs;
			public uint EFlags;

			public ulong Dr0;
			public ulong Dr1;
			public ulong Dr2;
			public ulong Dr3;
			public ulong Dr6;
			public ulong Dr7;

			public ulong Rax;
			public ulong Rcx;
			public ulong Rdx;
			public ulong Rbx;
			public ulong Rsp;
			public ulong Rbp;
			public ulong Rsi;
			public ulong Rdi;
			public ulong R8;
			public ulong R9;
			public ulong R10;
			public ulong R11;
			public ulong R12;
			public ulong R13;
			public ulong R14;
			public ulong R15;
			public ulong Rip;

			public XSAVE_FORMAT64 DUMMYUNIONNAME;

			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
			public M128A[] VectorRegister;
			public ulong VectorControl;

			public ulong DebugControl;
			public ulong LastBranchToRip;
			public ulong LastBranchFromRip;
			public ulong LastExceptionToRip;
			public ulong LastExceptionFromRip;
		}


		[DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, ThreadCreationFlags dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, MemoryProtection flNewProtect, out MemoryProtection lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, UInt32 dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint SuspendThread(IntPtr hThread);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

		[DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint GetLastError();
    }
}
