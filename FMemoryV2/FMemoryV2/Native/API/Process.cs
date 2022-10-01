using System;
using static FMemoryV2.Native.Kernel32;
using System.Diagnostics;

namespace FMemoryV2
{
    public partial class Memory
    {
        public bool FindProcess(string ProcessName)
        {
            Process[] processesByName = Process.GetProcessesByName(ProcessName);
            if (processesByName.Length == 0)
            {
                return false;
            }
            BaseAddress = processesByName[0].MainModule.BaseAddress;
            ID = processesByName[0].Id;
            Name = processesByName[0].ProcessName;
            HandleProcess = OpenProcess(0x38, false, ID);
            return (HandleProcess != IntPtr.Zero);
        }
    }
}
