using System;
using System.Runtime.InteropServices;
using static FMemoryV2.Native.Kernel32;

namespace FMemoryV2
{
    public partial class Memory
    {
        private byte[] StructureToByteArray(object obj)
        {
            var length = Marshal.SizeOf(obj);
            var buffer = new byte[length];
            var ptr = Marshal.AllocHGlobal(length);
            Marshal.StructureToPtr(obj, ptr, true);
            Marshal.Copy(ptr, buffer, 0, length);
            Marshal.FreeHGlobal(ptr);
            return buffer;
        }

        public void WriteMemory(IntPtr Address, object Value)
        {
            IntPtr ptr;
            byte[] bytes = StructureToByteArray(Value);
            WriteProcessMemory(HandleProcess, Address, bytes, bytes.Length, out ptr);
        }

        public void WriteMemory(IntPtr Address, int[] Offsets, object Value)
        {
            IntPtr ptr;
            byte[] bytes = StructureToByteArray(Value);

            foreach (int i in Offsets)
            {
                ReadProcessMemory(HandleProcess, Address, bytes, bytes.Length, out ptr);
                Address = (IntPtr.Size == 8) ? Address = IntPtr.Add(new IntPtr(BitConverter.ToInt64(bytes, 0)), i) : IntPtr.Add(new IntPtr(BitConverter.ToInt32(bytes, 0)), i);
            }
            WriteProcessMemory(HandleProcess, Address, bytes, bytes.Length, out ptr);
        }
    }
}
