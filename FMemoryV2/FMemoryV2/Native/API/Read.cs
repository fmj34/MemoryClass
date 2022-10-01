using System;
using System.Runtime.InteropServices;
using static FMemoryV2.Native.Kernel32;

namespace FMemoryV2
{
    public partial class Memory
    {
        private T ByteArrayToStructure<T>(byte[] bytes) where T : struct
        {
            var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                return (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            }
            finally
            {
                handle.Free();
            }
        }

        public T ReadMemory<T>(IntPtr Address) where T : struct
        {
            IntPtr ptr;
            int size = Marshal.SizeOf(typeof(T));
            byte[] bytes = new byte[size];
            ReadProcessMemory(HandleProcess, Address, bytes, bytes.Length, out ptr);
            return ByteArrayToStructure<T>(bytes);
        }

        public T ReadMemory<T>(IntPtr Address, int[] Offsets) where T : struct
        {
            IntPtr ptr;
            int size = Marshal.SizeOf(typeof(T));
            byte[] bytes = new byte[size];

            foreach (int i in Offsets)
            {
                ReadProcessMemory(HandleProcess, Address, bytes, bytes.Length, out ptr);
                Address = (IntPtr.Size == 8) ? Address = IntPtr.Add(new IntPtr(BitConverter.ToInt64(bytes, 0)), i) : IntPtr.Add(new IntPtr(BitConverter.ToInt32(bytes, 0)), i);
            }
            ReadProcessMemory(HandleProcess, Address, bytes, bytes.Length, out ptr);
            return ByteArrayToStructure<T>(bytes);
        }
    }
}
