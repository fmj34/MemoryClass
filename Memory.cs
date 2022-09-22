public class Memory
    {
        #region Imports

        [DllImport("Kernel32.dll")]
        static extern bool ReadProcessMemory(
           IntPtr hProcess,
           IntPtr lpBaseAddress,
           [Out] byte[] lpBuffer,
           int nSize,
           IntPtr lpNumberOfBytesRead
           );

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int size,
            IntPtr lpNumberOfBytesWritten
            );

        [DllImport("user32.dll")]
        static extern short GetAsyncKeyState(
            Keys vKeys
            );

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(
            uint dwDesiredAccess, 
            int bInheritHandle, 
            int dwProcessId
            );

        [DllImport("kernel32.dll")]
        static extern int CloseHandle(
            IntPtr hObject
            );

        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAllocEx(
            IntPtr hProcess, 
            IntPtr lpAddres, 
            int dwSize, 
            uint flAllocationType, 
            uint flProtect
            );

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool VirtualFreeEx(
            IntPtr hProcess, 
            IntPtr lpAddress,
            int dwSize, 
            int dwFreeType
            );

        #endregion
        #region Specials

        public int SizeOf(byte[] Buffer)
        {
            return Buffer.Length;
        }

        public int SizeOf(int[] Buffer)
        {
            return Buffer.Length;
        }

        public int SizeOf(string Buffer)
        {
            return Buffer.Length;
        }

        public int SizeOf(string[] Buffer)
        {
            return Buffer.Length;
        }

        public bool FindBytes(IntPtr Address, ref byte[] Buffer)
        {
            return ReadProcessMemory(Handle, Address, Buffer, Buffer.Length, IntPtr.Zero) ? true : false;
        }

        public int PatternScan(string module_name, string signature)
        {
            byte[] ModuleBuffer = null;
            int ModuleAddress = -1;
            foreach (ProcessModule process_module in TargetProcess.Modules)
            {
                if (process_module.ModuleName == module_name)
                {
                    ModuleBuffer = new byte[process_module.ModuleMemorySize];
                    ModuleAddress = (Int32)process_module.BaseAddress;
                }
            }

            if (ModuleAddress == -1 || ModuleBuffer == null)
                return -1;

            byte[] pattern = Transformation.SignatureToPattern(signature);
            string mask = Transformation.GetSignatureMask(signature);

            if (FindBytes((IntPtr)ModuleAddress, ref ModuleBuffer))
            {
                for (int i = 0; i < ModuleBuffer.Length; i++)
                {
                    bool IsFounded = false;

                    for (int a = 0; a < pattern.Length; a++)
                    {
                        if (mask[a] == '?')
                            continue;

                        if (pattern[a] == ModuleBuffer[i + a])
                            IsFounded = true;
                    }

                    if (!IsFounded) continue;
                    return i;
                }
            }

            return -1;
        }

        public IntPtr FindDMAAddy(IntPtr ptr, int[] offsets)
        {
            var buffer = new byte[IntPtr.Size];
            foreach (int i in offsets)
            {
                ReadProcessMemory(Handle, ptr, buffer, buffer.Length, IntPtr.Zero);

                ptr = (IntPtr.Size == 4)
                ? IntPtr.Add(new IntPtr(BitConverter.ToInt32(buffer, 0)), i)
                : ptr = IntPtr.Add(new IntPtr(BitConverter.ToInt64(buffer, 0)), i);
            }
            return ptr;
        }

        public IntPtr FindCodeCave(IntPtr Address, int Size)
        {
            IntPtr hSnap = OpenProcess(0x38, 1, TargetProcess.Id);
            IntPtr buffer = VirtualAllocEx(Handle, Address, Size, 0x1000 | 0x2000, 0x40);
            CloseHandle(hSnap);
            return buffer;
        }

        public void WriteToCodeCave(IntPtr Address, byte[] Codes)
        {
            IntPtr hSnap = OpenProcess(0x38, 1, TargetProcess.Id);
            WriteMemory(Address, Codes);
        }

        public void WriteToCodeCave(IntPtr Address, int[] Offsets, byte[] Codes)
        {
            IntPtr hSnap = OpenProcess(0x38, 1, TargetProcess.Id);
            WriteMemory(Address, Offsets, Codes);
        }

        public bool CloseCodeCave(IntPtr Address)
        {
            IntPtr hSnap = OpenProcess(0x38, 1, TargetProcess.Id);
            return VirtualFreeEx(Handle, Address, 0, 0x00008000);
        }

        #region Helpers

        class Transformation
        {
            public static byte[] SignatureToPattern(string sig)
            {
                string[] parts = sig.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                byte[] patternArray = new byte[parts.Length];

                for (int i = 0; i < parts.Length; i++)
                {
                    if (parts[i] == "?")
                    {
                        patternArray[i] = 0;
                        continue;
                    }

                    if (!byte.TryParse(parts[i], System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.DefaultThreadCurrentCulture, out patternArray[i]))
                    {
                        throw new Exception();
                    }
                }

                return patternArray;
            }

            public static string GetSignatureMask(string sig)
            {
                string[] parts = sig.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                string mask = "";

                for (int i = 0; i < parts.Length; i++)
                {
                    if (parts[i] == "?")
                    {
                        mask += "?";
                    }
                    else
                    {
                        mask += "x";
                    }
                }

                return mask;
            }

            public static string CutString(string mystring)
            {
                char[] chArray = mystring.ToCharArray();
                string str = "";
                for (int i = 0; i < mystring.Length; i++)
                {
                    if ((chArray[i] == ' ') && (chArray[i + 1] == ' '))
                    {
                        return str;
                    }
                    if (chArray[i] == '\0')
                    {
                        return str;
                    }
                    str = str + chArray[i].ToString();
                }
                return mystring.TrimEnd(new char[] { '0' });
            }

            public static float[] ConvertToFloatArray(byte[] bytes)
            {
                if (bytes.Length % 4 != 0) throw new ArgumentException();

                float[] floats = new float[bytes.Length / 4];

                for (int i = 0; i < floats.Length; i++) floats[i] = BitConverter.ToSingle(bytes, i * 4);

                return floats;
            }

            public static T ByteArrayToStructure<T>(byte[] bytes) where T : struct
            {
                GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);

                try
                {
                    return (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
                }
                finally
                {
                    handle.Free();
                }
            }

            public static byte[] StructureToByteArray(object obj)
            {
                int length = Marshal.SizeOf(obj);

                byte[] array = new byte[length];

                IntPtr pointer = Marshal.AllocHGlobal(length);

                Marshal.StructureToPtr(obj, pointer, true);
                Marshal.Copy(pointer, array, 0, length);
                Marshal.FreeHGlobal(pointer);

                return array;
            }
        }

        #endregion

        public bool IsKeyDown(Keys Key)
        {
            return (GetAsyncKeyState(Key) < 0);
        }

        #endregion
        #region Vectors

        public static class Vectors
        {
            public struct Vector2
            {
                public float X, Y;

                public Vector2(float value)
                {
                    X = value;
                    Y = value;
                }

                public Vector2(float x, float y)
                {
                    X = x;
                    Y = y;
                }

                public static readonly int SizeInBytes = Marshal.SizeOf<Vector2>();

                public static readonly Vector2 Zero = new Vector2(0);

                public static readonly Vector2 UnitX = new Vector2(1.0f, 0.0f);

                public static readonly Vector2 UnitY = new Vector2(0.0f, 1.0f);

                public static readonly Vector2 One = new Vector2(1.0f, 1.0f);

                public bool IsZero
                {
                    get { return X == 0 && Y == 0; }
                }

                public float Length()
                {
                    return (float)Math.Sqrt((X * X) + (Y * Y));
                }

                public float LengthSquared()
                {
                    return (X * X) + (Y * Y);
                }

                public void Normalize()
                {
                    float length = Length();
                    if (length != 0)
                    {
                        float inv = 1.0f / length;
                        X *= inv;
                        Y *= inv;
                    }
                }

                public float[] ToArray()
                {
                    return new float[] { X, Y };
                }

                public static Vector2 Add(Vector2 left, Vector2 right)
                {
                    return new Vector2(left.X + right.X, left.Y + right.Y);
                }

                public static Vector2 Subtract(Vector2 left, Vector2 right)
                {
                    return new Vector2(left.X - right.X, left.Y - right.Y);
                }

                public static Vector2 Multiply(Vector2 value, float scale)
                {
                    return new Vector2(value.X * scale, value.Y * scale);
                }

                public static Vector2 Multiply(Vector2 left, Vector2 right)
                {
                    return new Vector2(left.X * right.X, left.Y * right.Y);
                }

                public static Vector2 Divide(Vector2 value, float scale)
                {
                    return new Vector2(value.X / scale, value.Y / scale);
                }

                public static Vector2 Divide(Vector2 left, Vector2 right)
                {
                    return new Vector2(left.X / right.X, left.Y / right.Y);
                }

                public static Vector2 Negate(Vector2 value)
                {
                    return new Vector2(-value.X, -value.Y);
                }

                public static Vector2 Abs(Vector2 value)
                {
                    return new Vector2(
                        value.X > 0.0f ? value.X : -value.X,
                        value.Y > 0.0f ? value.Y : -value.Y);
                }
    
                public static Vector2 Clamp(Vector2 value, Vector2 min, Vector2 max)
                {
                    float x = value.X;
                    x = (x > max.X) ? max.X : x;
                    x = (x < min.X) ? min.X : x;

                    float y = value.Y;
                    y = (y > max.Y) ? max.Y : y;
                    y = (y < min.Y) ? min.Y : y;

                    return new Vector2(x, y);
                }

                public static float Distance(Vector2 value1, Vector2 value2)
                {
                    float x = value1.X - value2.X;
                    float y = value1.Y - value2.Y;

                    return (float)Math.Sqrt((x * x) + (y * y));
                }

                public static float Dot(Vector2 left, Vector2 right)
                {
                    return (left.X * right.X) + (left.Y * right.Y);
                }

                public static Vector2 operator +(Vector2 left, Vector2 right)
                {
                    return new Vector2(left.X + right.X, left.Y + right.Y);
                }

                public static Vector2 operator *(Vector2 left, Vector2 right)
                {
                    return new Vector2(left.X * right.X, left.Y * right.Y);
                }

                public static Vector2 operator +(Vector2 value)
                {
                    return value;
                }

                public static Vector2 operator -(Vector2 left, Vector2 right)
                {
                    return new Vector2(left.X - right.X, left.Y - right.Y);
                }

                public static Vector2 operator -(Vector2 value)
                {
                    return new Vector2(-value.X, -value.Y);
                }

                public static Vector2 operator *(float scale, Vector2 value)
                {
                    return new Vector2(value.X * scale, value.Y * scale);
                }

                public static Vector2 operator *(Vector2 value, float scale)
                {
                    return new Vector2(value.X * scale, value.Y * scale);
                }

                public static Vector2 operator /(Vector2 value, float scale)
                {
                    return new Vector2(value.X / scale, value.Y / scale);
                }

                public static Vector2 operator /(float scale, Vector2 value)
                {
                    return new Vector2(scale / value.X, scale / value.Y);
                }

                public static Vector2 operator /(Vector2 value, Vector2 scale)
                {
                    return new Vector2(value.X / scale.X, value.Y / scale.Y);
                }

                public static Vector2 operator +(Vector2 value, float scalar)
                {
                    return new Vector2(value.X + scalar, value.Y + scalar);
                }

                public static Vector2 operator +(float scalar, Vector2 value)
                {
                    return new Vector2(scalar + value.X, scalar + value.Y);
                }

                public static Vector2 operator -(Vector2 value, float scalar)
                {
                    return new Vector2(value.X - scalar, value.Y - scalar);
                }

                public static Vector2 operator -(float scalar, Vector2 value)
                {
                    return new Vector2(scalar - value.X, scalar - value.Y);
                }

                public static bool operator ==(Vector2 v1, Vector2 v2)
                {
                    return v1.X == v2.X && v1.Y == v2.Y;
                }

                public static bool operator !=(Vector2 v1, Vector2 v2)
                {
                    return v1.X != v2.X || v1.Y != v2.Y;
                }

                public override string ToString()
                {
                    return string.Format(CultureInfo.CurrentCulture, "X:{0} Y:{1}", X, Y);
                }
            }

            public struct Vector3
            {
                public float X, Y, Z;

                public Vector3(float value)
                {
                    X = value;
                    Y = value;
                    Z = value;
                }

                public Vector3(float x, float y, float z)
                {
                    X = x;
                    Y = y;
                    Z = z;
                }

                public static readonly int SizeInBytes = Marshal.SizeOf<Vector3>();

                public static readonly Vector3 Zero = new Vector3(0);

                public static readonly Vector3 UnitX = new Vector3(1.0f, 0.0f, 0.0f);

                public static readonly Vector3 UnitY = new Vector3(0.0f, 1.0f, 0.0f);

                public static readonly Vector3 UnitZ = new Vector3(0.0f, 0.0f, 1.0f);

                public static readonly Vector3 One = new Vector3(1.0f, 1.0f, 1.0f);

                public static readonly Vector3 Up = new Vector3(0.0f, 1.0f, 0.0f);

                public static readonly Vector3 Down = new Vector3(0.0f, -1.0f, 0.0f);

                public static readonly Vector3 Left = new Vector3(-1.0f, 0.0f, 0.0f);

                public static readonly Vector3 Right = new Vector3(1.0f, 0.0f, 0.0f);

                public static readonly Vector3 ForwardRH = new Vector3(0.0f, 0.0f, -1.0f);

                public static readonly Vector3 ForwardLH = new Vector3(0.0f, 0.0f, 1.0f);

                public static readonly Vector3 BackwardRH = new Vector3(0.0f, 0.0f, 1.0f);

                public static readonly Vector3 BackwardLH = new Vector3(0.0f, 0.0f, -1.0f);

                public bool IsZero
                {
                    get { return X == 0 && Y == 0 && Z == 0; }
                }

                public float Length()
                {
                    return (float)Math.Sqrt((X * X) + (Y * Y) + (Z * Z));
                }

                public float LengthSquared()
                {
                    return (X * X) + (Y * Y) + (Z * Z);
                }

                public void Normalize()
                {
                    float length = Length();
                    if (length != 0)
                    {
                        float inv = 1.0f / length;
                        X *= inv;
                        Y *= inv;
                        Z *= inv;
                    }
                }

                public float[] ToArray()
                {
                    return new float[] { X, Y, Z };
                }

                public static Vector3 Add(Vector3 left, Vector3 right)
                {
                    return new Vector3(left.X + right.X, left.Y + right.Y, left.Z + right.Z);
                }

                public static Vector3 Subtract(Vector3 left, Vector3 right)
                {
                    return new Vector3(left.X - right.X, left.Y - right.Y, left.Z - right.Z);
                }

                public static Vector3 Multiply(Vector3 value, float scale)
                {
                    return new Vector3(value.X * scale, value.Y * scale, value.Z * scale);
                }

                public static Vector3 Multiply(Vector3 left, Vector3 right)
                {
                    return new Vector3(left.X * right.X, left.Y * right.Y, left.Z * right.Z);
                }

                public static Vector3 Divide(Vector3 value, float scale)
                {
                    return new Vector3(value.X / scale, value.Y / scale, value.Z / scale);
                }

                public static Vector3 Divide(Vector3 left, Vector3 right)
                {
                    return new Vector3(left.X / right.X, left.Y / right.Y, left.Z / right.Z);
                }

                public static Vector3 Negate(Vector3 value)
                {
                    return new Vector3(-value.X, -value.Y, -value.Z);
                }

                public static Vector3 Abs(Vector3 value)
                {
                    return new Vector3(
                        value.X > 0.0f ? value.X : -value.X,
                        value.Y > 0.0f ? value.Y : -value.Y,
                        value.Z > 0.0f ? value.Z : -value.Z);
                }


                public static Vector3 Clamp(Vector3 value, Vector3 min, Vector3 max)
                {
                    float x = value.X;
                    x = (x > max.X) ? max.X : x;
                    x = (x < min.X) ? min.X : x;

                    float y = value.Y;
                    y = (y > max.Y) ? max.Y : y;
                    y = (y < min.Y) ? min.Y : y;

                    float z = value.Z;
                    z = (z > max.Z) ? max.Z : z;
                    z = (z < min.Z) ? min.Z : z;

                    return new Vector3(x, y, z);
                }

                public static float Distance(Vector3 value1, Vector3 value2)
                {
                    float x = value1.X - value2.X;
                    float y = value1.Y - value2.Y;
                    float z = value1.Z - value2.Z;

                    return (float)Math.Sqrt((x * x) + (y * y) + (z * z));
                }

                public static float Dot(Vector3 left, Vector3 right)
                {
                    return (left.X * right.X) + (left.Y * right.Y) + (left.Z * right.Z);
                }

                public static Vector3 operator +(Vector3 left, Vector3 right)
                {
                    return new Vector3(left.X + right.X, left.Y + right.Y, left.Z + right.Z);
                }

                public static Vector3 operator *(Vector3 left, Vector3 right)
                {
                    return new Vector3(left.X * right.X, left.Y * right.Y, left.Z * right.Z);
                }

                public static Vector3 operator +(Vector3 value)
                {
                    return value;
                }

                public static Vector3 operator -(Vector3 left, Vector3 right)
                {
                    return new Vector3(left.X - right.X, left.Y - right.Y, left.Z - right.Z);
                }

                public static Vector3 operator -(Vector3 value)
                {
                    return new Vector3(-value.X, -value.Y, -value.Z);
                }

                public static Vector3 operator *(float scale, Vector3 value)
                {
                    return new Vector3(value.X * scale, value.Y * scale, value.Z * scale);
                }

                public static Vector3 operator *(Vector3 value, float scale)
                {
                    return new Vector3(value.X * scale, value.Y * scale, value.Z * scale);
                }

                public static Vector3 operator /(Vector3 value, float scale)
                {
                    return new Vector3(value.X / scale, value.Y / scale, value.Z / scale);
                }

                public static Vector3 operator /(float scale, Vector3 value)
                {
                    return new Vector3(scale / value.X, scale / value.Y, scale / value.Z);
                }

                public static Vector3 operator /(Vector3 value, Vector3 scale)
                {
                    return new Vector3(value.X / scale.X, value.Y / scale.Y, value.Z / scale.Z);
                }

                public static Vector3 operator +(Vector3 value, float scalar)
                {
                    return new Vector3(value.X + scalar, value.Y + scalar, value.Z + scalar);
                }

                public static Vector3 operator +(float scalar, Vector3 value)
                {
                    return new Vector3(scalar + value.X, scalar + value.Y, scalar + value.Z);
                }

                public static Vector3 operator -(Vector3 value, float scalar)
                {
                    return new Vector3(value.X - scalar, value.Y - scalar, value.Z - scalar);
                }

                public static Vector3 operator -(float scalar, Vector3 value)
                {
                    return new Vector3(scalar - value.X, scalar - value.Y, scalar - value.Z);
                }

                public static bool operator ==(Vector3 v1, Vector3 v2)
                {
                    return v1.X == v2.X && v1.Y == v2.Y && v1.Z == v2.Z;
                }

                public static bool operator !=(Vector3 v1, Vector3 v2)
                {
                    return v1.X != v2.X || v1.Y != v2.Y || v1.Z != v2.Z;
                }

                public override string ToString()
                {
                    return string.Format(CultureInfo.CurrentCulture, "X:{0} Y:{1} Z:{2}", X, Y, Z);
                }
            }
        }

        #endregion

        public Process TargetProcess;

        public IntPtr BaseAddress;
        public IntPtr Handle;

        public bool GetProcess(string ProcessName)
        {
            Process[] processByName = Process.GetProcessesByName(ProcessName);

            if (processByName.Length == 0)
            {
                return false;
            }
            else
            {
                TargetProcess = processByName[0];
                Handle = TargetProcess.Handle;
                BaseAddress = TargetProcess.MainModule.BaseAddress;

                if (Handle.ToInt64() == 0 || BaseAddress.ToInt64() == 0)
                {
                    return false;
                }
                return true;
            }
        }

        public IntPtr GetModuleBaseAddress(string ModuleName)
        {
            foreach (ProcessModule processModule in TargetProcess.Modules)
            {
                if (processModule.ModuleName == ModuleName)
                {
                    return processModule.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }

        public byte[] ReadMemory(IntPtr Address, int Size)
        {
            byte[] buffer = new byte[Size];
            ReadProcessMemory(Handle, Address, buffer, SizeOf(buffer), IntPtr.Zero);
            return buffer;
        }

        public byte[] ReadMemory(IntPtr Address, int[] Offsets, int Size)
        {
            byte[] buffer = new byte[Size];
            ReadProcessMemory(Handle, FindDMAAddy(Address, Offsets), buffer, SizeOf(buffer), IntPtr.Zero);
            return buffer;
        }

        public void WriteMemory(IntPtr Address, byte[] NewBytes)
        {
            WriteProcessMemory(Handle, Address, NewBytes, SizeOf(NewBytes), IntPtr.Zero);
        }

        public void WriteMemory(IntPtr Address, int[] Offsets, byte[] NewBytes)
        {
            WriteProcessMemory(Handle, FindDMAAddy(Address, Offsets), NewBytes, SizeOf(NewBytes), IntPtr.Zero);
        }

        // Read Memory Functions
        public byte ReadByte(IntPtr Address)
        {
            return ReadMemory(Address, 1)[0];
        }

        public byte ReadByte(IntPtr Address, int[] Offsets)
        {
            return ReadMemory(Address, Offsets, 1)[0];
        }

        public byte[] ReadBytes(IntPtr Address, int Size)
        {
            return ReadMemory(Address, Size);
        }

        public byte[] ReadBytes(IntPtr Address, int[] Offsets, int Size)
        {
            return ReadMemory(Address, Offsets, Size);
        }

        public short ReadInt16(IntPtr Address)
        {
            return BitConverter.ToInt16(ReadMemory(Address, 2), 0);
        }

        public short ReadInt16(IntPtr Address, int[] Offsets)
        {
            return BitConverter.ToInt16(ReadMemory(Address, Offsets, 2), 0);
        }

        public int ReadInt32(IntPtr Address)
        {
            return BitConverter.ToInt32(ReadMemory(Address, 4), 0);
        }

        public int ReadInt32(IntPtr Address, int[] Offsets)
        {
            return BitConverter.ToInt32(ReadMemory(Address, Offsets, 4), 0);
        }

        public long ReadInt64(IntPtr Address)
        {
            return BitConverter.ToInt64(ReadMemory(Address, 8), 0);
        }

        public long ReadInt64(IntPtr Address, int[] Offsets)
        {
            return BitConverter.ToInt64(ReadMemory(Address, Offsets, 8), 0);
        }

        public float ReadFloat(IntPtr Address)
        {
            return BitConverter.ToSingle(ReadMemory(Address, 4), 0);
        }

        public float ReadFloat(IntPtr Address, int[] Offsets)
        {
            return BitConverter.ToSingle(ReadMemory(Address, Offsets, 4), 0);
        }

        public double ReadDouble(IntPtr Address)
        {
            return BitConverter.ToDouble(ReadMemory(Address, 8), 0);
        }

        public double ReadDouble(IntPtr Address, int[] Offsets)
        {
            return BitConverter.ToDouble(ReadMemory(Address, Offsets, 8), 0);
        }

        public Vector2 ReadVector2(IntPtr Address)
        {
            byte[] buffer = ReadMemory(Address, 0x4 * 2);
            float[] floatArray = new float[buffer.Length / 4];
            Buffer.BlockCopy(buffer, 0, floatArray, 0, buffer.Length);
            return new Vector2(floatArray[0], floatArray[1]);
        }

        public Vector2 ReadVector2(IntPtr Address, int[] Offsets)
        {
            byte[] buffer = ReadMemory(Address, Offsets, 0x4 * 2);
            float[] floatArray = new float[buffer.Length / 4];
            Buffer.BlockCopy(buffer, 0, floatArray, 0, buffer.Length);
            return new Vector2(floatArray[0], floatArray[1]);
        }

        public Vector3 ReadVector3(IntPtr Address)
        {
            byte[] buffer = ReadMemory(Address, 0x4 * 3);
            float[] floatArray = new float[buffer.Length / 4];
            Buffer.BlockCopy(buffer, 0, floatArray, 0, buffer.Length);
            return new Vector3(floatArray[0], floatArray[1], floatArray[2]);
        }

        public Vector3 ReadVector3(IntPtr Address, int[] Offsets)
        {
            byte[] buffer = ReadMemory(Address, Offsets, 0x4 * 3);
            float[] floatArray = new float[buffer.Length / 4];
            Buffer.BlockCopy(buffer, 0, floatArray, 0, buffer.Length);
            return new Vector3(floatArray[0], floatArray[1], floatArray[2]);
        }

        // Write Memory Functions
        public void WriteByte(IntPtr Address, byte Value)
        {
            WriteMemory(Address, BitConverter.GetBytes(Value));
        }

        public void WriteByte(IntPtr Address, int[] Offsets, byte Value)
        {
            WriteMemory(Address, Offsets, BitConverter.GetBytes(Value));
        }

        public void WriteBytes(IntPtr Address, byte[] Value)
        {
            WriteMemory(Address, Value);
        }

        public void WriteBytes(IntPtr Address, int[] Offsets, byte[] Value)
        {
            WriteMemory(Address, Offsets, Value);
        }

        public void WriteInt16(IntPtr Address, short Value)
        {
            WriteMemory(Address, BitConverter.GetBytes(Value));
        }

        public void WriteInt16(IntPtr Address, int[] Offsets, short Value)
        {
            WriteMemory(Address, Offsets, BitConverter.GetBytes(Value));
        }

        public void WriteInt32(IntPtr Address, int Value)
        {
            WriteMemory(Address, BitConverter.GetBytes(Value));
        }

        public void WriteInt32(IntPtr Address, int[] Offsets, int Value)
        {
            WriteMemory(Address, Offsets, BitConverter.GetBytes(Value));
        }

        public void WriteInt64(IntPtr Address, long Value)
        {
            WriteMemory(Address, BitConverter.GetBytes(Value));
        }

        public void WriteInt64(IntPtr Address, int[] Offsets, long Value)
        {
            WriteMemory(Address, Offsets, BitConverter.GetBytes(Value));
        }

        public void WriteFloat(IntPtr Address, float Value)
        {
            WriteMemory(Address, BitConverter.GetBytes(Value));
        }

        public void WriteFloat(IntPtr Address, int[] Offsets, float Value)
        {
            WriteMemory(Address, Offsets, BitConverter.GetBytes(Value));
        }

        public void WriteDouble(IntPtr Address, double Value)
        {
            WriteMemory(Address, BitConverter.GetBytes(Value));
        }

        public void WriteDouble(IntPtr Address, int[] Offsets, double Value)
        {
            WriteMemory(Address, Offsets, BitConverter.GetBytes(Value));
        }

        public void WriteVector2(IntPtr Address, Vector2 Value)
        {
            byte[] buffer = new byte[Vector2.SizeInBytes];
            Buffer.BlockCopy(BitConverter.GetBytes(Value.X), 0, buffer, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(Value.Y), 0, buffer, 4, 4);
            WriteMemory(Address, buffer);
        }

        public void WriteVector2(IntPtr Address, int[] Offsets, Vector2 Value)
        {
            byte[] buffer = new byte[Vector2.SizeInBytes];
            Buffer.BlockCopy(BitConverter.GetBytes(Value.X), 0, buffer, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(Value.Y), 0, buffer, 4, 4);
            WriteMemory(Address, Offsets, buffer);
        }

        public void WriteVector3(IntPtr Address, Vector3 Value)
        {
            byte[] buffer = new byte[Vector3.SizeInBytes];
            Buffer.BlockCopy(BitConverter.GetBytes(Value.X), 0, buffer, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(Value.Y), 0, buffer, 4, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(Value.Z), 0, buffer, 8, 4);
            WriteMemory(Address, buffer);
        }

        public void WriteVector3(IntPtr Address, int[] Offsets, Vector3 Value)
        {
            byte[] buffer = new byte[Vector3.SizeInBytes];
            Buffer.BlockCopy(BitConverter.GetBytes(Value.X), 0, buffer, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(Value.Y), 0, buffer, 4, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(Value.Z), 0, buffer, 8, 4);
            WriteMemory(Address, Offsets, buffer);
        }
    }
