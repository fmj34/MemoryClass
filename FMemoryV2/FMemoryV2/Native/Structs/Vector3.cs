using System;
using System.Globalization;
using System.Runtime.InteropServices;

namespace FMemoryV2.Native.Structs
{
    public static class Vector3
    {
        public struct Vec3
        {
            public float X, Y, Z;

            public Vec3(float value)
            {
                X = value;
                Y = value;
                Z = value;
            }

            public Vec3(float x, float y, float z)
            {
                X = x;
                Y = y;
                Z = z;
            }

            public static readonly int SizeInBytes = Marshal.SizeOf<Vec3>();

            public static readonly Vec3 Zero = new Vec3(0);

            public static readonly Vec3 UnitX = new Vec3(1.0f, 0.0f, 0.0f);

            public static readonly Vec3 UnitY = new Vec3(0.0f, 1.0f, 0.0f);

            public static readonly Vec3 UnitZ = new Vec3(0.0f, 0.0f, 1.0f);

            public static readonly Vec3 One = new Vec3(1.0f, 1.0f, 1.0f);

            public static readonly Vec3 Up = new Vec3(0.0f, 1.0f, 0.0f);

            public static readonly Vec3 Down = new Vec3(0.0f, -1.0f, 0.0f);

            public static readonly Vec3 Left = new Vec3(-1.0f, 0.0f, 0.0f);

            public static readonly Vec3 Right = new Vec3(1.0f, 0.0f, 0.0f);

            public static readonly Vec3 ForwardRH = new Vec3(0.0f, 0.0f, -1.0f);

            public static readonly Vec3 ForwardLH = new Vec3(0.0f, 0.0f, 1.0f);

            public static readonly Vec3 BackwardRH = new Vec3(0.0f, 0.0f, 1.0f);

            public static readonly Vec3 BackwardLH = new Vec3(0.0f, 0.0f, -1.0f);

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

            public static Vec3 Add(Vec3 left, Vec3 right)
            {
                return new Vec3(left.X + right.X, left.Y + right.Y, left.Z + right.Z);
            }

            public static Vec3 Subtract(Vec3 left, Vec3 right)
            {
                return new Vec3(left.X - right.X, left.Y - right.Y, left.Z - right.Z);
            }

            public static Vec3 Multiply(Vec3 value, float scale)
            {
                return new Vec3(value.X * scale, value.Y * scale, value.Z * scale);
            }

            public static Vec3 Multiply(Vec3 left, Vec3 right)
            {
                return new Vec3(left.X * right.X, left.Y * right.Y, left.Z * right.Z);
            }

            public static Vec3 Divide(Vec3 value, float scale)
            {
                return new Vec3(value.X / scale, value.Y / scale, value.Z / scale);
            }

            public static Vec3 Divide(Vec3 left, Vec3 right)
            {
                return new Vec3(left.X / right.X, left.Y / right.Y, left.Z / right.Z);
            }

            public static Vec3 Negate(Vec3 value)
            {
                return new Vec3(-value.X, -value.Y, -value.Z);
            }

            public static Vec3 Abs(Vec3 value)
            {
                return new Vec3(
                    value.X > 0.0f ? value.X : -value.X,
                    value.Y > 0.0f ? value.Y : -value.Y,
                    value.Z > 0.0f ? value.Z : -value.Z);
            }


            public static Vec3 Clamp(Vec3 value, Vec3 min, Vec3 max)
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

                return new Vec3(x, y, z);
            }

            public static float Distance(Vec3 value1, Vec3 value2)
            {
                float x = value1.X - value2.X;
                float y = value1.Y - value2.Y;
                float z = value1.Z - value2.Z;

                return (float)Math.Sqrt((x * x) + (y * y) + (z * z));
            }

            public static float Dot(Vec3 left, Vec3 right)
            {
                return (left.X * right.X) + (left.Y * right.Y) + (left.Z * right.Z);
            }

            public static Vec3 operator +(Vec3 left, Vec3 right)
            {
                return new Vec3(left.X + right.X, left.Y + right.Y, left.Z + right.Z);
            }

            public static Vec3 operator *(Vec3 left, Vec3 right)
            {
                return new Vec3(left.X * right.X, left.Y * right.Y, left.Z * right.Z);
            }

            public static Vec3 operator +(Vec3 value)
            {
                return value;
            }

            public static Vec3 operator -(Vec3 left, Vec3 right)
            {
                return new Vec3(left.X - right.X, left.Y - right.Y, left.Z - right.Z);
            }

            public static Vec3 operator -(Vec3 value)
            {
                return new Vec3(-value.X, -value.Y, -value.Z);
            }

            public static Vec3 operator *(float scale, Vec3 value)
            {
                return new Vec3(value.X * scale, value.Y * scale, value.Z * scale);
            }

            public static Vec3 operator *(Vec3 value, float scale)
            {
                return new Vec3(value.X * scale, value.Y * scale, value.Z * scale);
            }

            public static Vec3 operator /(Vec3 value, float scale)
            {
                return new Vec3(value.X / scale, value.Y / scale, value.Z / scale);
            }

            public static Vec3 operator /(float scale, Vec3 value)
            {
                return new Vec3(scale / value.X, scale / value.Y, scale / value.Z);
            }

            public static Vec3 operator /(Vec3 value, Vec3 scale)
            {
                return new Vec3(value.X / scale.X, value.Y / scale.Y, value.Z / scale.Z);
            }

            public static Vec3 operator +(Vec3 value, float scalar)
            {
                return new Vec3(value.X + scalar, value.Y + scalar, value.Z + scalar);
            }

            public static Vec3 operator +(float scalar, Vec3 value)
            {
                return new Vec3(scalar + value.X, scalar + value.Y, scalar + value.Z);
            }

            public static Vec3 operator -(Vec3 value, float scalar)
            {
                return new Vec3(value.X - scalar, value.Y - scalar, value.Z - scalar);
            }

            public static Vec3 operator -(float scalar, Vec3 value)
            {
                return new Vec3(scalar - value.X, scalar - value.Y, scalar - value.Z);
            }

            public static bool operator ==(Vec3 v1, Vec3 v2)
            {
                return v1.X == v2.X && v1.Y == v2.Y && v1.Z == v2.Z;
            }

            public static bool operator !=(Vec3 v1, Vec3 v2)
            {
                return v1.X != v2.X || v1.Y != v2.Y || v1.Z != v2.Z;
            }

            public override string ToString()
            {
                return string.Format(CultureInfo.CurrentCulture, "X:{0} Y:{1} Z:{2}", X, Y, Z);
            }
        }
    }
}
