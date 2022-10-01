using System;
using System.Globalization;
using System.Runtime.InteropServices;

namespace FMemoryV2.Native.Structs
{
    public static class Vector2
    {
        public struct Vec2
        {
            public float X, Y;

            public Vec2(float value)
            {
                X = value;
                Y = value;
            }

            public Vec2(float x, float y)
            {
                X = x;
                Y = y;
            }

            public static readonly int SizeInBytes = Marshal.SizeOf<Vec2>();

            public static readonly Vec2 Zero = new Vec2(0);

            public static readonly Vec2 UnitX = new Vec2(1.0f, 0.0f);

            public static readonly Vec2 UnitY = new Vec2(0.0f, 1.0f);

            public static readonly Vec2 One = new Vec2(1.0f, 1.0f);

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

            public static Vec2 Add(Vec2 left, Vec2 right)
            {
                return new Vec2(left.X + right.X, left.Y + right.Y);
            }

            public static Vec2 Subtract(Vec2 left, Vec2 right)
            {
                return new Vec2(left.X - right.X, left.Y - right.Y);
            }

            public static Vec2 Multiply(Vec2 value, float scale)
            {
                return new Vec2(value.X * scale, value.Y * scale);
            }

            public static Vec2 Multiply(Vec2 left, Vec2 right)
            {
                return new Vec2(left.X * right.X, left.Y * right.Y);
            }

            public static Vec2 Divide(Vec2 value, float scale)
            {
                return new Vec2(value.X / scale, value.Y / scale);
            }

            public static Vec2 Divide(Vec2 left, Vec2 right)
            {
                return new Vec2(left.X / right.X, left.Y / right.Y);
            }

            public static Vec2 Negate(Vec2 value)
            {
                return new Vec2(-value.X, -value.Y);
            }

            public static Vec2 Abs(Vec2 value)
            {
                return new Vec2(
                    value.X > 0.0f ? value.X : -value.X,
                    value.Y > 0.0f ? value.Y : -value.Y);
            }

            public static Vec2 Clamp(Vec2 value, Vec2 min, Vec2 max)
            {
                float x = value.X;
                x = (x > max.X) ? max.X : x;
                x = (x < min.X) ? min.X : x;

                float y = value.Y;
                y = (y > max.Y) ? max.Y : y;
                y = (y < min.Y) ? min.Y : y;

                return new Vec2(x, y);
            }

            public static float Distance(Vec2 value1, Vec2 value2)
            {
                float x = value1.X - value2.X;
                float y = value1.Y - value2.Y;

                return (float)Math.Sqrt((x * x) + (y * y));
            }

            public static float Dot(Vec2 left, Vec2 right)
            {
                return (left.X * right.X) + (left.Y * right.Y);
            }

            public static Vec2 operator +(Vec2 left, Vec2 right)
            {
                return new Vec2(left.X + right.X, left.Y + right.Y);
            }

            public static Vec2 operator *(Vec2 left, Vec2 right)
            {
                return new Vec2(left.X * right.X, left.Y * right.Y);
            }

            public static Vec2 operator +(Vec2 value)
            {
                return value;
            }

            public static Vec2 operator -(Vec2 left, Vec2 right)
            {
                return new Vec2(left.X - right.X, left.Y - right.Y);
            }

            public static Vec2 operator -(Vec2 value)
            {
                return new Vec2(-value.X, -value.Y);
            }

            public static Vec2 operator *(float scale, Vec2 value)
            {
                return new Vec2(value.X * scale, value.Y * scale);
            }

            public static Vec2 operator *(Vec2 value, float scale)
            {
                return new Vec2(value.X * scale, value.Y * scale);
            }

            public static Vec2 operator /(Vec2 value, float scale)
            {
                return new Vec2(value.X / scale, value.Y / scale);
            }

            public static Vec2 operator /(float scale, Vec2 value)
            {
                return new Vec2(scale / value.X, scale / value.Y);
            }

            public static Vec2 operator /(Vec2 value, Vec2 scale)
            {
                return new Vec2(value.X / scale.X, value.Y / scale.Y);
            }

            public static Vec2 operator +(Vec2 value, float scalar)
            {
                return new Vec2(value.X + scalar, value.Y + scalar);
            }

            public static Vec2 operator +(float scalar, Vec2 value)
            {
                return new Vec2(scalar + value.X, scalar + value.Y);
            }

            public static Vec2 operator -(Vec2 value, float scalar)
            {
                return new Vec2(value.X - scalar, value.Y - scalar);
            }

            public static Vec2 operator -(float scalar, Vec2 value)
            {
                return new Vec2(scalar - value.X, scalar - value.Y);
            }

            public static bool operator ==(Vec2 v1, Vec2 v2)
            {
                return v1.X == v2.X && v1.Y == v2.Y;
            }

            public static bool operator !=(Vec2 v1, Vec2 v2)
            {
                return v1.X != v2.X || v1.Y != v2.Y;
            }

            public override string ToString()
            {
                return string.Format(CultureInfo.CurrentCulture, "X:{0} Y:{1}", X, Y);
            }
        }
    }
}
