using System;
using System.Threading;
using FMemoryV2;

namespace _32BitGameTest
{
    class Program
    {
        public class Offsets
        {
            public static int PlayerBase = 0x0018AC00;
            public static int Health = 0xEC;
        }

        static void Main(string[] args)
        {
            var fmemapi = new Memory();

            while (true)
            {
                if (fmemapi.FindProcess("ac_client"))
                {
                    var Health = fmemapi.ReadMemory<Int32>(fmemapi.BaseAddress + Offsets.PlayerBase, new int[] { Offsets.Health });
                    Console.WriteLine(Health);
                    Thread.Sleep(1000);
                }
            }
        }
    }
}
