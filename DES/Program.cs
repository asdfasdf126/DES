using System;
using System.Diagnostics;

namespace DES
{
    class Program
    {
        static void Main(string[] args)
        {
            Stopwatch sw = new Stopwatch();
            DESEncryption des = new DESEncryption();
            String text = "AABBCCDD11223344"; //16 bit hex
            String key = "71322185720770FF"; //16 bit hex

            Console.WriteLine("Plain text: {0}\nKey: {1}\n", text, key);

            sw.Start();
            des.setText(text);
            des.setKey(key);
            des.encode();
            sw.Stop();

            text = des.getText();
            Console.WriteLine("Encoded text: {0}\nTime Elapsed: {1} ms\n", text, sw.ElapsedMilliseconds);

            sw.Start();
            des.setText(text);
            des.setKey(key);
            des.decode();
            sw.Stop();

            text = des.getText();
            Console.WriteLine("Decoded text: {0}\nTime Elapsed: {1} ms\n", text, sw.ElapsedMilliseconds);

            Console.Write("\nFinished!");
            Console.ReadKey();
        }
    }
}
