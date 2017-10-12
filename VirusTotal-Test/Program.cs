using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusTotal_Test
{
    class Program
    {
        private static readonly string API_KEY = Environment.GetEnvironmentVariable("VT_API_KEY");

        static void Main(string[] args)
        {
            VirusTotalHandle handle = new VirusTotalHandle(API_KEY, true);
            Console.WriteLine(handle.isInitialised());
            Console.ReadKey();
        }
    }
}
