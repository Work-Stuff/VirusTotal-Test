using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Net.Http;
using VirusTotal_Test;
using Nito.AsyncEx;

namespace TestApp
{
    class Program
    {
        private static readonly string API_KEY = Environment.GetEnvironmentVariable("VT_API_KEY");

        static void Main(string[] args)
        {
            AsyncContext.Run(() => MainAsync(args));
        }

        static async void MainAsync(string[] args)
        {
            VirusTotalHandle handle = new VirusTotalHandle(API_KEY, onRequestSending, onResponseRecieved, onRawResponseRecieved, true);
            Console.WriteLine("Is API Initialised: " + handle.IsInitialised());
            ScanResponseData document = await handle.ScanFileAsync("TestFiles/TestDocument.docx");
            Console.WriteLine(document.VerboseMessage);
            Console.ReadKey();
        }

        static async void onRequestSending(HttpRequestMessage request)
        {
            Console.WriteLine("Request Sending: " + request.ToString());
        }

        static async void onResponseRecieved(HttpResponseMessage response)
        {
            Console.WriteLine("Response Recieved: " + response.ToString());
        }

        static async void onRawResponseRecieved(byte[] responseData)
        {
            string response = new string(responseData.Select(ch => (char) ch).ToArray());
            Console.WriteLine("Raw Response Recieved: " + response);
        }
    }
}
