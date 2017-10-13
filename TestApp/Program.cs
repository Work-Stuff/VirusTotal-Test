using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Net.Http;
using VirusTotal_Test;
using Nito.AsyncEx;
using Newtonsoft.Json;

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

            Console.WriteLine("Scanning Test Document...");
            ScanResponseData document = await handle.ScanFileAsync("TestFiles/TestDocument.docx");
            Console.WriteLine(document.VerboseMessage);
            ReportResponseData documentResponse = await handle.ReportFileAsync(document.Resource);
            while(documentResponse.ResponseCode == EnumReportResponseCode.QUEUED)
            {
                Console.WriteLine("Scanning...");
                documentResponse = await handle.ReportFileAsync(document.Resource);
                Thread.Sleep(5000);
            }
            Console.WriteLine(documentResponse.VerboseMessage);
            Console.WriteLine(documentResponse.Positives + " of " + documentResponse.Total + " virus engines detected a virus.");

            Console.WriteLine("Scanning Test Photo...");
            ScanResponseData photo = await handle.ScanFileAsync("TestFiles/TestPhoto.jpeg");
            Console.WriteLine(photo.VerboseMessage);
            ReportResponseData photoResponse = await handle.ReportFileAsync(photo.Resource);
            while (photoResponse.ResponseCode == EnumReportResponseCode.QUEUED)
            {
                Console.WriteLine("Scanning...");
                photoResponse = await handle.ReportFileAsync(photo.Resource);
                Thread.Sleep(5000);
            }
            Console.WriteLine(photoResponse.VerboseMessage);
            Console.WriteLine(photoResponse.Positives + " of " + photoResponse.Total + " virus engines detected a virus.");

            Console.WriteLine("Scanning Test Video...");
            ScanResponseData video = await handle.ScanFileAsync("TestFiles/TestVideo.mov");
            Console.WriteLine(video.VerboseMessage);
            ReportResponseData videoResponse = await handle.ReportFileAsync(video.Resource);
            while (videoResponse.ResponseCode == EnumReportResponseCode.QUEUED)
            {
                Console.WriteLine("Scanning...");
                videoResponse = await handle.ReportFileAsync(video.Resource);
                Thread.Sleep(5000);
            }
            Console.WriteLine(videoResponse.VerboseMessage);
            Console.WriteLine(videoResponse.Positives + " of " + videoResponse.Total + " virus engines detected a virus.");

            Console.WriteLine("Scanning Test Virus...");
            ScanResponseData virus = await handle.ScanFileAsync("TestFiles/TestVirus.txt");
            Console.WriteLine(virus.VerboseMessage);
            ReportResponseData virusResponse = await handle.ReportFileAsync(virus.Resource);
            while (virusResponse.ResponseCode == EnumReportResponseCode.QUEUED)
            {
                Console.WriteLine("Scanning...");
                virusResponse = await handle.ReportFileAsync(virus.Resource);
                Thread.Sleep(5000);
            }
            Console.WriteLine(virusResponse.VerboseMessage);
            Console.WriteLine(virusResponse.Positives + " of " + virusResponse.Total + " virus engines detected a virus.");
            Console.ReadKey();
        }

        static async void onRequestSending(HttpRequestMessage request)
        {
            // Console.WriteLine("Request Sending: " + request.ToString());
        }

        static async void onResponseRecieved(HttpResponseMessage response)
        {
            // Console.WriteLine("Response Recieved: " + response.ToString());
        }

        static async void onRawResponseRecieved(byte[] responseData)
        {
            // string response = new string(responseData.Select(ch => (char) ch).ToArray());
            // Console.WriteLine("Raw Response Recieved: " + response);
        }
    }
}
