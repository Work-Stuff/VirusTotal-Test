using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using VirusTotalNET;
using VirusTotalNET.Results;

namespace VirusTotal_Test
{
    public class VirusTotalHandle
    {
        private VirusTotal handle;
        public Action<HttpRequestMessage> onRequestSending;
        public Action<HttpResponseMessage> onResponseRecieved;
        public Action<byte[]> onRawResponseRecieved;

        public VirusTotalHandle(string API_KEY, Action<HttpRequestMessage> sendHandler, 
            Action<HttpResponseMessage> responseHandler, Action<byte[]> rawResponseHandler, bool useTLS)
        {
            handle = new VirusTotal(API_KEY);
            handle.UseTLS = useTLS;
            onRequestSending = sendHandler;
            onResponseRecieved = responseHandler;
            onRawResponseRecieved = rawResponseHandler;
            handle.OnHTTPRequestSending += onRequestSending;
            handle.OnHTTPResponseReceived += onResponseRecieved;
            handle.OnRawResponseReceived += onRawResponseRecieved;
        }

        public bool IsInitialised()
        {
            return handle.ApiUrl != "";
        }

        public async Task<ScanResponseData> ScanFileAsync(string filePath)
        {
            byte[] file = await FileToBytesAsync(filePath);
            return await GetScanResultAsync(await handle.ScanFileAsync(file, filePath));
        }

        public async Task<byte[]> FileToBytesAsync(string filePath)
        {
            FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
            byte[] buffer = new byte[fileStream.Length];
            int status = await fileStream.ReadAsync(buffer, 0, (int) fileStream.Length); // Supports files up to 4GiB
            await fileStream.FlushAsync();
            fileStream.Close();
            return buffer;
        }

        public async Task<ScanResponseData> GetScanResultAsync(ScanResult res)
        {
            ScanResponseData data = new ScanResponseData(
                res,
                res.MD5,
                res.Permalink,
                res.Resource,
                res.ScanId,
                res.SHA1,
                res.SHA256,
                (EnumScanResponseCode)Convert.ToInt32(res.ResponseCode),
                res.VerboseMsg
            );
            return data;
        }
    }
}
