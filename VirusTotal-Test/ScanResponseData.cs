using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VirusTotalNET;
using VirusTotalNET.Results;

namespace VirusTotal_Test
{
    public struct ScanResponseData
    {
        private ScanResult Result;
        public string MD5;
        public string PermaLink;
        public string Resource;
        public string ScanID;
        public string SHA1;
        public string SHA256;
        EnumScanResponseCode ResponseCode;
        public string VerboseMessage;

        public ScanResponseData(ScanResult result, string mD5, string permaLink, string resource, 
            string scanID, string sHA1, string sHA256, EnumScanResponseCode responseCode, string verboseMessage)
        {
            Result = result;
            MD5 = mD5;
            PermaLink = permaLink;
            Resource = resource;
            ScanID = scanID;
            SHA1 = sHA1;
            SHA256 = sHA256;
            ResponseCode = responseCode;
            VerboseMessage = verboseMessage;
        }
    }

}
