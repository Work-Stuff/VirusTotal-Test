using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VirusTotalNET.Objects;
using VirusTotalNET.Results;

namespace VirusTotal_Test
{
    public struct ReportResponseData
    {
        private FileReport Report;
        public string MD5;
        public string Permalink;
        public int Positives;
        public string Resource;
        public DateTime ScanDate;
        public string ScanId;
        public Dictionary<string, ScanEngine> Scans;
        public string SHA1;
        public int Total;
        public EnumReportResponseCode ResponseCode;
        public string VerboseMessage;

        public ReportResponseData(FileReport report, string mD5, string permalink, int positives, string resource, DateTime scanDate, string scanId, Dictionary<string, ScanEngine> scans, string sHA1, int total, EnumReportResponseCode responseCode, string verboseMsg)
        {
            Report = report;
            MD5 = mD5;
            Permalink = permalink;
            Positives = positives;
            Resource = resource;
            ScanDate = scanDate;
            ScanId = scanId;
            Scans = scans;
            SHA1 = sHA1;
            Total = total;
            ResponseCode = responseCode;
            VerboseMessage = verboseMsg;
        }
    }
}
