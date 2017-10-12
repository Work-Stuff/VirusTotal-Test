using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VirusTotalNET;

namespace VirusTotal_Test
{
    class VirusTotalHandle
    {
        private VirusTotal handle;

        public VirusTotalHandle(string API_KEY, bool useTLS)
        {
            handle = new VirusTotal(API_KEY);
            handle.UseTLS = useTLS;
        }

        public bool isInitialised()
        {
            return handle.ApiUrl != "";
        }
    }
}
