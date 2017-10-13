using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusTotal_Test
{
    public enum EnumScanResponseCode : int
    {
        ERROR = 0,
        QUEUED = 1,
        SUCCESS = 2,
    }
}
