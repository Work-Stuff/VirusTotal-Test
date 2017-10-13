using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusTotal_Test
{
    public enum EnumReportResponseCode : int
    {
        QUEUED = -2,
        NOT_PRESENT = 0,
        PRESENT = 1
    }
}
