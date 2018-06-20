using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CoAP.Examples.Resources;
using Com.AugustCellars.CoAP.Server;
using Com.AugustCellars.CoAP.Server.Resources;

namespace TestServer.InteropTests.CoapCoreTests
{
    public class CoapCoreTests
    {
        public static void Setup(CoapServer server)
        {
            IResource r = new TestResource();
            server.Add(r);

            server.Add(new LongPath());
            server.Add(new Query());
            server.Add(new Separate());
            server.Add(new LargeResource("large"));
            server.Add(new LargeResource("large_update"));
            server.Add(new LargeResource("large_create"));
            server.Add(new TimeResource("obs", 5));
        }
    }
}
