using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Server.Resources;

namespace TestServer.InteropTests.CoapCoreTests
{
    class LongPath : Resource
    {
        public LongPath() : base("seg1")
        {
            Attributes.Title = "Multiple segment resource";
            IResource r1 = new LongPath("seg2");
            IResource r2 = new LongPath("seg3");

            Add(r1);
            r1.Add(r2);
        }

        public LongPath(string name) : base(name)
        {
            Attributes.Title = "Multiple segment resource";

        }

        protected override void DoGet(CoapExchange exchange)
        {
            Request r = exchange.Request;

            StringBuilder sb = new StringBuilder();

            sb.Append("Long path resorce ");
            sb.Append(r.UriPaths);

            exchange.Respond(StatusCode.Content, sb.ToString());
        }
    }
}
