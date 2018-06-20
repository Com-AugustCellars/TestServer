using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Server.Resources;

namespace TestServer.InteropTests.CoapCoreTests
{
    class Separate : Resource
    {
        public Separate() : base("separate")
        {
            Attributes.Title = "Resource responds with a deferred answer";
        }

        protected override void DoGet(CoapExchange exchange)
        {
            exchange.Accept();

            Thread.Sleep(1000);

            Request req = exchange.Request;
            StringBuilder sb = new StringBuilder("Deferred Response");

            exchange.Respond(StatusCode.Content, sb.ToString());
        }
    }
}
