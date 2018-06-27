using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Server.Resources;

namespace TestServer.InteropTests.CoapCoreTests
{
    class LocationQuery : Resource
    {
        public LocationQuery() : base("location_query")
        {

        }

        protected override void DoPost(CoapExchange exchange)
        {
            StringBuilder sb = new StringBuilder();

            sb.AppendFormat("POST to /location_query w/ options {0}", exchange.Request.UriQueries);

            exchange.Respond(StatusCode.Changed, sb.ToString(), MediaType.TextPlain);
        }
    }
}
