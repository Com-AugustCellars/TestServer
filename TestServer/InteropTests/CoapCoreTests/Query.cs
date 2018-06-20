using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Server.Resources;

namespace TestServer.InteropTests.CoapCoreTests
{
    class Query : Resource
    {
        public Query() : base("query")
        {
            Attributes.Title = "Resource for query parameters";
        }

        protected override void DoGet(CoapExchange exchange)
        {
            Request req = exchange.Request;

            StringBuilder sb = new StringBuilder();

            sb.Append("Query resource - parameters are");
            sb.Append(req.UriQueries);

            exchange.Respond(StatusCode.Content, sb.ToString());
        }
    }
}
