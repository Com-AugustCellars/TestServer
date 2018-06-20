using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Server.Resources;

namespace TestServer.InteropTests.CoapCoreTests
{
    class TestResource : Resource
    {
        public TestResource() : base("test")
        {
            Attributes.Title = "Default test resorce";
        }

        protected override void DoGet(CoapExchange exchange)
        {
            StringBuilder sb = new StringBuilder();
            Request req = exchange.Request;

            sb.AppendFormat("Type: %d (%)\nCode: %d (%s)\nMID: %d", req.Type, "", req.Code, req.CodeString, req.ID);

            if (req.Token.Length > 0) {
                sb.Append("\nToken ");
                sb.Append(req.TokenString);
            }

            string payload = sb.ToString();

            Response resp = new Response(StatusCode.Content);
            resp.MaxAge = 30;

            exchange.Respond(resp);
        }
    }
}
