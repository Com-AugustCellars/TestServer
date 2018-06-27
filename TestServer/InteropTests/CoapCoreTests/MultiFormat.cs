using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Server.Resources;

namespace TestServer.InteropTests.CoapCoreTests
{
    class MultiFormat : Resource
    {
        public MultiFormat() : base("multi-format")
        {

        }

        protected override void DoGet(CoapExchange exchange)
        {
            foreach (Option i in  exchange.Request.GetOptions(OptionType.Accept)) {
                switch (i.IntValue) {
                    case MediaType.TextPlain:
                        exchange.Respond(StatusCode.Content, "You asked for plain text", MediaType.TextPlain);
                        return;

                    case MediaType.ApplicationXml:
                        exchange.Respond(StatusCode.Content, "<t>You asked <em> for XML</em></t>",
                                         MediaType.ApplicationXml);
                        return;
                }
            }

            exchange.Respond(StatusCode.BadOption);
        }
    }
}
