using System;
using System.Diagnostics;
using System.Text;
using System.Threading;
using Com.AugustCellars.CoAP.Server.Resources;

namespace TestServer
{
    class LargeResource : Resource
    {
        private string payload;
        private static string blockFormat;

        static LargeResource()
        {
            blockFormat = new StringBuilder()
                .Append("/-------------------------------------------------------------\\\r\n")
                .Append("|               RESOURCE BLOCK NO. {0,3} OF {1,3}                 |\r\n")
                .Append("|               [each line contains 64 bytes]                 |\r\n")
                .Append("\\-------------------------------------------------------------/\r\n")
                .ToString();
        }

        public LargeResource(String name, int resourceSize = 8*64*4)
            : base(name)
        {
            Attributes.Title = "This is a large resource for testing block-wise transfer";
            Attributes.AddResourceType("BlockWiseTransferTester");

            payload = "";
            int count = resourceSize / (64*4);
            for (int i = 0; i < count; i++) {
                payload += string.Format(blockFormat, i + 1, count);
            }


            // RequireSecurity = true;
        }

        protected override void DoGet(CoapExchange exchange)
        {
            exchange.Respond(payload);
        }

        protected override void DoPost(CoapExchange exchange)
        {
            exchange.Respond(payload);
        }

        protected override void DoPut(CoapExchange exchange)
        {
            exchange.Respond(payload);
        }
    }
}
