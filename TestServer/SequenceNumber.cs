using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Server.Resources;
using Com.AugustCellars.CoAP.OSCOAP;

namespace server
{
    public class SequenceNumber : Resource
    {
        SecurityContext _ctx;

        public SequenceNumber(string name, SecurityContext ctx) : base(name)
        {
            _ctx = ctx;
        }

        protected override void DoGet(CoapExchange exchange)
        {
            String str = String.Format("Next sequence # will be {0}", _ctx.Sender.SequenceNumber + 1);
            exchange.Respond(str);
        }

        protected override void DoPut(CoapExchange exchange)
        {
            int i = Int32.Parse( exchange.Request.PayloadString);
            _ctx.Sender.SequenceNumber = i - 1;
            exchange.Respond(StatusCode.Changed, "Next sequence number will be {0}", i);
        }
    }
}
