using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Server.Resources;

namespace server
{
#if INCLUDE_PUBSUB
    public class PubSubLeaf : Resource
    {
        byte[] content;
        int contentType;
        DateTime? expire = null;

        public PubSubLeaf(string name, int contentTypeIn) : base(name)
        {
            contentType = contentTypeIn;
            Attributes.AddContentType(contentType);
        }

        public PubSubLeaf(string name) : base(name)
        {
        }

        protected override void DoGet(CoapExchange exchange)
        {
            if ((exchange.Request.ContentFormat != 0) && (exchange.Request.ContentFormat != contentType))
            {
                exchange.Respond(StatusCode.UnsupportedMediaType);
                return;
            }

            if (expire != null)
            {
                TimeSpan d = (DateTime) expire - DateTime.Now;
                if (d.TotalSeconds < 0)
                {
                    content = null;
                }
                else
                {
                    exchange.MaxAge = (int) d.TotalSeconds;
                }
            }

            if (content != null) exchange.Respond(StatusCode.BadRequest);
            else exchange.Respond(StatusCode.Content, content);

        }

        protected override void DoPut(CoapExchange exchange)
        {
            Request req = exchange.Request;

            if (Attributes.Contains("ContentType")) {
                if (exchange.Request.ContentFormat != contentType) {
                    exchange.Respond(StatusCode.BadRequest, "Mismatched content type");
                    return;
                }
            }

            if (req.HasOption(OptionType.MaxAge)) {
                if (exchange.Request.MaxAge > 0) {
                    expire = DateTime.Now + new TimeSpan(0, (Int32) (exchange.Request.MaxAge / 60), (Int32) (exchange.Request.MaxAge % 60));
                }
                else expire = null;
            }

            content = exchange.Request.Payload;
            Changed();
            exchange.Respond(StatusCode.Changed);
        }

        protected override void DoDelete(CoapExchange exchange)
        {
            this.Delete();
            exchange.Respond(StatusCode.Deleted);
        }
    }
#endif
}
