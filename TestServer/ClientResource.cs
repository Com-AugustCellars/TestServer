using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.OSCOAP;
using Com.AugustCellars.CoAP.Server.Resources;
using PeterO.Cbor;

namespace server
{
#if false
    class ClientResource : Resource
    {
        public ClientResource(String name) : base(name)
        {
            RequireSecurity = true;
        }

        protected override void DoPost(CoapExchange exchange)
        {
            try {
                Request request = exchange.Request;
                CBORObject obj = CBORObject.DecodeFromBytes(request.Payload);

                exchange.Accept();

                String uri = obj[0].AsString();
                byte[] key = obj[1].GetByteString();
                List<SecurityContext> contexts = SecurityContextSet.AllContexts.FindByKid(key);
                if (contexts.Count == 0) {
                    exchange.Respond(StatusCode.BadRequest, "No matching key identifier found");
                    return;
                }

                Codec.IMessageDecoder me = Spec.Default.NewMessageDecoder(obj[2].GetByteString());
                Request newRequest = me.DecodeRequest();

                newRequest.URI = new System.Uri(uri);
                newRequest.OscoapContext = contexts[0];

                newRequest.Send();
                Response response = newRequest.WaitForResponse();

                exchange.Respond(response);
            }
            catch (Exception e) {
                exchange.Respond(StatusCode.BadRequest, e.ToString());
            }
        }
    }
#endif
}
