using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Server.Resources;
//using OO= Com.AugustCellars.CoAP.OAuth;

namespace server
{
#if false
    public class Token : Resource
    {
        public Token(String name) : base(name)
        {

        }

        protected override void DoPost(CoapExchange exchange)
        {
            try {
                Com.AugustCellars.CoAP.Request req = exchange.Request;
                OO.Request reqOauth = new OO.Request(req.Payload);

                if (reqOauth.Grant_Type != 2) {
                    OO.Error errResponse = new OO.Error(4); // unsupported_grant_type
                    exchange.Respond(StatusCode.BadRequest, errResponse.EncodeToBytes());
                    return;
                }

                //  M00TODO -- check that we should grant this.



            }
            catch (Exception e) {
                OO.Error errResponse = new OO.Error(0); // 
                errResponse.Description = e.ToString();
                exchange.Respond(StatusCode.BadGateway, errResponse.EncodeToBytes());
            }
        }
    }
#endif
}
