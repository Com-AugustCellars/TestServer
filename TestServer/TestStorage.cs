using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Server.Resources;

namespace server
{
    class TestStorage : Resource
    {
        Boolean fActive = false;
        byte[] content;

        public TestStorage(String name) : base(name, false)
        {
            RequireSecurity = false ;
            RequireSecurityErrorText = "OSCOAP security is required";
        }

        protected override void DoGet(CoapExchange exchange)
        {
            if (fActive) {
                exchange.Respond(StatusCode.Content, content);
            }
            else exchange.Respond(StatusCode.NotFound);
        }

        protected override void DoPost(CoapExchange exchange)
        {
            Request request = exchange.Request;
            if (!request.HasOption(OptionType.ContentFormat) || request.GetFirstOption(OptionType.ContentFormat).IntValue != 0) {
                exchange.Respond(StatusCode.BadRequest, "Missing content format option");
                return;
            }

            Response response;
            if (fActive) {
                response = new Response(StatusCode.Changed);
                content = request.Payload;
            }
            else {
                //  Check what the payload is
                fActive = true;
                response = new Response(StatusCode.Created);
                response.LocationPath = "counter";
                response.AddLocationQuery("first=1");
                response.AddLocationQuery("second=2");
                content = request.Payload;
            }
            exchange.Respond(response);
        }

        byte[] _ifMatch = new byte[] { 0x5b, 0x5b };
        protected override void DoPut(CoapExchange exchange)
        {
            if (fActive) {
                Request request = exchange.Request;
                if (!request.HasOption(OptionType.ContentFormat) || request.GetFirstOption(OptionType.ContentFormat).IntValue != 0) {
                    exchange.Respond(StatusCode.BadRequest, "Content Format");
                    return;
                }
                if (!request.HasOption(OptionType.IfMatch) || ByteCompare(request.GetFirstOption(OptionType.IfMatch).RawValue, _ifMatch) != 0) {
                    exchange.Respond(StatusCode.BadRequest, "IfMatch");
                    return;
                }

                Response response = new Response(StatusCode.Content);
                response.AddETag(_ifMatch);
                response.ContentFormat = 0;
                response.Payload = content;
                exchange.Respond(response);
            }
            else exchange.Respond(StatusCode.NotFound);
        }

        protected override void DoDelete(CoapExchange exchange)
        {
            if (fActive) {
                fActive = false;
                content = null;
                exchange.Respond(StatusCode.Deleted);
            }
            else exchange.Respond(StatusCode.NotFound);
        }

        int ByteCompare(byte[] left, byte[] right)
        {
            if (left.Length != right.Length) return left.Length - right.Length;
            for (int i = 0; i < left.Length; i++) {
                if (left[i] != right[i]) return left[i] - right[i];
            }
            return 0;
        }
    }
}
