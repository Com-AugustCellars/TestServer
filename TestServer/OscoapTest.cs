using System;
using Com.AugustCellars.CoAP.Server.Resources;
using Com.AugustCellars.CoAP.Util;
using Com.AugustCellars.CoAP;


namespace TestServer
{
    class OscoapTest : Resource
    {
        private byte[] _payload;

        public OscoapTest(String name)
            : base(name)
        {
            Attributes.Title = "GET a friendly greeting!";
            Attributes.AddResourceType("OSCOAP-Tester");
            if (name != "coap") {
                RequireSecurity = true;
            }

            _payload = new byte[0];
            this.Observable = false;
        }

        protected override void DoGet(CoapExchange exchange)
        {
            Console.WriteLine("GET on {0} with ", Uri);
            Console.WriteLine(DateTime.Now.ToLongDateString());
            Console.WriteLine(Utils.ToString(exchange.Request));

            Request request = exchange.Request;
            Response response;

            switch (Name) {
                    // Should be security context A or context C
                    // Simple get returns text
                case "1":
                    response = new Response(StatusCode.Content) {
                        PayloadString = "Hello World!",
                        ContentFormat = 0
                    };
                    break;


                case "2":
                    if (request.UriQuery != "first=1") {
                        exchange.Respond(StatusCode.BadRequest);
                        return;
                    }
                    response = new Response(StatusCode.Content) {
                        PayloadString = "Hello World!",
                        ContentFormat =  MediaType.TextPlain
                    };
                    response.AddETag(new byte[] {0x2b});
                    break;
                

                case "3": {
                    if (request.Accept != 0) {
                        exchange.Respond(StatusCode.BadRequest);
                        return;
                    }
                    response = new Response(StatusCode.Content) {
                        PayloadString = "Hello World!",
                        ContentFormat = MediaType.TextPlain,
                        MaxAge = 5
                    };
                    break;
                }

                    //  Non-secure resource - returns a text string.
                case "coap": {
                    response = new Response(StatusCode.Content) {
                        PayloadString = "Hello World!"
                    };
                    break;
                }

                default:
                    response = new Response(StatusCode.BadRequest);
                    break;
            }

            Console.WriteLine(Utils.ToString(response));
            exchange.Respond(response);

        }

        protected override void DoPost(CoapExchange exchange)
        {

            switch (Name) {
                default:
                    base.DoPut(exchange);
                    return;

                case "6": {
                    Response response = new Response(StatusCode.Created) {
                        LocationPath = Path,
                        LocationQuery = "first=1",
                        ContentType = MediaType.TextPlain
                    };
                    _payload = exchange.Request.Payload;

                    exchange.Respond(response);
                    break;
                }

            }
        }

        protected override void DoPut(CoapExchange exchange)
        {
            switch (Name) {
                default:
                    base.DoPut(exchange);
                    return;

                case "7": {
                    if (exchange.Request.IfNoneMatch) {
                        Response res = new Response(StatusCode.PreconditionFailed);
                        exchange.Respond(res);
                        return;
                    }
                    Response response = new Response(StatusCode.Created) {
                        ContentType = MediaType.TextPlain
                    };
                    response.AddETag(new byte[] {0x7b});
                    _payload = exchange.Request.Payload;

                    exchange.Respond(response);
                    break;
                }

            }
        }

        protected override void DoDelete(CoapExchange exchange)
        {
            switch (Name) {
                case "test": 
                    exchange.Respond(StatusCode.Deleted);
                    break;

                default:
                    base.DoDelete(exchange);
                    break;
                
            }
        }
    }
}
