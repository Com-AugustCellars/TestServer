using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Server.Resources;

namespace server
{
    class OscoapObserve : Resource
    {
        public OscoapObserve(String name)
            : base(name)
        {
            Attributes.Title = "GET a friendly greeting!";
            Attributes.AddResourceType("OSCOAP-Tester");
            if (name != "coap") {
                RequireSecurity = true;
            }
            Observable = true;
        }

        protected override void DoGet(CoapExchange exchange)
        {


            Console.WriteLine("GET on /hello with ");
            Console.WriteLine(System.DateTime.Now.ToLongDateString());
            Console.WriteLine(Com.AugustCellars.CoAP.Util.Utils.ToString(exchange.Request));

            if (exchange.Request.OscoapContext == null) {
                exchange.Respond("Hello World! -- I see no OSCOAP here");
            }
            else {
                Request request = exchange.Request;

                if (request.HasOption(OptionType.UriQuery)) {
                    int count = 0;
                    Response response = new Response(StatusCode.Content);
                    foreach (Option options in request.GetOptions(OptionType.UriQuery)) {
                        switch (options.StringValue) {
                            case "first=1":
                                response.PayloadString = "Hello World!";
                                response.AddETag(new byte[] { 0x2b });
                                break;

                            case "second=1":
                            case "second=2":
                                if (!request.HasOption(OptionType.Accept) || request.GetFirstOption(OptionType.Accept).IntValue != 0) {
                                    response = new Response(StatusCode.BadRequest);
                                    response.PayloadString = "Incorrect Accept option";
                                }
                                else {
                                    response.PayloadString = "Hello World!";
                                    response.AddETag(new byte[] { 0x2b });
                                    response.MaxAge = 5;
                                    response.RemoveOptions(OptionType.ContentFormat);
                                }
                                break;

                            default:
                                exchange.Respond(StatusCode.BadRequest, "UriQuery '" + options.StringValue + "' is unrecognized");
                                break;
                        }
                        count++;
                    }
                    if (count > 1)
                        exchange.Respond(StatusCode.BadRequest, "Only one UriQuery can be supplied");
                    else
                        exchange.Respond(response);
                }
                else {
                    String s = String.Format("Hellow World! -- I see OSCOAP w/ kid of '{0}'", UTF8Encoding.UTF8.GetString(exchange.Request.OscoapContext.Recipient.Id));
                    exchange.Respond(s);
                }
            }
        }
    }
}
