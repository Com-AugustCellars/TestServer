using System;
using System.Collections.Generic;
using System.Text;
using Com.AugustCellars. CoAP.Server.Resources;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.DTLS;

namespace TestServer
{
    /// <summary>
    /// This resource responds with a kind "hello world" to GET requests.
    /// </summary>
    class HelloWorldResource : Resource
    {
        bool _fTellAboutOSCOAP;

        public HelloWorldResource(String name, bool fTellAboutOSCOAP)
            : base(name)
        {
            Attributes.Title = "GET a friendly greeting!";
            Attributes.AddResourceType("HelloWorldDisplayer");
            _fTellAboutOSCOAP = fTellAboutOSCOAP;
            if (!fTellAboutOSCOAP) {
                this.RequireSecurity = true;
                
            }
        }

        protected override void DoGet(CoapExchange exchange)
        {
            if (!_fTellAboutOSCOAP) {
                exchange.Respond("Hello World!");
                return;
            }

            Console.WriteLine("GET on /hello with ");
            Console.WriteLine(System.DateTime.Now.ToLongDateString());
            Console.WriteLine(Com.AugustCellars.CoAP.Util.Utils.ToString(exchange.Request));

            if (exchange.Request.OscoapContext != null) {
                Request request = exchange.Request;

                if (request.HasOption(OptionType.UriQuery))
                {
                    int count = 0;
                    Response response = new Response(StatusCode.Content);
                    foreach (Option options in request.GetOptions(OptionType.UriQuery))
                    {
                        switch (options.StringValue)
                        {
                            case "first=1":
                                response.PayloadString = "Hello World!";
                                response.AddETag(new byte[] { 0x2b });
                                break;

                            case "second=1":
                            case "second=2":
                                if (!request.HasOption(OptionType.Accept) || request.GetFirstOption(OptionType.Accept).IntValue != 0)
                                {
                                    response = new Response(StatusCode.BadRequest);
                                    response.PayloadString = "Incorrect Accept option";
                                }
                                else
                                {
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
                    if (count > 1) exchange.Respond(StatusCode.BadRequest, "Only one UriQuery can be supplied");
                    else exchange.Respond(response);
                }
                else
                {
                    String s;
                    if (exchange.Request.OscoapContext.GroupId == null)
                    {
                        s = String.Format("Hello World! -- I see OSCOAP w/ kid of '{0}'", UTF8Encoding.UTF8.GetString(exchange.Request.OscoapContext.Recipient.Id));
                    }
                    else
                    {
                        s = $"Hello World! -- I see OSCOAP w/ gid of '{Encoding.UTF8.GetString(exchange.Request.OscoapContext.GroupId)}'";
                    }
                    exchange.Respond(s);
                }
            }
            else if (exchange.Request.Session is DTLSSession) {
                DTLSSession ses = (DTLSSession) exchange.Request.Session;
                exchange.Respond($"Hello World! I have a DTLS session w/ Authentcator = {ses.AuthenticationKey.GetType()}");
            }
            else {
                exchange.Respond("Hello World! -- I see no OSCOAP here");
            }
        }
    }
}
