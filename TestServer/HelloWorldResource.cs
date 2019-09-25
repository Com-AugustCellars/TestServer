using System;
using System.Text;
using Com.AugustCellars. CoAP.Server.Resources;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.DTLS;
using Com.AugustCellars.CoAP.TLS;
using Org.BouncyCastle.Crypto.Tls;

namespace TestServer
{
    /// <summary>
    /// This resource responds with a kind "hello world" to GET requests.
    /// </summary>
    class HelloWorldResource : Resource
    {
        readonly bool _fTellAboutOSCORE;

        public HelloWorldResource(String name, bool fTellAboutOscore)
            : base(name)
        {
            Attributes.Title = "GET a friendly greeting!";
            Attributes.AddResourceType("HelloWorldDisplayer");
            _fTellAboutOSCORE = fTellAboutOscore;
            if (!fTellAboutOscore) {
                this.RequireSecurity = true;

            }
        }

        protected override void DoGet(CoapExchange exchange)
        {
            if (!_fTellAboutOSCORE) {
                exchange.Respond("Hello World!");
                return;
            }

            Console.WriteLine("GET on /hello with ");
            Console.WriteLine(DateTime.Now.ToLongDateString());
            Console.WriteLine(Com.AugustCellars.CoAP.Util.Utils.ToString(exchange.Request));

            if (exchange.Request.OscoreContext != null) {
                Request request = exchange.Request;

                if (request.HasOption(OptionType.UriQuery)) {
                    int count = 0;
                    Response response = new Response(StatusCode.Content);
                    foreach (Option options in request.GetOptions(OptionType.UriQuery)) {
                        switch (options.StringValue) {
                        case "first=1":
                            response.PayloadString = "Hello World!";
                            response.AddETag(new byte[] {0x2b});
                            break;

                        case "second=1":
                        case "second=2":
                            if (!request.HasOption(OptionType.Accept) || request.GetFirstOption(OptionType.Accept).IntValue != 0) {
                                response = new Response(StatusCode.BadRequest) {
                                    PayloadString = "Incorrect Accept option"
                                };
                            }
                            else {
                                response.PayloadString = "Hello World!";
                                response.AddETag(new byte[] {0x2b});
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

                    if (count > 1) {
                        exchange.Respond(StatusCode.BadRequest, "Only one UriQuery can be supplied");
                    }
                    else {
                        exchange.Respond(response);
                    }
                }
                else {
                    String s;
                    if (exchange.Request.OscoreContext.GroupId == null) {
                        s = $"Hello World! -- I see OSCORE w/ kid of '{Encoding.UTF8.GetString(exchange.Request.OscoreContext.Recipient.Id)}'";
                    }
                    else {
                        s = $"Hello World! -- I see OSCORE w/ gid of '{Encoding.UTF8.GetString(exchange.Request.OscoreContext.GroupId)}'";
                    }

                    exchange.Respond(s);
                }
            }
            else if (exchange.Request.Session is DTLSSession) {
                DTLSSession ses = (DTLSSession) exchange.Request.Session;
                if (ses.AuthenticationKey != null) {
                    exchange.Respond($"Hello World! I have a DTLS session w/ Authenticator = {ses.AuthenticationKey.GetType()}");
                }
                else {
                    exchange.Respond($"Hello World! I have a DTLS session w/ Authenticator = {ses.AuthenticationCertificate.GetCertificateAt(0).Subject}");
                }
            }
            else if (exchange.Request.Session is TLSSession) {
                TLSSession ses = (TLSSession) exchange.Request.Session;
                if (ses.AuthenticationKey != null) {
                    exchange.Respond($"Hello World! I have a TLS session w/ Authenticator = {ses.AuthenticationKey.GetType()}");
                }
                else {
                    exchange.Respond($"Hello World! I have a TLS session w/ Authenticator = {ses.AuthenticationCertificate.GetCertificateAt(0).Subject}");
                }
            }
            else
            {
                exchange.Respond("Hello World! -- I see no OSCORE here");
            }
        }
    }
}
