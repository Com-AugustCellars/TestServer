using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.OAuth;
using Com.AugustCellars.CoAP.Server;
using Com.AugustCellars.CoAP.Server.Resources;
using PeterO.Cbor;
using TestServer;

namespace server
{
    class AceTest
    {
        public static void Setup(CoapServer server, string audience)
        {
            Resource r = new NopResource("ace");
            server.Add(r);
            r = new HelloWorld() {
                Audience = audience
            };
            server.Add("ace", r);

            r = new Lock() {
                Audience = audience
            };
            server.Add("ace", r);
        }
    }

    class NopResource : Resource
    {
        public NopResource(string name) : base(name)
        {
        }
    }

    class HelloWorld : Resource
    {
        private AuthorizationEvaluate _accessCheck  = new AuthorizationEvaluate();
        private bool _allowTls = true;
        private bool _allowOscore = false;
        private AsInfo _asInfo { get; }
        public string Audience { get; set; }

        public HelloWorld() : base("helloWorld")
        {
            _asInfo = new AsInfo() {
                // ASServer = "coaps://ASServer/token"
               ASServer = "coap://localhost:5688/token"
                // ASServer = "coaps://31.133.145.200/token"
            };
            _allowOscore = true;
        }

        protected override void DoGet(CoapExchange exchange)
        {
            if (_allowTls && exchange.Request.Session is ISecureSession) {
                ISecureSession secSession = (ISecureSession)exchange.Request.Session;
                if (!_accessCheck.CheckAccess(Method.GET, Audience, "helloWorld", secSession.AuthenticationKey)) {
                    Unauthorized(exchange);
                    return;
                }
            }
            else if (_allowOscore && exchange.Request.OscoapContext != null) {
                if (!_accessCheck.CheckAccess(Method.GET, this.Uri, exchange.Request.OscoapContext)) {
                    Unauthorized(exchange);
                    return;
                }
            }
            else {
                //  There is not a security context that is acceptable, return an unauthorized
                // Response.
                Unauthorized(exchange);
                return;
            }

            exchange.Respond(StatusCode.Content, $"This was a success getting into resource {Path}");
        }

        private void Unauthorized(CoapExchange exchange)
        {
            AsInfo info = new AsInfo(_asInfo);
            // info.Nonce = AuthTokenProcessor.CurrentNonce();
            exchange.Respond(StatusCode.Unauthorized, info.EncodeToBytes(), MediaType.ApplicationCbor);
        }
    }

    class Lock : Resource
    {
        private AuthorizationEvaluate _accessCheck = new AuthorizationEvaluate();
        private bool _allowTls = true;
        private bool _allowOscore = false;
        private AsInfo _asInfo { get; }
        private bool _state = false;
        public string Audience { get; set; }

        public Lock() : base("lock")
        {
            _asInfo = new AsInfo() {
                // ASServer = "coaps://31.133.145.200/token"
                ASServer = "coap://localhost:5688/token"
            };
            _allowOscore = true;
        }

        protected override void DoGet(CoapExchange exchange)
        {
            if (_allowTls && exchange.Request.Session is ISecureSession) {
                ISecureSession secSession = (ISecureSession)exchange.Request.Session;
                if (!_accessCheck.CheckAccess(Method.GET, Audience, "r_lock", secSession.AuthenticationKey) &&
                    !_accessCheck.CheckAccess(Method.GET, Audience, "rw_lock", secSession.AuthenticationKey)) {
                    Unauthorized(exchange);
                    return;
                }
            }
            else if (_allowOscore && exchange.Request.OscoapContext != null) {
                if (!_accessCheck.CheckAccess(Method.GET, this.Uri, exchange.Request.OscoapContext)) {
                    Unauthorized(exchange);
                    return;
                }
            }
            else {
                //  There is not a security context that is acceptable, return an unauthorized
                // Response.
                Unauthorized(exchange);
                return;
            }

            Com.AugustCellars.CoAP.Response resp = new Com.AugustCellars.CoAP.Response(StatusCode.Content);
            resp.Payload = CBORObject.FromObject(_state).EncodeToBytes();
            resp.ContentFormat = MediaType.ApplicationCbor;
            exchange.Respond(resp);
        }

        protected override void DoPut(CoapExchange exchange)
        {
            try {
                if (_allowTls && exchange.Request.Session is ISecureSession) {
                    ISecureSession secSession = (ISecureSession) exchange.Request.Session;
                    if (!_accessCheck.CheckAccess(Method.GET, Audience, "rw_lock", secSession.AuthenticationKey)) {
                        Unauthorized(exchange);
                        return;
                    }
                }
                else if (_allowOscore && exchange.Request.OscoapContext != null) {
                    if (!_accessCheck.CheckAccess(Method.GET, this.Uri, exchange.Request.OscoapContext)) {
                        Unauthorized(exchange);
                        return;
                    }
                }
                else {
                    //  There is not a security context that is acceptable, return an unauthorized
                    // Response.
                    Unauthorized(exchange);
                    return;
                }

                if (exchange.Request.ContentFormat != MediaType.ApplicationCbor) {
                    exchange.Respond(StatusCode.BadRequest);
                    return;
                }

                CBORObject o = CBORObject.DecodeFromBytes(exchange.Request.Bytes);
                if (o.Type != CBORType.Boolean) {
                    exchange.Respond(StatusCode.BadRequest);
                    return;
                }

                _state = o.AsBoolean();

                exchange.Respond(StatusCode.Changed);
            }
            catch (Exception e) {
                exchange.Respond(StatusCode.BadRequest, e.ToString());
            }
        }

        private void Unauthorized(CoapExchange exchange)
        {
            AsInfo info = new AsInfo(_asInfo);
            // info.Nonce = AuthTokenProcessor.CurrentNonce();
            exchange.Respond(StatusCode.Unauthorized, info.EncodeToBytes(), 65008);
        }
    }
}
