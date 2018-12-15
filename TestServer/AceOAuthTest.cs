using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.OAuth;
using Com.AugustCellars.CoAP.Server.Resources;
using server;

namespace TestServer
{
    class AceOAuthTest : Resource
    {
        private byte[] _unsecureResponse;
        private bool _allowTls { get; }
        private bool _allowOscore { get;  }
        private AsInfo _asInfo { get; }
        private AuthorizationEvaluate _accessCheck { get; } = new AuthorizationEvaluate();

        public AceOAuthTest(string name, bool allowTLS, bool allowOSCORE, string asServer) : base(name)
        {
            _asInfo = new AsInfo() {
                ASServer = asServer
            };
            _allowTls = allowTLS;
            _allowOscore = allowOSCORE;
        }

        protected override void DoGet(CoapExchange exchange)
        {
            if (_allowTls && exchange.Request.Session is ISecureSession) {
                ISecureSession secSession = (ISecureSession) exchange.Request.Session;
                if (!_accessCheck.CheckAccess(Method.GET, this.Uri, secSession.AuthenticationKey)) {
                    Unauthorized(exchange);
                    return;
                }
            }
            else if (_allowOscore && exchange.Request.OscoapContext != null) {
                if (!_accessCheck.CheckAccess(Method.GET, this.Uri, exchange.Request.OscoapContext)) {
                    Unauthorized(exchange);
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


        public AuthZ AuthTokenProcessor { get; set; }

        private void Unauthorized(CoapExchange exchange)
        {
            AsInfo info = new AsInfo(_asInfo);
            info.Nonce = AuthTokenProcessor.CurrentNonce();
            exchange.Respond(StatusCode.Unauthorized, info.EncodeToBytes(), 65008);
        }
    }
}
