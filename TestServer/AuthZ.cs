using Com.AugustCellars.CoAP.Server.Resources;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.DTLS;
using Com.AugustCellars.CoAP.OAuth;
using Com.AugustCellars.COSE;
using PeterO.Cbor;
using Com.AugustCellars.WebToken;
using Com.AugustCellars.CoAP.Log;
using Com.AugustCellars.CoAP.OSCOAP;
using server;
using Request = Com.AugustCellars.CoAP.Request;

namespace TestServer
{
    class AuthZ : Resource
    {
        public class IntrospectionServer
        {
            public string AuthServerUrl { get;  }
            public OneKey AuthServerKey { get; }
            public IntrospectionServer(string url, OneKey key)
            {
                AuthServerUrl = url;
                AuthServerKey = key;
            }
        }

        public List<IntrospectionServer> AuthServerList = new List<IntrospectionServer>();

        private readonly KeySet _myKeys;
        private readonly KeySet _asSigningKeys;

        private static ILogger _logger = LogManager.GetLogger("AUTHZ");

        public AuthZ(KeySet myKeys, KeySet asSigningKeys, DTLSEndPoint ep) : base("authz-info")
        {
            _lastNonceUpdate = DateTime.MinValue;
            byte[] x = new byte[5]{1, 2, 3, 4, 5};
            _nonceList.Add(x);
            _myKeys = myKeys;
            _asSigningKeys = asSigningKeys;

            OneKey key = new OneKey();
            key.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_Octet);
            key.Add(CoseKeyParameterKeys.Octet_k, CBORObject.FromObject(new byte[] { 15, 12, 2, 3, 4, 5, 6, 7, 8, 9, 10 }));
            key.Add(CoseKeyKeys.KeyIdentifier, CBORObject.FromObject(Encoding.UTF8.GetBytes("AS_RS")));

            OneKey key2 = new OneKey();
            key2.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_Octet);
            key2.Add(CoseKeyParameterKeys.Octet_k, CBORObject.FromObject(new byte[] {
            0xb1, 0xb2, 0xb3, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}));
            key2.Add(CoseKeyKeys.KeyIdentifier, CBORObject.FromObject(Encoding.UTF8.GetBytes("RS2")));

            // AuthServerList.Add(new IntrospectionServer("coap://localhost:5688/introspect", key));
            AuthServerList.Add(new IntrospectionServer("coaps://31.133.145.200/introspect", key2));

            ep.TlsEventHandler += AuthzForPsk;
        }

        private List<CWT> _activeTokens = new List<CWT>();

        protected override void DoPost(CoapExchange exchange)
        {
            try {
                exchange.Accept();

                Request req = exchange.Request;
                CWT cwt = null;

                switch (req.ContentFormat) {
                case MediaType.Undefined: // No Media type in the message
                    //  Don't know if this is correct.
                    cwt = CWT.Decode(req.Payload, _myKeys, _asSigningKeys);
                    break;

                case MediaType.ApplicationCwt:
                    cwt = CWT.Decode(req.Payload, _myKeys, _asSigningKeys);
                    break;

                case MediaType.ApplicationAceCbor:
                    CBORObject obj = CBORObject.DecodeFromBytes(req.Payload);
                    cwt = CWT.Decode(obj[CBORObject.FromObject(Oauth_Parameter.Access_Token.Key)].GetByteString(), _myKeys, _asSigningKeys);
                    break;

                default:
                    exchange.Respond(StatusCode.BadOption, "unknown or invalid content type");
                    return;
                }

                //  Need to validate that both 1) this is an issuer name we recognized and 2) it is the issuer name for the key
                if (cwt.HasClaim(ClaimId.Issuer)) {
                    _logger.Error(
                        m => m(
                            "There is an issuer claim in the token, but we don't know how to do any checks on this"));
                    exchange.Respond(StatusCode.Unauthorized);
                    return;
                }
                else if (cwt.HasClaim(ClaimId.CwtId)) {
                    _logger.Info(m => m("Token has a claim ID, but does not have an issuer name"));
                    exchange.Respond(StatusCode.BadRequest, "No Issuer w/ ID set");
                    return;
                }

            if (cwt.HasClaim(ClaimId.ExpirationTime)) {
                    _logger.Info(m => m("Token expires at {0}", cwt.ExperationTime));
                    if (cwt.ExperationTime <= DateTime.Now) {
                        exchange.Respond(StatusCode.Unauthorized);
                        return;
                    }
                }

                /*
                 * M00BUG Accept any Audience for now
                 */
                 
                if (cwt.HasClaim(ClaimId.Audience)) {
#if false
                    if (cwt.Audience != _audience) {
                        _logger.Info(m => m("Token for the wrong audience: got '{0}' and expected '{1}", cwt.Audience, _audience));
                        exchange.Respond(StatusCode.BadRequest, "Incorrect token");
                        return;
                    }
#else
                    _logger.Info("Not checking that audience is correct");
#endif
                }

                /*
                 * M00BUG - Accept any Scope for now
                 */

                if (cwt.HasClaim(ClaimId.Scope)) {
                    _logger.Info("We are not doing scope checks");
                }

                /*
                 * M00BUG - Reject if any fields exist we don't know about.
                 */

                _logger.Info("We don't reject CWTs that have other claims");


                // M00TODO - fill in a default value if there is no profile in the token
                if (cwt.Profile == null) {
                    cwt.Profile = (int?) ProfileIds.Coap_Dtls;
                }

                if ((cwt.Profile == null) || 
                    (cwt.Profile != (int) ProfileIds.Coap_Dtls && cwt.Profile != (int) ProfileIds.Coap_Oscore)) {
                    _logger.Info(m => m("Unrecognized CWT profile value:  Received '{0}", cwt.Profile));
                    exchange.Respond(StatusCode.BadRequest, "No profile");
                    return;
                }

                //  Is this a CWT that I have already seen?  If so then I can safely ignore it

                List<CWT> matches = new List<CWT>();
                foreach (CWT have in _activeTokens) {
                    //  Exact same token - replay
                    if (have.HasClaim(ClaimId.CwtId) && cwt.HasClaim(ClaimId.CwtId) && have.Issuer == cwt.Issuer &&
                        have.CwtId == cwt.CwtId) {
                        _logger.Info("Replay of CWT detected");
                        exchange.Respond(StatusCode.Changed);
                        return;
                    }

                    if (cwt.Profile == have.Profile) {
                        /*
                        if (cwt.Cnf.Key.Compare(have.Cnf.Key)) {
                            matches.Add(have);
                        }
                        */

                        if (cwt.Profile == (int) ProfileIds.Coap_Dtls) {
                            if (cwt.Cnf.Key.HasKeyType((int) GeneralValuesInt.KeyType_Octet)) {
                                if (cwt.Cnf.Key.Compare(have.Cnf.Key)) {
                                    if (cwt.Cnf.Key.ContainsName(CoseKeyKeys.KeyIdentifier) &&
                                        cwt.Cnf.Key.ContainsName(CoseKeyKeys.KeyIdentifier) &&
                                        cwt.Cnf.Key.HasKid(have.Cnf.Key[CoseKeyKeys.KeyIdentifier].GetByteString())) { 

                                        _logger.Info(
                                            "Two different keys with the same Key ID for TLS - not supported by TLS");
                                        exchange.Respond(StatusCode.BadRequest);
                                        return;
                                    }
                                    else {
                                        matches.Add(have);
                                    }
                                }
                            }
                            else if (cwt.Cnf.Key.HasKeyType((int) GeneralValuesInt.KeyType_EC2)) {
                                if (cwt.Cnf.Key.Compare(have.Cnf.Key)) {
                                    matches.Add(have);
                                }
                            }
                        }
                        else if (cwt.Profile == (int) ProfileIds.Coap_Oscore) {
                            ;
                            // M00TODO - decide what the duplicate detection logic should be.
                        }
                    }
                }

                if (matches.Count > 0) {
                    Debug.Assert(false, "TO BE IMPLEMENTED");
                    exchange.Respond(StatusCode.BadRequest);
                    return;
                }
                else {
                    if (cwt.Profile == (int) ProfileIds.Coap_Oscore) {
                        CBORObject obj = CBORObject.DecodeFromBytes(req.Payload);
                        byte[] clientSalt = new byte[0];
                        if (obj.ContainsKey((CBORObject) Oauth_Parameter.CNonce)) {
                            clientSalt = obj[(CBORObject) Oauth_Parameter.CNonce].GetByteString();
                        }

                        byte[] serverSalt = Encoding.UTF8.GetBytes("ServerSalt");

                        CBORObject oscoreContext = cwt.Cnf.AsCBOR[CBORObject.FromObject(Confirmation.ConfirmationIds.COSE_OSCORE)];


                        byte[] salt = null;
                        if (oscoreContext.ContainsKey(CBORObject.FromObject(6))) salt = oscoreContext[CBORObject.FromObject(6)].GetByteString();

                        byte[] context = null;
                        if (oscoreContext.ContainsKey(CBORObject.FromObject(7))) context = oscoreContext[CBORObject.FromObject(7)].GetByteString();

                        CBORObject alg = null;
                        if (oscoreContext.ContainsKey(CBORObject.FromObject(5))) {
                            alg = oscoreContext[CBORObject.FromObject(5)];
                        }
                        else {
                            // M00BUG Verify what this is supposed to default to.
                            _logger.Info("No algorithm for this CWT - assuming ?");
                            alg = AlgorithmValues.AES_CCM_16_64_128;
                        }

                        CBORObject kdf = null;
                        if (oscoreContext.ContainsKey(CBORObject.FromObject(4))) kdf = oscoreContext[CBORObject.FromObject(4)];

                        //  Build salt
                        byte[] newSalt = new byte[clientSalt.Length + serverSalt.Length + salt.Length];
                        Array.Copy(salt, newSalt, salt.Length);
                        Array.Copy(clientSalt, 0, newSalt, salt.Length, clientSalt.Length);
                        Array.Copy(serverSalt, 0, newSalt, salt.Length + clientSalt.Length, serverSalt.Length);

                        SecurityContext oscoapContext = SecurityContext.DeriveContext(
                            oscoreContext[CBORObject.FromObject(1)].GetByteString(),
                            context,
                            oscoreContext[CBORObject.FromObject(2)].GetByteString(),
                            oscoreContext[CBORObject.FromObject(3)].GetByteString(),
                            newSalt, alg, kdf);

                        oscoapContext.UserData = new List<CWT>() {cwt};
                        Program.OscoapContexts.Add(oscoapContext);
                        SecurityContextSet.AllContexts.Add(oscoapContext);

                        CBORObject cborReturn = CBORObject.NewMap();
                        cborReturn.Add((CBORObject) Oauth_Parameter.CNonce, serverSalt);
                        exchange.Respond( StatusCode.Created, cborReturn.EncodeToBytes(), MediaType.ApplicationAceCbor);
                    }
                    else if (cwt.Profile == (int) ProfileIds.Coap_Dtls) {
                        OneKey newKey = cwt.Cnf.Key;
                        newKey.UserData = new List<CWT>() {cwt};
                        Program.DtlsValidateKeys.AddKey(newKey);

                        exchange.Respond(StatusCode.Created);
                    }
                }

                _activeTokens.Add(cwt);
            }
            catch (CoseException e) {
                //
                //  Maybe we should do introspection?
                //

                byte[] rgb = TryIntrospection(exchange);

                //  If we get here then something good went wrong
                // KeyExchange.Respond(StatusCode.Unauthorized, "cose error");
            }
            catch (CwtException e) {
                //
                //  Maybe we should do introspection?
                //

                byte[] rgb = TryIntrospection(exchange);

                //  If we get here then something good went wrong
                // exchange.Respond(StatusCode.Unauthorized, "cwt error");
            }
            catch (Exception e) {

                byte[] rgb = TryIntrospection(exchange);
                //  If we get here then something bad went wrong
                // exchange.Respond(StatusCode.Unauthorized, "other error");
            }


        }

        private DateTime _lastNonceUpdate;
        private List<byte[]> _nonceList = new List<byte[]>();
        private TimeSpan _nodeUpdateFreq = new TimeSpan(0, 0, 20, 0);
        public byte[] CurrentNonce()
        {
            if (DateTime.Now - _lastNonceUpdate > _nodeUpdateFreq) {
                byte[] x = _nonceList[0];
                _nonceList.RemoveAt(_nonceList.Count-1);
                byte[] y = new byte[x.Length];
                Array.Copy(x, y, y.Length);
                for (int i = 0; i < y.Length; i++) {
                    y[i] += (byte) (29 * (i+1));
                }
                _nonceList.Insert(0, y);
            }

            return _nonceList[0];
        }

        private byte[] TryIntrospection(CoapExchange exchange)
        {
            Request req = exchange.Request;

            if (req.ContentFormat == MediaType.ApplicationCwt) {
                exchange.Respond(StatusCode.BadRequest);
            }

            byte[] payload;
            if (req.ContentFormat == MediaType.ApplicationAceCbor) {
                CBORObject obj = CBORObject.DecodeFromBytes(req.Payload);
                payload = obj[Oauth_Parameter.Access_Token.Key].GetByteString();
            }
            else {
                payload = exchange.Request.Payload;
            }

            //

            IntrospectRequest request = new IntrospectRequest() {
                Token = payload
            };

            IntrospecResponse iResponse = null;

            foreach (IntrospectionServer server in AuthServerList) {

                CoapClient client = new CoapClient(new Uri(server.AuthServerUrl));
                client.EndPoint = new DTLSClientEndPoint(server.AuthServerKey);
                client.EndPoint.Start();

                Com.AugustCellars.CoAP.Response response =
                    client.Post(request.EncodeToBytes(), MediaType.ApplicationOctetStream);

                if (response != null && response.StatusCode == StatusCode.Created) {
                    iResponse = new IntrospecResponse(response.Payload);
                    break;
                }
            }

            if (iResponse == null) {
                exchange.Respond(StatusCode.BadRequest);
                return null;
            }

            if (!iResponse.Active) {
                exchange.Respond(StatusCode.Unauthorized);
                return null;
            }

            OneKey newKey = new OneKey(iResponse.Cnf.Key.AsCBOR());

            CWT cwt = new CWT();
            cwt.Profile = iResponse.Profile;
            cwt.Cnf = iResponse.Cnf;
            cwt.Audience = iResponse.Audience;
            cwt.SetClaim(ClaimId.Scope, iResponse.Scope);
            newKey.UserData = new List<CWT>() {cwt};

            byte[] kid = newKey[CoseKeyKeys.KeyIdentifier].GetByteString();

            foreach (OneKey keyX in Program.DtlsValidateKeys)
            {
                if (keyX.HasKid(kid)) {
                    // Need an update to deal with this

                    exchange.Respond(StatusCode.BadGateway);
                    return null;
                }

            }

            Program.DtlsValidateKeys.AddKey(newKey);

            if (iResponse.HasKey(CBORObject.FromObject("client_token"))) {
                exchange.Respond(StatusCode.Created, iResponse.ClientToken, MediaType.ApplicationOctetStream);
            }
            else exchange.Respond(StatusCode.Created);

            return null;
        }

        public void AuthzForPsk(Object obj, TlsEvent tlsEvent)
        {
            if (tlsEvent.Code != TlsEvent.EventCode.UnknownPskName || 
                tlsEvent.KeyValue != null) {
                return;
            }

            try {
                CWT cwt = CWT.Decode(tlsEvent.PskName, _myKeys, _asSigningKeys);

                // M00TODO - fill in a default value if there is no profile in the token
                if (cwt.Profile == null) {
                    cwt.Profile = (int?)ProfileIds.Coap_Dtls;
                }

                if ((cwt.Profile == null) ||cwt.Profile != (int)ProfileIds.Coap_Dtls) {
                    _logger.Info(m => m("Unrecognized CWT profile value:  Received '{0}", cwt.Profile));
                    return;
                }

                // M00TODO - Actually process the CWT.

                OneKey newKey = new OneKey(cwt.Cnf.Key.AsCBOR());
                newKey.UserData = new List<CWT> {cwt};
                tlsEvent.KeyValue = newKey;

            }
            catch (CwtException e) {
                //  We don't introspect this - so just done set anything
                ;
            }
            catch (Exception) {
                //  Ignore all errors
                ;
            }
        }
    }
}
