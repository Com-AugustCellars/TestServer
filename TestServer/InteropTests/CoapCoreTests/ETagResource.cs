using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Server.Resources;

namespace TestServer
{
    class ETagResource : Resource
    {
        private bool _hasContent = false;
        byte[] _eTag = new byte[2];
        private byte[] _content;
        private int? _contentFormat;

        public ETagResource(string name, bool createContent = false) : base(name)
        {
            if (createContent) {
                _hasContent = true;
                _content = Encoding.UTF8.GetBytes("entry content");
            }
        }

        protected override void DoGet(CoapExchange exchange)
        {
            if (!_hasContent) {
                exchange.Respond(StatusCode.NotFound);
                return;
            }

            Request req = exchange.Request;

            if (req.HasOption(OptionType.ETag)) {
                foreach (byte[] tag in req.ETags) {
                    if (ArrayMatch(tag, _eTag)) {
                        exchange.Respond(StatusCode.Valid);
                        return;
                    }
                }
            }

            exchange.ETag = _eTag;
            
            if (_contentFormat != null) {
                exchange.Respond(StatusCode.Content, _content, (int) _contentFormat);   
            }
            else {
                exchange.Respond(StatusCode.Content, _content);
            }

        }

        protected override void DoPost(CoapExchange exchange)
        {
            Request req = exchange.Request;

            if (req.HasOption(OptionType.IfNoneMatch) && _hasContent) {
                exchange.Respond(StatusCode.PreconditionFailed);
                return;
            }

            if (req.HasOption(OptionType.IfMatch)) {
                if (!_hasContent) {
                    exchange.Respond(StatusCode.PreconditionFailed);
                    return;
                }

                bool match = false;

                foreach (byte[] tag in req.IfMatches) {
                    if (ArrayMatch(tag, _eTag)) {
                        match = true;
                        break;
                    }
                }

                if (!match) {
                    exchange.Respond(StatusCode.PreconditionFailed);
                    return;
                }
            }

            _content = req.Payload;
            if (req.HasOption(OptionType.ContentFormat)) {
                _contentFormat = req.ContentFormat;
            }
            else {
                _contentFormat = null;
            }

            _eTag[0] += 1;
            if (_eTag[0] == 0) _eTag[1] += 1;
            
            exchange.Respond(_hasContent ? StatusCode.Changed : StatusCode.Created);
            _hasContent = true;

            return;
        }


        private bool ArrayMatch(byte[] left, byte[] right)
        {
            if (left.Length != right.Length) return false;
            for (int i=0; i<left.Length; i++) {
                if (left[i] != right[i]) return false;
            }
            return true;
        }
    }
}
