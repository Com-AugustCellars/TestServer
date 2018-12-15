using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Remoting.Channels;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Server.Resources;

namespace server
{
    class OscoapObserve : Resource
    {
        private int counter = 0;
        private Timer _timer;

        public OscoapObserve(String name)
            : base(name)
        {
            int seconds = 5;

            Attributes.Title = "GET a friendly greeting!";
            Attributes.AddResourceType("OSCOAP-Tester");
            Observable = true;

            _timer = new Timer(Timed, null, 0, seconds * 1000);
        }

        private void Timed(Object o)
        {
            if (counter > 0) {
                Changed();
            }
        }

        protected override void DoGet(CoapExchange exchange)
        {
            Console.WriteLine("GET on /hello with ");
            Console.WriteLine(Com.AugustCellars.CoAP.Util.Utils.ToString(exchange.Request));

            if (exchange.Request.OscoapContext == null) {
                exchange.Respond("Hello World! -- I see no OSCOAP here");
            }
            else {
                Request request = exchange.Request;

                if (counter == 0) counter = 3;

                Console.WriteLine($"Do a objserve w/ the counter={counter}");

                switch (counter) {
                case 3:
                    exchange.Respond(StatusCode.Content, "one", MediaType.TextPlain);
                    break;

                case 2:
                    exchange.Respond(StatusCode.Content, "two", MediaType.TextPlain);
                    break;

                case 1:
                    if (Name == "observe1") {
                        exchange.Respond(StatusCode.InternalServerError);
                    }
                    else {
                        exchange.Respond(StatusCode.Content, "Terminate Observe");
                    }

                    exchange.CancelObserve();
                    break;

                default:
                    exchange.Respond(StatusCode.InternalServerError);
                    counter = 0;
                    break;
                }

                counter -= 1;
            }
        }
    }
}
