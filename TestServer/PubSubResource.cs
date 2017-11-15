using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Server.Resources;


namespace server
{
#if INCLUDE_PUBSUB
    public class PubSubResource : Resource
    {
        private readonly int Application_Link_Format = 65001;
        public PubSubResource(string name, Boolean root= false) : base(name)
        {
            Attributes.Title = "Pub/Sub Broker";
            Attributes.AddContentType(40);
            if (root) {
                Attributes.AddResourceType("core.ps");
            }
        }

        /// <summary>
        /// Posting to this resource will cause a new resource to be created.
        /// </summary>
        /// <param name="exchange"></param>
        protected override void DoPost(CoapExchange exchange)
        {
            try {
                Request req = exchange.Request;

                //  If there is a content-format, then it must be "application/link-format"
                if (req.HasOption(OptionType.ContentFormat)) {
                    if ((req.GetOptions(OptionType.ContentFormat).Count() != 1) && (req.GetFirstOption(OptionType.ContentFormat).IntValue != Application_Link_Format)) { 
                        exchange.Respond(StatusCode.BadOption);
                        return;
                    }
                }

                //  Parse the payload
                IEnumerable<WebLink> fmt = LinkFormat.Parse(exchange.Request.PayloadString);
                if (fmt.Count() != 1) {
                    exchange.Respond(StatusCode.BadRequest);
                    return;
                }

                WebLink item = fmt.First();

                //  Ensure resource does not already exist

                foreach (IResource child in Children) {
                    if (child.Name == item.Uri) {
                        exchange.Respond(StatusCode.Forbidden);
                        return;
                    }
                }

                Resource newResource;
                if (item.Attributes.Contains(LinkFormat.ContentType)) {
                    if (item.Attributes.GetContentTypes().Count() == 1) {
                        if (item.Attributes.GetContentTypes().First() == "application/link-format") {
                            newResource = new PubSubResource(item.Uri);
                        }
                        else {
                            newResource = new PubSubLeaf(item.Uri);
                        }
                    }
                    else {
                        newResource = new PubSubLeaf(item.Uri);
                    }
                }
                else {
                    newResource = new PubSubLeaf(item.Uri);
                }

                foreach (string key in item.Attributes.Keys) {
                    


                    IEnumerable<string> valueSet = item.Attributes.GetValues(key);
                    foreach (string value in valueSet) {
                        newResource.Attributes.Add(key, value);
                    }
                }

                if (req.HasOption(OptionType.MaxAge)) {
                    //  Figure out how to time out items M00TODO
                }

                this.Add(newResource);
                Response resp = new Response(StatusCode.Created);
                resp.LocationPath = this.Parent + "/" + item.Uri;
                exchange.Respond(resp);

            } catch (Exception)
            {
                exchange.Respond(StatusCode.BadRequest);
            }
        }

        protected override void DoDelete(CoapExchange exchange)
        {
            this.Delete();
            exchange.Respond(StatusCode.Deleted);
        }
    }
#endif
}
