using PeterO.Cbor;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;

namespace TestServer
{
    class Permission
    {
        public List<string> Tags = new List<string>();
        public List<Method> Methods = new List<Method>();
        public bool AnyMethod { get; }

        public Permission(CBORObject obj)
        {
#if true
            if (obj.Type == CBORType.TextString) {
                Tags.Add(obj.AsString());
                AnyMethod = true;
            }
            else if (obj.Type == CBORType.Array) {
                if (obj[0].Type == CBORType.Array) {
                    foreach (CBORObject o in obj[0].Values) {
                        Tags.Add(o.AsString());
                    }
                }
                else {
                    Tags.Add(obj[0].AsString());
                }

                foreach (CBORObject o in obj[1].Values) {
                    Methods.Add((Method) o.AsInt32());
                }
            }
#else
            if (obj[0].Type == CBORType.TextString) {
                Tags.Add(obj[0].AsString());
            }
            else if (obj[0].Type == CBORType.Array) {
                foreach (CBORObject o in obj[0].Values) {
                    Tags.Add(o.AsString());
                }
            }
            else {
                throw new FormatException("Expected Array or TextString");
            }

            foreach (CBORObject o in obj[1].Values) {
                switch (o.AsString().ToUpper()) {
                    case "GET":
                        Methods.Add(Method.GET);
                        break;

                    case "PUT":
                        Methods.Add(Method.PUT);
                        break;

                    case "POST":
                        Methods.Add(Method.POST);
                        break;

                    default:
                        throw new NotImplementedException($"Method {o.AsString()} unrecognized");
                }
            }
#endif
        }


        public Permission(string tag, Method[] methods)
        {
            Methods.AddRange(methods);
            Tags.Add(tag);
        }

        public Permission(string tag, Method methods)
        {
            Methods.Add(methods);
            Tags.Add(tag);
        }

        public bool Allows(Permission request)
        {
            foreach (string s in request.Tags) {
                if (!Tags.Contains(s)) return false;
            }

            if (!AnyMethod) {
                foreach (Method m in request.Methods) {
                    if (!Methods.Contains(m)) return false;
                }
            }

            return true;
        }

        public CBORObject AsCBOR()
        {
            CBORObject root = CBORObject.NewArray();
            if (Tags.Count == 1) {
                root.Add(Tags[0]);
            }
            else {
                CBORObject x = CBORObject.NewArray();
                foreach (string s in Tags) {
                    x.Add(s);
                }
                root.Add(x);
            }

            CBORObject m1 = CBORObject.NewArray();
            foreach (Method m in Methods) {
                m1.Add(m);
            }
            root.Add(m1);
            return root;
        }
    }

    class PermissionSet
    {
        public List<Permission> Permissions { get; } = new List<Permission>();
        private static Method[] allMethods = new Method[] {
            Method.GET, Method.POST, Method.PUT, Method.DELETE,
            Method.FETCH, Method.PATCH, Method.iPATCH
        };

        /*
        public PermissionSet(CBORObject obj)
        {
            foreach (CBORObject o in obj.Values) {
                Permission p = new Permission(o);
                Permissions.Add(p);
            }
        }

        /// <summary>
        /// What string formats are wanted 
        /// "string"
        /// "GET string"
        /// Above as comma separated list.
        /// </summary>
        /// <param name="permissions"></param>
        public PermissionSet(string permissions)
        {
            foreach (String line in permissions.Split(',')) {
                string[] fields = line.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length == 1) {
                    Permissions.Add(new Permission(fields[0], new Method[] { Method.GET, Method.PUT, Method.POST }));
                }
                else if (fields.Length == 2) {
                    Method m;
                    switch (fields[1].ToUpper()) {
                        case "GET": m = Method.GET; break;
                        case "PUT": m = Method.PUT; break;
                        case "POST": m = Method.POST; break;
                        default:
                            throw new Exception("Unknown method");
                    }
                    Permissions.Add(new Permission(fields[0], m));
                }
                else {
                    throw new Exception("Invalid data format");
                }
            }
        }

        */

        public PermissionSet(CBORObject permits)
        {
            if (permits.Type == CBORType.ByteString) {
                CBORObject obj = CBORObject.DecodeFromBytes(permits.GetByteString());
                if (obj.Type == CBORType.Array) {
                    if (obj[0].Type == CBORType.TextString) {
                        Permissions.Add(new Permission(obj));
                    }
                    else if (obj[0].Type == CBORType.Array) {
                        foreach (CBORObject o in obj.Values) {
                            Permissions.Add(new Permission(o));
                        }
                    }
                    else {
                        throw new Exception("Unknown Scope structure");
                    }
                }
                else {
                    throw new Exception("Unknown Scope structure");
                }
            }
            else if (permits.Type == CBORType.TextString) {
                string s = permits.AsString();
                string[] strs = s.Split(' ');
                foreach (string s1 in strs) {
                    Permissions.Add(new Permission(s1, allMethods));
                }
            }
            else {
                //  For now just ignore things we don't understand
            }
        }

        public bool Allows(PermissionSet request)
        {
            foreach (Permission p1 in request.Permissions) {
                bool found = false;
                    foreach (Permission p in Permissions) {
                        if (p.Allows(p1)) {
                            found = true;
                            break;
                        }
                }

                if (!found) return false;
            }
            return true;
        }

        public bool Allows(Permission request)
        {
            foreach (Permission p1 in Permissions) {
                if (p1.Allows(p1)) return true;
            }

            return false;
        }

        public CBORObject AsCBOR()
        {
            CBORObject obj = CBORObject.NewArray();

            foreach (Permission p in Permissions) {
                obj.Add(p.AsCBOR());
            }

            return obj;
        }
    }
}
