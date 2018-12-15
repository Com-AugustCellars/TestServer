using System;
using System.CodeDom;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using CoAP.Examples.Resources;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.DTLS;
using Com.AugustCellars.CoAP.Log;
using Com.AugustCellars.CoAP.Server;
using Com.AugustCellars.CoAP.Server.Resources;
#if DEV_VERSION
using Com.AugustCellars.CoAP.TLS;
#endif

using Com.AugustCellars.COSE;
using Com.AugustCellars.CoAP.OSCOAP;
using PeterO.Cbor;
using Com.AugustCellars.CoAP.Net;
#if DEV_VERSION
using Com.AugustCellars.WebToken;
#endif
using server;

namespace TestServer
{
    class Program
    {
        private static readonly CBORObject _UsageKey = CBORObject.FromObject("usage");

        private static readonly KeySet DtlsSignKeys = new KeySet();
        public static readonly KeySet DtlsValidateKeys = new KeySet();
        private static readonly KeySet edhocKeys = new KeySet();
        private static OneKey edhocSign = null;


        public static SecurityContextSet OscoapContexts;

        public static ManualResetEvent ExitEvent = new ManualResetEvent(false);

        private static void PrintCommandLine()
        {
            Console.WriteLine("Command line for server is:");
            Console.WriteLine("server <args>");
            Console.WriteLine("");
            Console.WriteLine("--config=<fileName>\tLoad server configuration");
            Console.WriteLine("--generate=<fileName>\tGenerate a new set of keys");
            Console.WriteLine("--keyfile=<fileName>\tLoad initial keys from here");
            Console.WriteLine("--ipaddress=<address>\tAddress to run the server on");
            Console.WriteLine();
            Console.WriteLine("Load keys from Serverkeys.cbor by default");
            Environment.Exit(1);
        }

        static void GenerateKeys(string fileName)
        {
            if (fileName == null) fileName = "ServerKeys.cbor";

            KeySet keys = new KeySet();
            OneKey key;

            for (int i = 0; i < 4; i++) {
                key = new OneKey();
                key.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_Octet);
                if (i == 3) key.Add(CoseKeyKeys.KeyIdentifier, CBORObject.FromObject(Encoding.UTF8.GetBytes("Key#2")));
                else
                    key.Add(CoseKeyKeys.KeyIdentifier,
                            CBORObject.FromObject(Encoding.UTF8.GetBytes("Key#" + i.ToString())));
                if (i == 3) key.Add(CoseKeyKeys.Algorithm, AlgorithmValues.AES_CCM_64_128_128);
                else key.Add(CoseKeyKeys.Algorithm, AlgorithmValues.AES_CCM_64_64_128);
                key.Add(CBORObject.FromObject("KDF"), AlgorithmValues.dir_kdf);
                key.Add(CBORObject.FromObject("SenderID"), CBORObject.FromObject(Encoding.UTF8.GetBytes("client")));
                key.Add(CBORObject.FromObject("RecipID"), CBORObject.FromObject(Encoding.UTF8.GetBytes("server")));
                byte[] keyValue = new byte[35];
                for (int j = 0; j < keyValue.Length; j++) keyValue[j] = (byte) (((i + 1) * (j + 1)));
                key.Add(CoseKeyParameterKeys.Octet_k, CBORObject.FromObject(keyValue));

                keys.AddKey(key);
            }

            FileStream fs = new FileStream(fileName, FileMode.Create);
            using (BinaryWriter writer = new BinaryWriter(fs)) {
                writer.Write(keys.EncodeToBytes());
                writer.Close();
            }

            Environment.Exit(0);
        }

        static KeySet LoadKeys(string fileName)
        {
            if (fileName == null) fileName = "ServerKeys.cbor";
            KeySet keys = new KeySet();

            FileStream fs = new FileStream(fileName, FileMode.Open);
            using (BinaryReader reader = new BinaryReader(fs)) {
                byte[] data = reader.ReadBytes((int) fs.Length);
                CBORObject obj = CBORObject.DecodeFromBytes(data);

                for (int i = 0; i < obj.Count; i++) {

                    OneKey key = new OneKey(obj[i]);
                    string[] usages = key[_UsageKey].AsString().Split(' ');

                    foreach (String usage in usages) {

                        if (usage == "oscoap") {
                            SecurityContext ctx = SecurityContext.DeriveContext(
                                key[CoseKeyParameterKeys.Octet_k].GetByteString(),
                                key[CBORObject.FromObject("RecipID")].GetByteString(),
                                key[CBORObject.FromObject("SenderID")].GetByteString(), null,
                                key[CoseKeyKeys.Algorithm]);
                            SecurityContextSet.AllContexts.Add(ctx);
                            break;
                        }
#if DEV_VERSION
                        else if (usage == "oscoap-group") {
                            SecurityContext ctx = SecurityContext.DeriveGroupContext(
                                key[CoseKeyParameterKeys.Octet_k].GetByteString(),
                                key[CoseKeyKeys.KeyIdentifier].GetByteString(),
                                key[CBORObject.FromObject("sender")][CBORObject.FromObject("ID")].GetByteString(), null,
                                null, key[CoseKeyKeys.Algorithm]);
                            ctx.Sender.SigningKey = new OneKey(obj[i]["sign"]);
                            foreach (CBORObject recipient in key[CBORObject.FromObject("recipients")].Values) {
                                ctx.AddRecipient(recipient[CBORObject.FromObject("ID")].GetByteString(),
                                                 new OneKey(recipient["sign"]));
                            }

                            SecurityContextSet.AllContexts.Add(ctx);
                        }
#endif
                        else if (usage == "dtls") {
                            if (key.HasPrivateKey()) {
                                DtlsSignKeys.AddKey(key);
                            }
                            else {
                                DtlsValidateKeys.AddKey(key);
                            }
                        }

                        else if (usage == "edhoc") {
                            if (key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_EC) ||
                                key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_OKP)) {
                                if (key.ContainsName(CoseKeyParameterKeys.EC_D)) {
                                    edhocSign = key;
                                }
                                else {
                                    edhocKeys.AddKey(key);
                                }
                            }
                            else {
                                edhocKeys.AddKey(key);
                            }
                        }

                    }

                    if ((usages.Length != 1) || (usages[0] != "oscoap")) {
                        keys.AddKey(key);
                    }
                }

                reader.Close();
            }

            return keys;
        }

        static EndPoint ServerEndPoint = null;
        static bool AsDemon = false;

        static void Main(string[] args)
        {
            ICoapConfig config = null;
            KeySet allKeys = null;
            string interopTest = null;

            LogManager.Level = LogLevel.All;
            LogManager.Instance = new FileLogManager(Console.Out);

            for (int i = 0; i < args.Length; i++) {
                String[] s = args[i].Split('=');
                if (s.Length == 1) {
                    Array.Resize(ref s, 2);
                }

                switch (s[0]) {
                case "--generate":
                    GenerateKeys(s[1]);
                    break;

                case "--loadkeys":
                    allKeys = LoadKeys(s[1]);
                    break;

                case "--config":
                    if (s[1] == null) PrintCommandLine();
                    config = new CoapConfig();
                    config.Load(s[1]);
                    break;

                case "--demon":
                    AsDemon = true;
                    break;

                case "--ipAddr":
                case "--ipaddress":
                    if (s[1] == null) PrintCommandLine();
                    IPAddress ip;
                    if (!IPAddress.TryParse(s[1], out ip)) {
                        Console.WriteLine("Invalid ip-address");
                        PrintCommandLine();
                    }

                    ServerEndPoint = new IPEndPoint(ip, 0);

                    break;

                case "--interop-test":
                    if (s[1] == null) PrintCommandLine();
                    interopTest = s[1];
                    break;

                default:
                    PrintCommandLine();
                    break;
                }
            }

            if (interopTest != null) {
                RunInteropTests(interopTest, config, ServerEndPoint);
            }

            if (allKeys == null) {
                allKeys = LoadKeys(null);
            }

            if (true) {
                SecurityContext a = SecurityContext.DeriveContext(
                    new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 },
                    new byte[]{1}, new byte[0],
                    new byte[] { 0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40 });
                SecurityContextSet.AllContexts.Add(a);

                a = SecurityContext.DeriveGroupContext(
                    new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 },
                    new byte[] { 0x37, 0xcb, 0xf3, 0x21, 0x00, 0x17, 0xa2, 0xd3 }, new byte[]{1},
                    new byte[][] { new byte[] { } },
                    new byte[] { 0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40 });
                SecurityContextSet.AllContexts.Add(a);
            }

            CoapServer server1 = SetupServer(config, ServerEndPoint, CoapConfig.Default.DefaultPort, DtlsSignKeys, DtlsValidateKeys);
            CoapServer server2 = SetupServer(config, ServerEndPoint, 5685, DtlsSignKeys, DtlsValidateKeys);

            if (AsDemon) {
                ExitEvent.WaitOne();
            }
            else {
                Console.WriteLine("Press key to exit");
                Console.ReadKey();
            }

            server1.Stop();
            server2.Stop();
        }


        static CoapServer SetupServer(ICoapConfig config, EndPoint endPoint, int port, KeySet dtlsSignKeys,
                               KeySet dtlsValidateKeys)
        { 
            //
            //

            CoapServer server = new CoapServer(config, endPoint, port);
            if (port == CoapConfig.Default.DefaultPort) {
                server.AddMulticastAddress(new IPEndPoint(IPAddress.Parse("224.0.1.187"/*"[ff02::100]"*/), CoapConfig.Default.DefaultPort));
            }

            DTLSEndPoint ep2 = new DTLSEndPoint(dtlsSignKeys, dtlsValidateKeys, port+1);
            server.AddEndPoint(ep2);

            IResource root = new HelloWorldResource("hello", true);
            server.Add(root);

            IResource r2 = new OscoapTest("oscore");
            server.Add(r2);

            IResource r1 = new OscoapTest("hello");
            r2.Add(r1);

            r1.Add(new OscoapTest("coap"));
            IResource x = new OscoapTest("1");
            r1.Add(x);

            r1.Add(new OscoapTest("2"));
            r1.Add(new OscoapTest("3"));
            r1.Add(new OscoapTest("6"));
            r1.Add(new OscoapTest("7"));

            r2.Add(new OscoapTest("test"));

            r2.Add(new OscoapObserve("observe1"));
            r2.Add(new OscoapObserve("observe2"));

            r2.Add(new LargeResource("LargeResource"));

#if DEV_VERSION
            AceTest.Setup(server, "RS1");
#if false
            server.Add(new Com.AugustCellars.CoAP.EDHOC.EdhocResource(edhocKeys, edhocSign));
#endif

            //  Setup the ACE resources
            // string UseAsServer = "coaps://localhost:5689/token";
            string UseAsServer = "coaps://31.133.132.127/token";
            // UseAsServer = "coaps://31.133.134.176/token";

            KeySet myDecryptKeySet = new KeySet();
            OneKey key = new OneKey();

            key.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_Octet);
            key.Add(CoseKeyParameterKeys.Octet_k, CBORObject.FromObject(new byte[] { 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 }));
            key.Add(CoseKeyKeys.KeyIdentifier, CBORObject.FromObject(Encoding.UTF8.GetBytes("SERVER_KID")));
            key.Add(CoseKeyKeys.Algorithm, AlgorithmValues.AES_CCM_64_128_128);

            myDecryptKeySet.AddKey(key);

            key = new OneKey();
            key.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_Octet);
            key.Add(CoseKeyParameterKeys.Octet_k, CBORObject.FromObject(new byte[]{(byte)'a', (byte)'b', (byte)'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}));
            key.Add(CoseKeyKeys.KeyIdentifier, CBORObject.FromObject(new byte[] {0x70, 0x63, 0x6F, 0x61, 0x70, 0x3A, 0x2F, 0x2F, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74}));
            key.Add(CoseKeyKeys.Algorithm, CBORObject.FromObject(5));
            myDecryptKeySet.AddKey(key);

            AuthZ authZ = new AuthZ(myDecryptKeySet, null, ep2);
            server.Add(authZ);
            AceOAuthTest r = new AceOAuthTest("ace-echo", true, true, UseAsServer);
            r.AuthTokenProcessor = authZ;
            server.Add(r);
            OscoapContexts = SecurityContextSet.AllContexts;
#endif

            // ep2.Add(new AceOAuthTest("ace/echo", true, true, null));

#if INCLUDE_RD
            ResourceDirectoryResource.CreateResources(server);
#endif

#if DEV_VERSION
            // server = new CoapServer(config);
            CoAPEndPoint tcp = new TcpEndPoint(port);
            tcp.Start();
            server.AddEndPoint(tcp);

            // server.Add(new HelloWorldResource("hello", false));
            // server.Add(new LargeResource("LargeResource"));
            server.Add(new LargeResource("ExtraLargeResource", 20 * 1024));
            server.Add(new StorageResource("StorageHere"));
            server.Start();

            // server = new CoapServer(config);
            tcp = new TLSEndPoint(dtlsSignKeys, dtlsValidateKeys, port+1);
            tcp.Start();
            server.AddEndPoint(tcp);

            AceTest.Setup(server, "RS2");

            //server.Add(new HelloWorldResource("hello", false));

#endif

            server.Start();
            return server;

        }


        private static void RunInteropTests(string testToRun, ICoapConfig config, EndPoint serverEndPoint)
        {
            CoapServer server = new CoapServer(config, serverEndPoint, 5683);

            switch (testToRun) {
            case "CoapCore":
                InteropTests.CoapCoreTests.CoapCoreTests.Setup(server);
                break;

            default:
                Console.WriteLine("Interop test name not recognized");
                Environment.Exit(1);
                break;
            }

            server.Start();

            if (AsDemon) {
                ExitEvent.WaitOne();
            }
            else {
                Console.WriteLine("Press key to exit");
                Console.ReadKey();
            }

            Environment.Exit(0);
        }
    }
}

