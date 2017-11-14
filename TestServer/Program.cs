using System;
using System.Collections.Generic;
using System.IO;
using System.Net.NetworkInformation;
using System.Text;
using CoAP.Examples.Resources;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.DTLS;
using Com.AugustCellars.CoAP.Log;
using Com.AugustCellars.CoAP.Server;
using Com.AugustCellars.CoAP.Server.Resources;
using Com.AugustCellars.CoAP.TLS;

using Com.AugustCellars.COSE;
using Com.AugustCellars.CoAP.OSCOAP;
using PeterO.Cbor;
using server;

namespace TestServer
{
    class Program
    {
        private static  readonly CBORObject _UsageKey = CBORObject.FromObject("usage");

        private static readonly KeySet DtlsSignKeys = new KeySet();
        private static readonly KeySet DtlsValidateKeys = new KeySet();
        private static   readonly          KeySet edhocKeys = new KeySet();
        private static     OneKey edhocSign = null;



        static void PrintCommandLine()
        {
            Console.WriteLine("Command line for server is:");
            Console.WriteLine("server <args>");
            Console.WriteLine("");
            Console.WriteLine("--config=<fileName>\tLoad server configuration");
            Console.WriteLine("--generate=<fileName>\tGenerate a new set of keys");
            Console.WriteLine("--keyfile=<fileName>\tLoad initial keys from here");
            Console.WriteLine();
            Console.WriteLine("Load keys from Serverkeys.cbor by default");
            Environment.Exit(1);
        }

        static void GenerateKeys(string fileName)
        {
            if (fileName == null) fileName = "ServerKeys.cbor";

            KeySet keys = new KeySet();
            OneKey key;

            for (int i=0; i<4; i++) {
                key = new OneKey();
                key.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_Octet);
                if (i == 3) key.Add(CoseKeyKeys.KeyIdentifier, CBORObject.FromObject(Encoding.UTF8.GetBytes("Key#2")));
                else key.Add(CoseKeyKeys.KeyIdentifier, CBORObject.FromObject(Encoding.UTF8.GetBytes("Key#" + i.ToString())));
                if (i == 3) key.Add(CoseKeyKeys.Algorithm, AlgorithmValues.AES_CCM_64_128_128);
                else key.Add(CoseKeyKeys.Algorithm, AlgorithmValues.AES_CCM_64_64_128);
                key.Add(CBORObject.FromObject("KDF"), AlgorithmValues.dir_kdf);
                key.Add(CBORObject.FromObject("SenderID"), CBORObject.FromObject(Encoding.UTF8.GetBytes("client")));
                key.Add(CBORObject.FromObject("RecipID"), CBORObject.FromObject(Encoding.UTF8.GetBytes("server")));
                byte[] keyValue = new byte[35];
                for (int j = 0; j < keyValue.Length; j++) keyValue[j] = (byte) (((i+1) * (j+1)));
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

                        else if (usage == "oscoap-group") {
                            SecurityContext ctx = SecurityContext.DeriveGroupContext(key[CoseKeyParameterKeys.Octet_k].GetByteString(), key[CoseKeyKeys.KeyIdentifier].GetByteString(), 
                                key[CBORObject.FromObject("sender")][CBORObject.FromObject("ID")].GetByteString(), null, null, key[CoseKeyKeys.Algorithm]);
                            ctx.Sender.SigningKey = new OneKey(obj[i]["sign"]);
                            foreach (CBORObject recipient in key[CBORObject.FromObject("recipients")].Values) {
                                ctx.AddRecipient(recipient[CBORObject.FromObject("ID")].GetByteString(), new OneKey(recipient["sign"]));
                            }
                            SecurityContextSet.AllContexts.Add(ctx);
                        }

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

        static void Main(string[] args)
        {
            ICoapConfig config = null;
            KeySet allKeys = null;

            LogManager.Level = LogLevel.All;
            LogManager.Instance = new FileLogManager(Console.Out);

            for (int i=0; i<args.Length; i++) {
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

                    default:
                        PrintCommandLine();
                        break;
                }
            }

            if (allKeys == null) {
                allKeys = LoadKeys(null);
            }



            //
            //  We listen only on the default port
            //

            CoapServer server = new CoapServer(config, CoapConfig.Default.DefaultPort);
            DTLSEndPoint ep2 = new DTLSEndPoint(DtlsSignKeys, DtlsValidateKeys, CoapConfig.Default.DefaultSecurePort);
            server.AddEndPoint(ep2);

            IResource root = new HelloWorldResource("hello", true);
            server.Add(root);

            IResource x = new OscoapTest("coap");
            root.Add(x);

            x = new OscoapTest("1");
            root.Add(x);

            root.Add(new OscoapTest("2"));
            root.Add(new OscoapTest("3"));
            root.Add(new OscoapTest("6"));
            root.Add(new OscoapTest("7"));

            server.Add(new OscoapTest("test"));

            server.Add(new TimeResource("observe"));

            server.Add(new LargeResource("LargeResource"));

#if true

            server.Add(new Com.AugustCellars.CoAP.EDHOC.EdhocResource(edhocKeys, edhocSign));
#endif



            server.Start();

            server = new CoapServer(config);
            TcpEndPoint tcp = new TcpEndPoint(CoapConfig.Default.DefaultPort);
            tcp.Start();
            server.AddEndPoint(tcp);

            server.Add(new HelloWorldResource("hello", false));
            server.Start();

            Console.WriteLine("Press key to exit");
            Console.ReadKey();

        }
    }
}
