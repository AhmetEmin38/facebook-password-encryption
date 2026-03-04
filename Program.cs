using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace facebookPasswordEncryption
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string pass = "";
            string encryptedPass = FacebookPasswordEncryptor.Encrypt(pass);
            Console.WriteLine(encryptedPass);
        }

        public static class FacebookPasswordEncryptor
        {
            public static (string PublicKey, string KeyId) GetPublicKey()
            {
                using (var wc = new WebClient())
                {
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                    string url = "https://b-graph.facebook.com/pwd_key_fetch?version=2&flow=CONTROLLER_INITIALIZATION&method=GET&fb_api_req_friendly_name=pwdKeyFetch&fb_api_caller_class=com.facebook.auth.login.AuthOperations&access_token=438142079694454|fc0a7caa49b192f64f6f5a6d9643bb28";
                    var response = wc.DownloadString(url);
                    var json = JObject.Parse(response);
                    return (json["public_key"].ToString(), json["key_id"]?.ToString() ?? "25");
                }
            }

            public static string Encrypt(string password, string publicKey = null, string keyId = "25")
            {
                if (publicKey == null)
                {
                    var keys = GetPublicKey();
                    publicKey = keys.PublicKey;
                    keyId = keys.KeyId;
                }

                SecureRandom random = new SecureRandom();
                byte[] randKey = new byte[32];
                byte[] iv = new byte[12];
                random.NextBytes(randKey);
                random.NextBytes(iv);

                long currentTime = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;

                byte[] cleanKeyBytes = Convert.FromBase64String(publicKey
                    .Replace("-----BEGIN PUBLIC KEY-----", "")
                    .Replace("-----END PUBLIC KEY-----", "")
                    .Replace("\n", "").Replace("\r", "").Trim());

                AsymmetricKeyParameter pubKey = PublicKeyFactory.CreateKey(cleanKeyBytes);
                var rsaCipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
                rsaCipher.Init(true, pubKey);
                byte[] encryptedRandKey = rsaCipher.DoFinal(randKey);

                var aesCipher = new GcmBlockCipher(new AesEngine());
                var parameters = new AeadParameters(new KeyParameter(randKey), 128, iv, Encoding.UTF8.GetBytes(currentTime.ToString()));
                aesCipher.Init(true, parameters);

                byte[] plainBytes = Encoding.UTF8.GetBytes(password);
                byte[] output = new byte[aesCipher.GetOutputSize(plainBytes.Length)];
                int len = aesCipher.ProcessBytes(plainBytes, 0, plainBytes.Length, output, 0);
                aesCipher.DoFinal(output, len);

                byte[] encryptedPass = new byte[output.Length - 16];
                byte[] authTag = new byte[16]; // Hata buradaki isimden kaynaklanıyordu

                Array.Copy(output, 0, encryptedPass, 0, encryptedPass.Length);
                Array.Copy(output, encryptedPass.Length, authTag, 0, 16); // 'tag' yerine 'authTag' kullandık

                using (var ms = new MemoryStream())
                {
                    ms.WriteByte(1); // Version
                    ms.WriteByte(byte.Parse(keyId));
                    ms.Write(iv, 0, iv.Length);

                    short keyLen = (short)encryptedRandKey.Length;
                    ms.Write(BitConverter.GetBytes(keyLen), 0, 2);

                    ms.Write(encryptedRandKey, 0, encryptedRandKey.Length);
                    ms.Write(authTag, 0, authTag.Length);
                    ms.Write(encryptedPass, 0, encryptedPass.Length);

                    string encoded = Convert.ToBase64String(ms.ToArray());
                    return $"#PWD_FB4A:2:{currentTime}:{encoded}";
                }
            }
        }
    }



}
