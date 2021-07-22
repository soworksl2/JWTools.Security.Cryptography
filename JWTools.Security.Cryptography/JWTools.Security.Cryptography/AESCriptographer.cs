using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace JWTools.Security.Cryptography
{
    public static class AESCriptographer
    {
        public static string EncryptString(string plainText, string key = "default")
        {
            if (string.IsNullOrEmpty(key)) throw new ArgumentNullException("the key cannot be null");

            string output;
            byte[] processedKey = ProcessStringKey(key);
            byte[] processedIv = processedKey.Take(16).ToArray();

            using(AesManaged aes = new AesManaged() { Key = processedKey, IV = processedIv })
            {
                using(ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    using(MemoryStream memoryStream = new MemoryStream())
                    {
                        using( CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter streamWriter = new StreamWriter(cryptoStream, Encoding.UTF8))
                            {
                                streamWriter.Write(plainText);
                            }
                        }
                        output = Convert.ToBase64String(memoryStream.ToArray());
                    }
                }
            }

            return output;
        }

        public static string DecryptString(string cipherText, string key = "default")
        {
            if (string.IsNullOrEmpty(key)) throw new ArgumentNullException("the key cannot be null");

            string output;
            byte[] processedKey = ProcessStringKey(key);
            byte[] processedIv = processedKey.Take(16).ToArray();

            using (AesManaged aes = new AesManaged() { Key = processedKey, IV = processedIv })
            {
                using (ICryptoTransform encryptor = aes.CreateDecryptor())
                {
                    using (MemoryStream memoryStream = new MemoryStream(Convert.FromBase64String(cipherText)))
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Read))
                        {
                            using(StreamReader streamReader = new StreamReader(cryptoStream, Encoding.UTF8))
                            {
                                output = streamReader.ReadToEnd();
                            }
                        }
                    }
                }
            }

            return output;
        }

        private static byte[] ProcessStringKey(string key)
        {
            byte[] output = new byte[32];
            byte[] unprocesedKey = Encoding.UTF8.GetBytes(key);
            using (SHA256 sHA256 = SHA256.Create())
            {
                output = sHA256.ComputeHash(unprocesedKey);
            }

            return output;
        }
    }
}
