using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace JWTools.Security.Cryptography
{
    public static class AESCriptographer
    {
        public const string ENCRYPTED_FILE_EXTENSION = "jwlock";

        public static string EncryptString(string plainText, string key = "default")
        {

            if (string.IsNullOrEmpty(plainText)) throw new ArgumentNullException("the plainText to encrypt cannot be null or empty");
            if (string.IsNullOrEmpty(key)) throw new ArgumentNullException("the key cannot be null or empty");

            string output;

            using (ICryptoTransform encryptor = GetCryptoTransformByStringKey(key, KindCryptoTransform.Encryptor))
            {
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new StreamWriter(cryptoStream, Encoding.UTF8))
                        {
                            streamWriter.Write(plainText);
                        }
                    }
                    output = Convert.ToBase64String(memoryStream.ToArray());
                }
            }

            return output;
        }

        public static string DecryptString(string cipherText, string key = "default")
        {
            if (string.IsNullOrEmpty(cipherText)) throw new ArgumentNullException("the cipherText to decrypt cannot be null or empty");
            if (string.IsNullOrEmpty(key)) throw new ArgumentNullException("the key cannot be null");

            string output;

            using (ICryptoTransform encryptor = GetCryptoTransformByStringKey(key, KindCryptoTransform.Decryptor))
            {
                using (MemoryStream memoryStream = new MemoryStream(Convert.FromBase64String(cipherText)))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader(cryptoStream, Encoding.UTF8))
                        {
                            output = streamReader.ReadToEnd();
                        }
                    }
                }
            }

            return output;
        }

        public static void EncryptFile(string plainFilePath, string outputCipherFilePath = "", string key = "default")
        {
            if (!File.Exists(plainFilePath)) throw new ArgumentException("the file not exist");
            if (string.IsNullOrEmpty(key)) throw new ArgumentNullException("the key cannot be null or empty");

            if (string.IsNullOrWhiteSpace(outputCipherFilePath))
                outputCipherFilePath = Path.ChangeExtension(plainFilePath, ENCRYPTED_FILE_EXTENSION);
            else if (string.IsNullOrEmpty(Path.GetExtension(outputCipherFilePath)))
                outputCipherFilePath = Path.ChangeExtension(outputCipherFilePath, ENCRYPTED_FILE_EXTENSION);

            using (ICryptoTransform encryptor = GetCryptoTransformByStringKey(key, KindCryptoTransform.Encryptor))
            {
                using (FileStream cipherFileOutput = new FileStream(outputCipherFilePath, FileMode.Create, FileAccess.Write))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(cipherFileOutput, encryptor, CryptoStreamMode.Write))
                    {
                        using(FileStream plainFileStream = new FileStream(plainFilePath, FileMode.Open, FileAccess.Read))
                        {
                            plainFileStream.CopyTo(cryptoStream);
                        }
                    }
                }
            }
        }

        public static void DecryptFile(string cipherFilePath, string outputPlainFilePath, string key = "default")
        {
            if (string.IsNullOrEmpty(key)) throw new ArgumentNullException("the key cannot be null or empty");
            if (string.IsNullOrWhiteSpace(cipherFilePath)) throw new ArgumentNullException("cipherFilePath cannot be null");
            if (string.IsNullOrWhiteSpace(outputPlainFilePath)) throw new ArgumentNullException("outputPlainFilePath cannot be null");
            if (Path.GetFullPath(cipherFilePath) == Path.GetFullPath(outputPlainFilePath)) 
                throw new ArgumentException("the cipherFilePath and the outputPlainFilePath cannot be equals");

            using(ICryptoTransform cryptoTransform = GetCryptoTransformByStringKey(key, KindCryptoTransform.Decryptor))
            {
                using(FileStream outputPlainFileStream = new FileStream(outputPlainFilePath, FileMode.Create, FileAccess.Write))
                {
                    using(CryptoStream cryptoStream = new CryptoStream(outputPlainFileStream, cryptoTransform, CryptoStreamMode.Write))
                    {
                        using(FileStream cipherFileStream = new FileStream(cipherFilePath, FileMode.Open, FileAccess.Read))
                        {
                            cipherFileStream.CopyTo(cryptoStream);
                        }
                    }
                }
            }
        }

        private static ICryptoTransform GetCryptoTransformByStringKey(string key, KindCryptoTransform kindCryptoTransform)
        {
            ICryptoTransform output;

            byte[] keyAsByteArray = Encoding.UTF8.GetBytes(key);
            byte[] keyProcessed;
            byte[] ivProcessed;
            using (SHA256 sha256 = SHA256.Create())
            {
                keyProcessed = sha256.ComputeHash(keyAsByteArray);
            }
            ivProcessed = keyProcessed.Take(16).ToArray();

            using (AesManaged aes = new AesManaged() { Key = keyProcessed, IV = ivProcessed })
            {
                if (kindCryptoTransform == KindCryptoTransform.Encryptor)
                    output = aes.CreateEncryptor();
                else
                    output = aes.CreateDecryptor();
            }

            return output;
        }

        private enum KindCryptoTransform
        {
            Encryptor,
            Decryptor
        }
    }
}
