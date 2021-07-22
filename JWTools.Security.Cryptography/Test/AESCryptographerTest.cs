using JWTools.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Test
{
    [TestClass]
    public class AESCryptographerTest
    {
        [DataRow("Hola mundo")]
        [DataRow("ñiñí que ñoño", DisplayName = "Encrypt And Decrypt String Correctly With spanish characters")]
        [DataRow("kakarikó!\"@#$%^&*()_-+=`~", DisplayName = "Encrypt And Decrypt String Correctly With Symbol")]
        [DataRow("\tEsto no me gusta\nAmi si me gusta;\n\tY ami tambien?", DisplayName = "Encrypt And Decrypt String Correctly With escapes")]
        [TestMethod]
        public void EncryptAndDecryptStringcorrectly(string testText)
        {
            string testKey = "testKey";
            string encriptedText;
            string decryptedText;

            encriptedText = AESCriptographer.EncryptString(testText, testKey);
            decryptedText = AESCriptographer.DecryptString(encriptedText, testKey);

            Assert.AreEqual(testText, decryptedText);
        }

        [TestMethod]
        public void EncryptAndDecryptStringCorrectlyWithDefaultKey()
        {
            string plainText = "Hello World!";
            string encriptedText;
            string decryptedText;

            encriptedText = AESCriptographer.EncryptString(plainText);
            decryptedText = AESCriptographer.DecryptString(encriptedText);

            Assert.AreEqual(plainText, decryptedText);
        }

        [ExpectedException(typeof(System.ArgumentNullException))]
        [TestMethod]
        public void EncryptString_throwAnExceptionWhenTheKeyIsNullOrEmpty()
        {
            string plainText = "Hello World!";

            AESCriptographer.EncryptString(plainText, "");
        }

        [ExpectedException(typeof(System.ArgumentNullException))]
        [TestMethod]
        public void DecryptString_throwAnExceptionWhenTheKeyIsNullOrEmpty()
        {
            string plainText = "Hellow";

            AESCriptographer.DecryptString(plainText, null);
        }
    }
}
