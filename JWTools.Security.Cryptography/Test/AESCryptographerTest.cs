using JWTools.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;

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

        [ExpectedException(typeof(System.ArgumentNullException))]
        [DataRow(null, DisplayName = "EncryptString throw an ArgumentNullException when the plainText is null")]
        [DataRow("", DisplayName = "EncryptString throw an ArgumentNullException when the plaintText is empty")]
        [TestMethod]
        public void EncryptString_ThrowAnExceptionWhenThePlainTextIsNullOrEmpty(string plainText)
        {
            AESCriptographer.EncryptString(plainText);
        }

        [ExpectedException(typeof(System.ArgumentNullException))]
        [DataRow(null, DisplayName = "DecryptString throw an ArgumentNullException when the cipherText is null")]
        [DataRow("", DisplayName = "DecryptString throw an ArgumentNullException when the CipherText is empty")]
        [TestMethod]
        public void DecryptString_ThrownAnExceptionWhenTheCipherTextIsNullOrEmpty(string cipherText)
        {
            AESCriptographer.DecryptString(cipherText);
        }

        [TestMethod]
        public void EncryptAndDecryptFile()
        {
            bool debug = false;
            string dataTest = "Esto es un archivo de prueba que tiene que ser encriptado";
            string folderTest = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "EncriptorTest");
            string testerFilePath = Path.Combine(folderTest, "Encriptenme.txt");
            string encriptedFilePath = Path.Combine(folderTest, "ArchivoEncriptado." + AESCriptographer.ENCRYPTED_FILE_EXTENSION);
            string decryptedFilePath = Path.Combine(folderTest, "ArchivoDesencriptado.txt");

            if(Directory.Exists(folderTest))
                Directory.Delete(folderTest, true);

            Directory.CreateDirectory(folderTest);

            File.WriteAllText(testerFilePath, "Esto es un archivo de prueba que tiene que ser encriptado");

            AESCriptographer.EncryptFile(testerFilePath, encriptedFilePath);
            AESCriptographer.DecryptFile(encriptedFilePath, decryptedFilePath);

            string result = File.ReadAllText(decryptedFilePath);

            if(!debug)
                Directory.Delete(folderTest, true);

            Assert.AreEqual(dataTest, result);
        }
    }
}
