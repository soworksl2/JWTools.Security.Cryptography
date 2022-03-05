using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Security;
using System.Runtime.InteropServices;
using System.IO;

namespace JWTools.Security.Cryptography
{
    public static class SHA256Helper
    {
        public static string SHA256ToBase64(this string strToComputeHash)
        {
            byte[] strAsByteArray = Encoding.UTF8.GetBytes(strToComputeHash);

            return Convert.ToBase64String(SHA256.Create().ComputeHash(strAsByteArray));
        }

        //TODO: Make more secure
        public static string SHA256ToBase64(this SecureString strToComputeHash)
        {
            return strToComputeHash.ToString().SHA256ToBase64();
        }
    }
}
