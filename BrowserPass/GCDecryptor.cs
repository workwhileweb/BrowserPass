﻿using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using Newtonsoft.Json;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace BrowserPass
{
    public static class GcDecryptor
    {
        public static byte[] GetKey()
        {
            var path = Path.GetFullPath(Helper.AppData.FullName + "\\..\\Local\\Google\\Chrome\\User Data\\Local State");

            var v = File.ReadAllText(path);

            dynamic json = JsonConvert.DeserializeObject(v);
            string key = json.os_crypt.encrypted_key;

            var src = Convert.FromBase64String(key);
            var encryptedKey = src.Skip(5).ToArray();

            var decryptedKey = ProtectedData.Unprotect(encryptedKey, null, DataProtectionScope.CurrentUser);

            return decryptedKey;
        }

        public static string Decrypt(byte[] encryptedBytes, byte[] key, byte[] iv)
        {
            var sR = string.Empty;
            try
            {
                var cipher = new GcmBlockCipher(new AesEngine());
                var parameters = new AeadParameters(new KeyParameter(key), 128, iv, null);

                cipher.Init(false, parameters);
                var plainBytes = new byte[cipher.GetOutputSize(encryptedBytes.Length)];
                var retLen = cipher.ProcessBytes(encryptedBytes, 0, encryptedBytes.Length, plainBytes, 0);
                cipher.DoFinal(plainBytes, retLen);

                sR = Encoding.UTF8.GetString(plainBytes).TrimEnd("\r\n\0".ToCharArray());
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.StackTrace);
            }

            return sR;
        }

        public static void Prepare(byte[] encryptedData, out byte[] nonce, out byte[] ciphertextTag)
        {
            nonce = new byte[12];
            ciphertextTag = new byte[encryptedData.Length - 3 - nonce.Length];

            Array.Copy(encryptedData, 3, nonce, 0, nonce.Length);
            Array.Copy(encryptedData, 3 + nonce.Length, ciphertextTag, 0, ciphertextTag.Length);
        }
    }
}
