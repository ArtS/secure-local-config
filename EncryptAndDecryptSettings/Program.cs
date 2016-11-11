using System;
using System.Text;
using System.Configuration;
using System.Reflection;
using System.Security.Cryptography;
using System.IO;

namespace EncryptAndDecryptSettings
{
    class Program
    {
        // Password that's used to encypt / decrypt data
        private static string configPassword = "SecretKey";
        private static byte[] _salt = Encoding.ASCII.GetBytes("0123456789abcdef");

        private static void ReadAndPrintCurrentConfig()
        {
            var encryptedUsername = ConfigurationManager.AppSettings["username"];
            var encryptedPassword = ConfigurationManager.AppSettings["password"];

            var decryptedUsername = DecryptString(encryptedUsername, configPassword);
            var decryptedPassword = DecryptString(encryptedPassword, configPassword);

            Console.WriteLine(string.Format("Decrypted from config username: {0}", decryptedUsername));
            Console.WriteLine(string.Format("Decrypted from config password: {0}", decryptedPassword));
        }

        static void Main(string[] args)
        {
            // Reads, decrypts and prints to the console encoded values in the config
            ReadAndPrintCurrentConfig();

            // Update configuration file, store some arbitrary values, "new username" & "new password"
            var configuration = ConfigurationManager.OpenExeConfiguration(Assembly.GetExecutingAssembly().Location);
            configuration.AppSettings.Settings["username"].Value = EncryptString("new username", configPassword);
            configuration.AppSettings.Settings["password"].Value = EncryptString("new password", configPassword);
            configuration.Save();
            // Reload app config file
            ConfigurationManager.RefreshSection("appSettings");

            // Read and print to the console encrypted values
            var encryptedUsername = ConfigurationManager.AppSettings["username"];
            var encryptedPassword = ConfigurationManager.AppSettings["password"];
            Console.WriteLine(string.Format("Encrypted username: {0}", encryptedUsername));
            Console.WriteLine(string.Format("Encrypted password: {0}", encryptedPassword));
            
            // Decrypt username & password and print to the console
            var decryptedUsername = DecryptString(encryptedUsername, configPassword);
            var decryptedPassword = DecryptString(encryptedPassword, configPassword);

            Console.WriteLine(string.Format("Decrypted username: {0}", decryptedUsername));
            Console.WriteLine(string.Format("Decrypted password: {0}", decryptedPassword));
        }

        public static string EncryptString(string plainText, string sharedSecret)
        {
            string result = null;
            RijndaelManaged aesAlg = null;

            try
            {
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, _salt);
                aesAlg = new RijndaelManaged();
                aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    msEncrypt.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, sizeof(int));
                    msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                    }
                    result = Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
            finally
            {
                if (aesAlg != null)
                    aesAlg.Clear();
            }

            return result;
        }
                
        public static string DecryptString(string cipherText, string sharedSecret)
        {
            RijndaelManaged aesAlg = null;
            string result = null;

            try
            {
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, _salt);
                byte[] bytes = Convert.FromBase64String(cipherText);
                using (MemoryStream msDecrypt = new MemoryStream(bytes))
                {
                    aesAlg = new RijndaelManaged();
                    aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                    aesAlg.IV = ReadByteArray(msDecrypt);
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            result = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            finally
            {
                if (aesAlg != null)
                    aesAlg.Clear();
            }

            return result;
        }

        private static byte[] ReadByteArray(Stream s)
        {
            byte[] rawLength = new byte[sizeof(int)];
            if (s.Read(rawLength, 0, rawLength.Length) != rawLength.Length)
            {
                throw new SystemException("Stream did not contain properly formatted byte array");
            }

            byte[] buffer = new byte[BitConverter.ToInt32(rawLength, 0)];
            if (s.Read(buffer, 0, buffer.Length) != buffer.Length)
            {
                throw new SystemException("Did not read byte array properly");
            }

            return buffer;
        }
    }
}
