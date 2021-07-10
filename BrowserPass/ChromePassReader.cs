using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.IO;

namespace BrowserPass
{
    /// <summary>
    ///     http://raidersec.blogspot.com/2013/06/how-browsers-store-your-passwords-and.html#chrome_decryption
    /// </summary>
    internal class ChromePassReader : IPassReader
    {
        private readonly string _loginDataPath;

        public ChromePassReader(FileSystemInfo dataFolder, string profileFolderName)
        {
            DataFolder = dataFolder ?? new DirectoryInfo(Path.Combine(Helper.AppData.FullName, @"..\Local\Google\Chrome\User Data"));
            ProfileFolderName = profileFolderName ?? "Default";
            _loginDataPath = Path.Combine(DataFolder.FullName, ProfileFolderName, @"Login Data");
        }

        public FileSystemInfo DataFolder { get; }
        public string ProfileFolderName { get; }
        public string BrowserName => "Chrome";


        public IEnumerable<CredentialModel> ReadPasswords()
        {
            var result = new List<CredentialModel>();

            if (!File.Exists(_loginDataPath)) throw new FileNotFoundException(_loginDataPath);
            var cloned = _loginDataPath + ".copied";
            File.Copy(_loginDataPath,cloned);
            using (var conn = new SQLiteConnection($"Data Source={cloned};"))
            {
                conn.Open();
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = "SELECT action_url, username_value, password_value FROM logins";
                    using (var reader = cmd.ExecuteReader())
                    {
                        if (reader.HasRows)
                        {
                            var key = GcDecryptor.GetKey();
                            while (reader.Read())
                            {
                                var encryptedData = GetBytes(reader, 2);
                                GcDecryptor.Prepare(encryptedData, out var nonce, out var ciphertextTag);
                                var pass = GcDecryptor.Decrypt(ciphertextTag, key, nonce);

                                result.Add(new CredentialModel
                                {
                                    Url = reader.GetString(0),
                                    Username = reader.GetString(1),
                                    Password = pass
                                });
                            }
                        }
                    }
                }

                conn.Close();
            }
            File.Delete(cloned);
            return result;
        }

        private static byte[] GetBytes(IDataRecord reader, int columnIndex)
        {
            const int chunkSize = 2 * 1024;
            var buffer = new byte[chunkSize];
            long fieldOffset = 0;
            using (var stream = new MemoryStream())
            {
                long bytesRead;
                while ((bytesRead = reader.GetBytes(columnIndex, fieldOffset, buffer, 0, buffer.Length)) > 0)
                {
                    stream.Write(buffer, 0, (int) bytesRead);
                    fieldOffset += bytesRead;
                }

                return stream.ToArray();
            }
        }
    }
}