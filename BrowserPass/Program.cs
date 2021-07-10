using System;
using System.Collections.Generic;

namespace BrowserPass
{
    // Missing windows.security? https://software.intel.com/en-us/articles/using-winrt-apis-from-desktop-applications
    // or check path to Windows.winmd in csproj file
    internal class Program
    {
        private static void Main()
        {
            var readers = new List<IPassReader>
            {
                new FirefoxPassReader(), new ChromePassReader(null, "Profile 1"), new Ie10PassReader()
            };

            foreach (var reader in readers)
            {
                Console.WriteLine($"== {reader.BrowserName} ============================================ ");
                try
                {
                    PrintCredentials(reader.ReadPasswords());
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error reading {reader.BrowserName} passwords: " + ex.Message);
                }
            }

#if DEBUG
            Console.ReadLine();
#endif

        }

        static void PrintCredentials(IEnumerable<CredentialModel> data)
        {
            foreach (var d in data)
                Console.WriteLine($"{d.Url}\r\n\tU: {d.Username}\r\n\tP: {d.Password}\r\n");
        }
    }
}