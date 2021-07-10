using System.Collections.Generic;
using System.IO;

namespace BrowserPass
{
    internal interface IPassReader
    {
        IEnumerable<CredentialModel> ReadPasswords();
        string BrowserName { get; }
    }
}