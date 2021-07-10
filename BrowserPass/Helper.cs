using System;
using System.IO;

namespace BrowserPass
{
    public static class Helper
    {
        public static readonly DirectoryInfo AppData =
            new DirectoryInfo(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
    }
}