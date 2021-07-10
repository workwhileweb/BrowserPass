using System;
using System.Runtime.InteropServices;
using System.Text;

namespace BrowserPass
{
    /// <summary>
    /// Firefox helper class
    /// </summary>
    internal static class FfDecryptor
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string dllFilePath);
        static IntPtr NSS3;
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate long DLLFunctionDelegate(string configdir);

        private const string ffFolderName = @"\Mozilla Firefox\";
        public static long NSS_Init(string configdir)
        {

            var mozillaPath = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) + ffFolderName;
            if(!System.IO.Directory.Exists(mozillaPath))
                mozillaPath = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) + ffFolderName;
            if (!System.IO.Directory.Exists(mozillaPath))
                throw new Exception("Firefox folder not found");

            LoadLibrary(mozillaPath + "mozglue.dll");
            NSS3 = LoadLibrary(mozillaPath + "nss3.dll");
            var pProc = GetProcAddress(NSS3, "NSS_Init");
            var dll = (DLLFunctionDelegate)Marshal.GetDelegateForFunctionPointer(pProc, typeof(DLLFunctionDelegate));
            return dll(configdir);
        }

        public static string Decrypt(string cypherText)
        {
            var ffDataUnmanagedPointer = IntPtr.Zero;
            var sb = new StringBuilder(cypherText);

            try
            {
                var ffData = Convert.FromBase64String(cypherText);

                ffDataUnmanagedPointer = Marshal.AllocHGlobal(ffData.Length);
                Marshal.Copy(ffData, 0, ffDataUnmanagedPointer, ffData.Length);

                var tSecDec = new TSECItem();
                var item = new TSECItem();
                item.SECItemType = 0;
                item.SECItemData = ffDataUnmanagedPointer;
                item.SECItemLen = ffData.Length;

                if (PK11SDR_Decrypt(ref item, ref tSecDec, 0) == 0)
                {
                    if (tSecDec.SECItemLen != 0)
                    {
                        var bvRet = new byte[tSecDec.SECItemLen];
                        Marshal.Copy(tSecDec.SECItemData, bvRet, 0, tSecDec.SECItemLen);
                        return Encoding.ASCII.GetString(bvRet);
                    }
                }
            }
            catch (Exception ex)
            {
                return null;
            }
            finally
            {
                if (ffDataUnmanagedPointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(ffDataUnmanagedPointer);

                }
            }

            return null;
        }
        
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int DLLFunctionDelegate4(IntPtr arenaOpt, IntPtr outItemOpt, StringBuilder inStr, int inLen);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int DLLFunctionDelegate5(ref TSECItem data, ref TSECItem result, int cx);
        public static int PK11SDR_Decrypt(ref TSECItem data, ref TSECItem result, int cx)
        {
            var pProc = GetProcAddress(NSS3, "PK11SDR_Decrypt");
            var dll = (DLLFunctionDelegate5)Marshal.GetDelegateForFunctionPointer(pProc, typeof(DLLFunctionDelegate5));
            return dll(ref data, ref result, cx);
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TSECItem
        {
            public int SECItemType;
            public IntPtr SECItemData;
            public int SECItemLen;
        }
    }

}