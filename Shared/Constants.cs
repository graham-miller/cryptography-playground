using System.Text;

namespace CryptographyPlayground.Shared
{
    public static class Constants
    {
        public const string PlainText = "The greatest glory in living lies not in never falling, but in rising every time we fall.";
        public static readonly byte[] PlainBytes = Encoding.Default.GetBytes(PlainText);

        public const string DifferentPlainText = "The greatest glory in living lies not in never falling, but in rising every time we fall!"; // exclamation instead of full stop;
        public static readonly byte[] DifferentPlainBytes = Encoding.Default.GetBytes(DifferentPlainText);

        public const string Password = "password";
    }
}
