using System.IO;

namespace CryptographyPlayground.CryptographyWalkthrough
{
    internal static class StreamExtensions
    {
        public static byte[] ReadBytes(this Stream stream, int count)
        {
            var buffer = new byte[count];
            stream.Read(buffer, 0, count);
            return buffer;
        }
    }
}