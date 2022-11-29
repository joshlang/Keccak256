using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Epoche
{
    public static class Keccak256
    {
        static readonly BouncyKeccak256 Hasher = new BouncyKeccak256();

        public static byte[] ComputeHash(byte[] input)
        {
            if (Monitor.TryEnter(Hasher))
            {
                try
                {
                    return ComputeHash(Hasher, input, true);
                }
                finally
                {
                    Monitor.Exit(Hasher);
                }
            }
            return ComputeHash(new BouncyKeccak256(), input, false);
        }
        public static byte[] ComputeHash(string input) => ComputeHash(Encoding.UTF8.GetBytes(input));
        public static async Task<byte[]> ComputeHashAsync(Stream input, CancellationToken cancellationToken = default)
        {
            var hasher = new BouncyKeccak256();
            var buffer = new byte[8192];
            while (true)
            {
                int r = await input.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                if (r == 0)
                {
                    byte[] hash = new byte[32];
                    hasher.DoFinal(hash, 0);
                    return hash;
                }
                hasher.BlockUpdate(buffer, 0, r);
            }
        }

        static byte[] ComputeHash(BouncyKeccak256 hasher, byte[] input, bool reset)
        {
            if (reset)
            {
                hasher.Reset();
            }
            hasher.BlockUpdate(input, 0, input.Length);
            var hash = new byte[32];
            hasher.DoFinal(hash, 0);
            return hash;
        }

        public static string ComputeEthereumFunctionSelector(string functionSignature, bool prefix0x = true)
        {
            var hash = ComputeHash(functionSignature);
            string s = prefix0x ? "0x" : "";
            s += hash[0].ToString("x2");
            s += hash[1].ToString("x2");
            s += hash[2].ToString("x2");
            s += hash[3].ToString("x2");
            return s;
        }
    }
}
