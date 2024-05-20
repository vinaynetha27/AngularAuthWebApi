using System.Security.Cryptography;

namespace AngularAuthWebApi.Helpers
{
    public class Passwordhash
    {
        private static RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        private static readonly int SaltSize = 16;
        private static readonly int HashSize = 20;
        private static readonly int Iteration = 10000;

        public static string PasswordHash(string password)
        {
            byte[] salt;
            rng.GetBytes(salt = new byte[SaltSize]);
            var key = new Rfc2898DeriveBytes(password, salt, Iteration);
            var hash = key.GetBytes(HashSize);

            var hashbytes = new byte[SaltSize + HashSize];
            Array.Copy(salt, 0, hashbytes, 0, SaltSize);
            Array.Copy(hash,0, hashbytes, SaltSize, HashSize);
            var base64hash = Convert.ToBase64String(hashbytes);

            return base64hash;
        }

        public static bool VerifyPassword(string password, string base64hash)
        {
            var hashbytes = Convert.FromBase64String(base64hash);
            var salt = new byte[SaltSize];
            Array.Copy(hashbytes, 0, salt, 0, SaltSize);

            var key = new Rfc2898DeriveBytes(password, salt, Iteration);
            byte[] hash = key.GetBytes(HashSize);

            for (int i = 0; i < HashSize; i++)
            {
                if (hashbytes[i + SaltSize] != hash[i])
                    return false;
            }
            return true;
        }

    }
}
