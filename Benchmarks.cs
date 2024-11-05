using System;
using BenchmarkDotNet;
using BenchmarkDotNet.Attributes;
using System.Security.Cryptography;

namespace MyBenchmark
{
    [MemoryDiagnoser]
    public class Benchmarks
    {
        private byte[] salt = new byte[16];

        //[Params("MySecretP@$$w0rd!", "Eas1P@$s", "Ch0xC@t1nSh!f^re&V2'Uz{u}N?")]
        [Params("MySecretP@$$w0rd!")]
        public string passwordText { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            salt = new byte[16];
            new Random().NextBytes(salt); // Generate a random salt
        }

        [Benchmark(Baseline = true)]
        public string OriginalScenario()
        {
            return GeneratePasswordHashUsingSalt(passwordText, salt);
        }

        [Benchmark]
        public string UpdatedScenario()
        {
            return GeneratePasswordHashUsingSaltOptimized(passwordText, salt);
        }

        public string GeneratePasswordHashUsingSalt(string passwordText, byte[] salt)
        {
            var iterate = 10000;
            var pbkdf2 = new Rfc2898DeriveBytes(passwordText, salt, iterate);
            byte[] hash = pbkdf2.GetBytes(20);

            byte[] hashBytes = new byte[36];
            Array.Copy(salt, 0, hashBytes, 0, 16);
            Array.Copy(hash, 0, hashBytes, 16, 20);

            var passwordHash = Convert.ToBase64String(hashBytes);

            return passwordHash;
        }

        public string GeneratePasswordHashUsingSaltOptimized(string passwordText, byte[] salt)
        {
            var iterate = 10000;
            var pbkdf2 = new Rfc2898DeriveBytes(passwordText, salt, iterate, HashAlgorithmName.SHA256);
            byte[] hash = pbkdf2.GetBytes(20);

            byte[] hashBytes = new byte[36];
            Buffer.BlockCopy(salt, 0, hashBytes, 0, 16);
            Buffer.BlockCopy(hash, 0, hashBytes, 16, 20);

            return Convert.ToBase64String(hashBytes);
        }
    }
}
