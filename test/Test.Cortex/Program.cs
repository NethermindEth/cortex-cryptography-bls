using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Cortex.Cryptography;

namespace Test.Cortex
{
    class Program
    {
        private static IList<byte[]> Domains => new List<byte[]>
        {
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            // new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
            // new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            // new byte[] { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            // new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
            // new byte[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        };

        private static IList<byte[]> MessageHashes => new List<byte[]>
        {
            Enumerable.Repeat((byte)0x00, 32).ToArray(),
            // Enumerable.Repeat((byte)0x56, 32).ToArray(),
            // Enumerable.Repeat((byte)0xab, 32).ToArray(),
        };

        private static IList<string> PrivateKeys => new List<string>
        {
            "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
            "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
//            "328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
        };

        static void Main(string[] args)
        {
            Console.WriteLine("Test Cortex");
            Console.WriteLine();
            try
            {
                BlsRoundtripSignAndVerify();

                Console.WriteLine("Finished. Press ENTER to exit.");
                Console.ReadLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception: {0}", ex);
            }
        }

        static void BlsRoundtripSignAndVerify()
        {
            // Arrange
            var privateKey = HexMate.Convert.FromHexString(PrivateKeys[1]);
            var messageHash = MessageHashes[0];
            var domain = Domains[0];

            Console.WriteLine("Input:");
            Console.WriteLine("Private Key: [{0}] {1}", privateKey.Length, HexMate.Convert.ToHexString(privateKey));
            Console.WriteLine("Domain: [{0}] {1}", domain.Length, HexMate.Convert.ToHexString(domain));
            Console.WriteLine("MessageHash: [{0}] {1}", messageHash.Length, HexMate.Convert.ToHexString(messageHash));

            // Act
            var parameters = new BLSParameters()
            {
                PrivateKey = privateKey
            };
            using var bls = new BLSHerumi(parameters);

            var publicKey = new byte[48];
            _ = bls.TryExportBLSPublicKey(publicKey, out var _);

            Console.WriteLine("Public Key: [{0}] {1}", publicKey.Length, HexMate.Convert.ToHexString(publicKey));

            var initialX = new byte[96];
            _ = bls.TryCombineHashAndDomain(messageHash, domain, initialX, out var _);

            Console.WriteLine("InitialX: [{0}] {1}", initialX.Length, HexMate.Convert.ToHexString(initialX));

            var signature = new byte[96];
            var signatureSuccess = bls.TrySignHash(initialX, signature.AsSpan(), out var bytesWritten);

            Console.WriteLine("Signature: {0} [{1}] {2}", signatureSuccess, bytesWritten, HexMate.Convert.ToHexString(signature));

            //var expectedSignature = HexMate.Convert.FromHexString("b9d1bf921b3dd048bdce38c2ceac2a2a8093c864881f2415f22b198de935ffa791707855c1656dc21a7af2d502bb46590151d645f062634c3b2cb79c4ed1c4a4b8b3f19f0f5c76965c651553e83d153ff95353735156eff77692f7a62ae653fb");
            //signature.ShouldBe(expectedSignature);

            var verifySuccess = bls.VerifyHash(initialX, signature);
            Console.WriteLine("Verify1: {0}", verifySuccess);

            var parameters2 = new BLSParameters()
            {
                PublicKey = publicKey
            };
            using var bls2 = new BLSHerumi(parameters);

            var verifySuccess2 = bls2.VerifyHash(initialX, signature);
            Console.WriteLine("Verify2: {0}", verifySuccess2);
        }

    }
}
