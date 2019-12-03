using System;
using System.Security.Cryptography;

namespace Cortex.Cryptography
{
    /// <summary>
    /// Implementation of BLS that supports Eth 2.0, using the Herumi library.
    /// </summary>
    public class BLSHerumi : BLS
    {
        private const int DomainLength = 8;
        private const int HashLength = 32;
        private const int InitialXPartLength = 48;
        private const int PrivateKeyLength = 32;
        private const int PublicKeyLength = 48;
        private const int SignatureLength = 96;
        private static bool _initialised;
        private byte[]? _privateKey;
        private byte[]? _publicKey;

        public BLSHerumi(BLSParameters parameters)
        {
            // Only supports minimal public key size
            KeySizeValue = PrivateKeyLength * 8;
            ImportParameters(parameters);
        }

        /// <inheritdoc />
        public override string CurveName => "BLS12381";

        /// <inheritdoc />
        public override string HashToPointName => "ETH2-";

        /// <inheritdoc />
        public override BlsScheme Scheme => BlsScheme.Basic;

        /// <inheritdoc />
        public override BlsVariant Variant => BlsVariant.MinimalPublicKeySize;

        /// <inheritdoc />
        public override void ImportParameters(BLSParameters parameters)
        {
            if (parameters.PrivateKey != null && parameters.PrivateKey.Length != PrivateKeyLength)
            {
                throw new ArgumentOutOfRangeException(nameof(parameters.PrivateKey), parameters.PrivateKey.Length, $"Private key must be {PrivateKeyLength} bytes long.");
            }
            if (parameters.PublicKey != null && parameters.PublicKey.Length != PublicKeyLength)
            {
                throw new ArgumentOutOfRangeException(nameof(parameters.PublicKey), parameters.PublicKey.Length, $"Public key must be {PublicKeyLength} bytes long.");
            }

            if (parameters.InputKeyMaterial != null)
            {
                throw new NotSupportedException("BLS input key material not supported.");
            }

            // Only supports minimal public key size (or unspecified)
            if (parameters.Variant != BlsVariant.Unknown
                && parameters.Variant != BlsVariant.MinimalPublicKeySize)
            {
                throw new NotSupportedException($"BLS variant {parameters.Variant} not supported.");
            }

            // Only supports basic (or unspecified)
            if (parameters.Scheme != BlsScheme.Unknown
               && parameters.Scheme != BlsScheme.Basic)
            {
                throw new NotSupportedException($"BLS scheme {parameters.Scheme} not supported.");
            }

            // TODO: If both are null, generate random key??

            _privateKey = parameters.PrivateKey?.AsSpan().ToArray();
            _publicKey = parameters.PublicKey?.AsSpan().ToArray();
        }

        public override bool TryAggregatePublicKeys(ReadOnlySpan<byte> publicKeys, Span<byte> destination, out int bytesWritten)
        {
            // This is independent of the keys set, although other parameters (type of curve, variant, scheme, etc) are relevant.

            if (publicKeys.Length % PublicKeyLength != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(publicKeys), publicKeys.Length, $"Public key data must be a multiple of the public key length {PublicKeyLength}.");
            }
            if (destination.Length < PublicKeyLength)
            {
                bytesWritten = 0;
                return false;
            }

            EnsureInitialised();

            Bls384Interop.BlsPublicKey aggregateBlsPublicKey = default;
            for (var index = 0; index < publicKeys.Length; index += PublicKeyLength)
            {
                var publicKeySlice = publicKeys.Slice(index, PublicKeyLength);
                Bls384Interop.BlsPublicKey blsPublicKey;
                int publickKeyBytesRead;
                unsafe
                {
                    // Using fixed pointer for input data allows us to pass a slice
                    fixed (byte* publicKeyPtr = publicKeySlice)
                    {
                        publickKeyBytesRead = Bls384Interop.PublicKeyDeserialize(out blsPublicKey, publicKeyPtr, PublicKeyLength);
                    }
                }
                if (publickKeyBytesRead != PublicKeyLength)
                {
                    throw new Exception($"Error deserializing BLS public key, length: {publickKeyBytesRead}");
                }
                if (index == 0)
                {
                    aggregateBlsPublicKey = blsPublicKey;
                }
                else
                {
                    Bls384Interop.PublicKeyAdd(ref aggregateBlsPublicKey, blsPublicKey);
                }
            }

            unsafe
            {
                // Using fixed pointer for output data allows us to write directly to destination
                fixed (byte* destinationPtr = destination)
                {
                    bytesWritten = Bls384Interop.PublicKeySerialize(destinationPtr, PublicKeyLength, aggregateBlsPublicKey);
                }
            }
            if (bytesWritten != PublicKeyLength)
            {
                throw new Exception($"Error serializing BLS public key, length: {bytesWritten}");
            }
            return true;
        }

        /// <inheritdoc />
        public override bool TryAggregateSignatures(ReadOnlySpan<byte> signatures, Span<byte> destination, out int bytesWritten)
        {
            // This is independent of the keys set, although other parameters (type of curve, variant, scheme, etc) are relevant.
            if (signatures.Length % SignatureLength != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(signatures), signatures.Length, $"Signature data must be a multiple of the signature length {SignatureLength}.");
            }
            if (destination.Length < SignatureLength)
            {
                bytesWritten = 0;
                return false;
            }

            EnsureInitialised();

            Bls384Interop.BlsSignature aggregateBlsSignature = default;
            for (var index = 0; index < signatures.Length; index += SignatureLength)
            {
                var signatureSlice = signatures.Slice(index, SignatureLength);
                Bls384Interop.BlsSignature blsSignature;
                int signatureBytesRead;
                unsafe
                {
                    // Using fixed pointer for input data allows us to pass a slice
                    fixed (byte* signaturePtr = signatureSlice)
                    {
                        signatureBytesRead = Bls384Interop.SignatureDeserialize(out blsSignature, signaturePtr, SignatureLength);
                    }
                }
                if (signatureBytesRead != SignatureLength)
                {
                    throw new Exception($"Error deserializing BLS signature, length: {signatureBytesRead}");
                }
                if (index == 0)
                {
                    aggregateBlsSignature = blsSignature;
                }
                else
                {
                    Bls384Interop.SignatureAdd(ref aggregateBlsSignature, blsSignature);
                }
            }

            unsafe
            {
                // Using fixed pointer for output data allows us to write directly to destination
                fixed (byte* destinationPtr = destination)
                {
                    bytesWritten = Bls384Interop.SignatureSerialize(destinationPtr, SignatureLength, aggregateBlsSignature);
                }
            }
            if (bytesWritten != SignatureLength)
            {
                throw new Exception($"Error serializing BLS signature, length: {bytesWritten}");
            }
            return true;
        }

        /// <summary>
        /// Combines a hash and domain to the input format used by Herumi (the G2 initial X value).
        /// </summary>
        /// <returns>true if the operation was successful; false if the destination is not large enough to hold the result</returns>
        public bool TryCombineHashAndDomain(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> domain, Span<byte> destination, out int bytesWritten)
        {
            if (destination.Length < 2 * InitialXPartLength)
            {
                bytesWritten = 0;
                return false;
            }

            if (hash.Length != HashLength)
            {
                throw new ArgumentOutOfRangeException(nameof(hash), hash.Length, $"Hash with domain must be {HashLength} bytes long.");
            }
            if (domain.Length != DomainLength)
            {
                throw new ArgumentOutOfRangeException(nameof(domain), domain.Length, $"Domain must be {DomainLength} bytes long.");
            }

            var hashWithDomain = new Span<byte>(new byte[HashLength + DomainLength]);
            hash.CopyTo(hashWithDomain);
            domain.CopyTo(hashWithDomain.Slice(HashLength));

            unsafe
            {
                fixed (byte* destinationPtr = destination)
                fixed (byte* hashPtr = hashWithDomain)
                {
                    Bls384Interop.HashWithDomainToFp2(destinationPtr, hashPtr);
                }
            }

            bytesWritten = 2 * InitialXPartLength;
            return true;
        }

        /// <inheritdoc />
        public override bool TryExportBLSPrivateKey(Span<byte> desination, out int bytesWritten)
        {
            if (_privateKey == null)
            {
                throw new CryptographicException("The key could not be exported.");
            }
            if (desination.Length < _privateKey.Length)
            {
                bytesWritten = 0;
                return false;
            }
            _privateKey.CopyTo(desination);
            bytesWritten = _privateKey.Length;
            return true;
        }

        /// <inheritdoc />
        public override bool TryExportBLSPublicKey(Span<byte> desination, out int bytesWritten)
        {
            EnsurePublicKey();
            if (_publicKey == null)
            {
                throw new CryptographicException("The key could not be exported.");
            }
            if (desination.Length < _publicKey.Length)
            {
                bytesWritten = 0;
                return false;
            }
            _publicKey.CopyTo(desination);
            bytesWritten = _publicKey.Length;
            return true;
        }

        /// <inheritdoc />
        public override bool TrySignData(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten, ReadOnlySpan<byte> domain = default)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public override bool TrySignHash(ReadOnlySpan<byte> hash, Span<byte> destination, out int bytesWritten, ReadOnlySpan<byte> domain = default)
        {
            if (destination.Length < SignatureLength)
            {
                bytesWritten = 0;
                return false;
            }

            EnsureInitialised();

            // TODO: Generate random key if null
            // EnsurePrivateKey();

            Bls384Interop.BlsSecretKey blsSecretKey;
            int bytesRead;
            unsafe
            {
                fixed (byte* privateKeyPtr = _privateKey)
                {
                    bytesRead = Bls384Interop.SecretKeyDeserialize(out blsSecretKey, privateKeyPtr, _privateKey!.Length);
                }
            }
            if (bytesRead != _privateKey.Length)
            {
                throw new Exception($"Error deserializing BLS private key, length: {bytesRead}");
            }

            Bls384Interop.BlsSignature blsSignature;
            int result;

            if (domain.Length > 0)
            {
                if (hash.Length != HashLength)
                {
                    throw new ArgumentOutOfRangeException(nameof(hash), hash.Length, $"Hash with domain must be {HashLength} bytes long.");
                }
                if (domain.Length != DomainLength)
                {
                    throw new ArgumentOutOfRangeException(nameof(domain), domain.Length, $"Domain must be {DomainLength} bytes long.");
                }

                var hashWithDomain = new Span<byte>(new byte[HashLength + DomainLength]);
                hash.CopyTo(hashWithDomain);
                domain.CopyTo(hashWithDomain.Slice(HashLength));

                unsafe
                {
                    fixed (byte* hashPtr = hashWithDomain)
                    {
                        result = Bls384Interop.SignHashWithDomain(out blsSignature, blsSecretKey, hashPtr);
                    }
                }
            }
            else
            {
                unsafe
                {
                    fixed (byte* hashPtr = hash)
                    {
                        result = Bls384Interop.SignHash(out blsSignature, blsSecretKey, hashPtr, hash.Length);
                    }
                }
            }

            if (result != 0)
            {
                throw new Exception($"Error generating BLS signature for hash. Error: {result}");
            }

            unsafe
            {
                fixed (byte* destinationPtr = destination)
                {
                    bytesWritten = Bls384Interop.SignatureSerialize(destinationPtr, SignatureLength, blsSignature);
                }
            }
            if (bytesWritten != SignatureLength)
            {
                throw new Exception($"Error serializing BLS signature, length: {bytesWritten}");
            }
            return true;
        }

        /// <inheritdoc />
        public override bool VerifyAggregate(ReadOnlySpan<byte> publicKeys, ReadOnlySpan<byte> hashes, ReadOnlySpan<byte> aggregateSignature, ReadOnlySpan<byte> domain = default)
        {
            // This is independent of the keys set, although other parameters (type of curve, variant, scheme, etc) are relevant.

            if (aggregateSignature.Length != SignatureLength)
            {
                throw new ArgumentOutOfRangeException(nameof(aggregateSignature), aggregateSignature.Length, $"Signature must be {SignatureLength} bytes long.");
            }
            if (publicKeys.Length % PublicKeyLength != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(publicKeys), publicKeys.Length, $"Public key data must be a multiple of the public key length {PublicKeyLength}.");
            }
            var publicKeyCount = publicKeys.Length / PublicKeyLength;
            if (hashes.Length % publicKeyCount != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(hashes), hashes.Length, $"Hashes must all be the same length, with total bytes evenly divisble by the number of public keys, {publicKeyCount}.");
            }

            EnsureInitialised();

            var blsPublicKeys = new Bls384Interop.BlsPublicKey[publicKeyCount];
            var publicKeysIndex = 0;
            for (var blsPublicKeyIndex = 0; blsPublicKeyIndex < publicKeyCount; blsPublicKeyIndex++)
            {
                var publicKey = publicKeys.Slice(publicKeysIndex, PublicKeyLength);
                int publicKeyBytesRead;
                unsafe
                {
                    fixed (byte* publicKeyPtr = publicKey)
                    {
                        publicKeyBytesRead = Bls384Interop.PublicKeyDeserialize(out blsPublicKeys[blsPublicKeyIndex], publicKeyPtr, PublicKeyLength);
                    }
                }
                if (publicKeyBytesRead != PublicKeyLength)
                {
                    throw new Exception($"Error deserializing BLS public key {blsPublicKeyIndex}, length: {publicKeyBytesRead}");
                }
                publicKeysIndex += PublicKeyLength;
            }

            Bls384Interop.BlsSignature aggregateBlsSignature;
            int signatureBytesRead;
            unsafe
            {
                fixed (byte* signaturePtr = aggregateSignature)
                {
                    signatureBytesRead = Bls384Interop.SignatureDeserialize(out aggregateBlsSignature, signaturePtr, SignatureLength);
                }
            }
            if (signatureBytesRead != aggregateSignature.Length)
            {
                throw new Exception($"Error deserializing BLS signature, length: {signatureBytesRead}");
            }

            int result;
            var hashLength = hashes.Length / publicKeyCount;

            if (domain.Length > 0)
            {
                if (hashLength != HashLength)
                {
                    throw new ArgumentOutOfRangeException(nameof(hashes), hashes.Length, $"Hashes with domain must have total length {publicKeyCount * HashLength} (each should be {HashLength} bytes long, for {publicKeyCount} public keys).");
                }
                if (domain.Length != DomainLength)
                {
                    throw new ArgumentOutOfRangeException(nameof(domain), domain.Length, $"Domain must be {DomainLength} bytes long.");
                }

                var combined = new Span<byte>(new byte[publicKeyCount * (HashLength + DomainLength)]);
                var combinedIndex = 0;
                for (var hashIndex = 0; hashIndex < hashes.Length; hashIndex += HashLength)
                {
                    var hashSlice = hashes.Slice(hashIndex, HashLength);
                    hashSlice.CopyTo(combined.Slice(combinedIndex));
                    combinedIndex += HashLength;
                    domain.CopyTo(combined.Slice(combinedIndex));
                    combinedIndex += DomainLength;
                }

                unsafe
                {
                    fixed (byte* hashPtr = combined)
                    {
                        result = Bls384Interop.VerifyAggregatedHashWithDomain(aggregateBlsSignature, blsPublicKeys, hashPtr, publicKeyCount);
                    }
                }
            }
            else
            {
                unsafe
                {
                    fixed (byte* hashPtr = hashes)
                    {
                        result = Bls384Interop.VerifyAggregateHashes(aggregateBlsSignature, blsPublicKeys, hashPtr, hashLength, publicKeyCount);
                    }
                }
            }

            return (result == 1);
        }

        /// <inheritdoc />
        public override bool VerifyData(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> domain = default)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public override bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> domain = default)
        {
            if (signature.Length != SignatureLength)
            {
                throw new ArgumentOutOfRangeException(nameof(signature), signature.Length, $"Signature must be {SignatureLength} bytes long.");
            }

            EnsureInitialised();
            EnsurePublicKey();

            Bls384Interop.BlsPublicKey blsPublicKey;
            int publicKeyBytesRead;
            unsafe
            {
                fixed (byte* publicKeyPtr = _publicKey)
                {
                    publicKeyBytesRead = Bls384Interop.PublicKeyDeserialize(out blsPublicKey, publicKeyPtr, _publicKey!.Length);
                }
            }
            if (publicKeyBytesRead != _publicKey.Length)
            {
                throw new Exception($"Error deserializing BLS public key, length: {publicKeyBytesRead}");
            }

            Bls384Interop.BlsSignature blsSignature;
            int signatureBytesRead;
            unsafe
            {
                fixed (byte* signaturePtr = signature)
                {
                    signatureBytesRead = Bls384Interop.SignatureDeserialize(out blsSignature, signaturePtr, SignatureLength);
                }
            }
            if (signatureBytesRead != signature.Length)
            {
                throw new Exception($"Error deserializing BLS signature, length: {signatureBytesRead}");
            }

            int result;

            if (domain.Length > 0)
            {
                if (hash.Length != HashLength)
                {
                    throw new ArgumentOutOfRangeException(nameof(hash), hash.Length, $"Hash with domain must be {HashLength} bytes long.");
                }
                if (domain.Length != DomainLength)
                {
                    throw new ArgumentOutOfRangeException(nameof(domain), domain.Length, $"Domain must be {DomainLength} bytes long.");
                }

                var hashWithDomain = new Span<byte>(new byte[HashLength + DomainLength]);
                hash.CopyTo(hashWithDomain);
                domain.CopyTo(hashWithDomain.Slice(HashLength));

                unsafe
                {
                    fixed (byte* hashPtr = hashWithDomain)
                    {
                        result = Bls384Interop.VerifyHashWithDomain(blsSignature, blsPublicKey, hashPtr);
                    }
                }
            }
            else
            {
                unsafe
                {
                    fixed (byte* hashPtr = hash)
                    {
                        result = Bls384Interop.VerifyHash(blsSignature, blsPublicKey, hashPtr, hash.Length);
                    }
                }
            }

            return (result == 1);
        }

        private static void EnsureInitialised()
        {
            if (!_initialised)
            {
                var result = Bls384Interop.Init(Bls384Interop.MCL_BLS12_381, Bls384Interop.MCLBN_COMPILED_TIME_VAR);
                if (result != 0)
                {
                    throw new Exception($"Error initialising BLS algorithm. Error: {result}");
                }
                Bls384Interop.SetETHserialization(1);
                _initialised = true;
            }
        }

        private void EnsurePublicKey()
        {
            if (_publicKey == null)
            {
                if (_privateKey != null)
                {
                    EnsureInitialised();

                    // Standard values are big endian encoding (are using the Herumi deserialize / serialize)

                    Bls384Interop.BlsSecretKey blsSecretKey;
                    int bytesRead;
                    unsafe
                    {
                        fixed (byte* ptr = _privateKey)
                        {
                            bytesRead = Bls384Interop.SecretKeyDeserialize(out blsSecretKey, ptr, _privateKey.Length);
                        }
                    }
                    if (bytesRead != _privateKey.Length)
                    {
                        throw new Exception($"Error deserializing BLS private key, length: {bytesRead}");
                    }

                    Bls384Interop.GetPublicKey(out var blsPublicKey, blsSecretKey);

                    var buffer = new Span<byte>(new byte[PublicKeyLength]);
                    int bytesWritten;
                    unsafe
                    {
                        fixed (byte* ptr = buffer)
                        {
                            bytesWritten = Bls384Interop.PublicKeySerialize(ptr, buffer.Length, in blsPublicKey);
                        }
                    }

                    if (bytesWritten != buffer.Length)
                    {
                        throw new Exception($"Error serializing BLS public key, length: {bytesWritten}");
                    }
                    _publicKey = buffer.ToArray();
                }
            }
        }
    }
}
