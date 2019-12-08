using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Test.Bls
{
    // Using https://github.com/herumi/bls
    // * Install Visual Studio C++ tools
    // * Open 64-bit command prompt
    // * "makelib.bat dll" worked (as does test, mentioned in readme)
    // * copy the output dll from bin folder

    class Program
    {
        const string DllName = "bls384_256";

        // 	MCL_BLS12_381 = 5,
        const int MCL_BLS12_381 = 5;

        /**
	        @file
	        @brief C API of 384-bit optimal ate pairing over BN curves
	        @author MITSUNARI Shigeo(@herumi)
	        @license modified new BSD license
	        http://opensource.org/licenses/BSD-3-Clause
        */
        //#define MCLBN_FP_UNIT_SIZE 6
        //#define MCLBN_FR_UNIT_SIZE 6
        const int MCLBN_FP_UNIT_SIZE = 6;
        const int MCLBN_FR_UNIT_SIZE = 4;

        //#define MCLBN_COMPILED_TIME_VAR ((MCLBN_FR_UNIT_SIZE) * 10 + (MCLBN_FP_UNIT_SIZE))
        // (the +200 is for BLS_ETH)
        const int MCLBN_COMPILED_TIME_VAR = MCLBN_FR_UNIT_SIZE * 10 + MCLBN_FP_UNIT_SIZE + 200;

        //typedef struct {
        //uint64_t d[MCLBN_FP_UNIT_SIZE];
        //}
        //mclBnFp;
        [StructLayout(LayoutKind.Sequential)]
        public struct mclBnFp
        {
            public ulong d_0;
            public ulong d_1;
            public ulong d_2;
            public ulong d_3;
            public ulong d_4;
            public ulong d_5;

            public override string ToString()
            {
                return $"FP(ulong[{d_0:x},{d_1:x},{d_2:x},{d_3:x},{d_4:x},{d_5:x}])";
            }
        }

        /*
	        x = d[0] + d[1] i where i^2 = -1
        */
        //typedef struct {
        //    mclBnFp d[2];
        //}
        //mclBnFp2;
        [StructLayout(LayoutKind.Sequential)]
        public struct mclBnFp2
        {
            public mclBnFp d_0;
            public mclBnFp d_1;

            public override string ToString()
            {
                return $"FP2({d_0},{d_1})";
            }
        }

        /*
            G1 and G2 are isomorphism to Fr
        */
        //typedef struct {
        //    uint64_t d[MCLBN_FR_UNIT_SIZE];
        //    }
        //    mclBnFr;
        [StructLayout(LayoutKind.Sequential)]
        public struct mclBnFr
        {
            public ulong d_0;
            public ulong d_1;
            public ulong d_2;
            public ulong d_3;

            public override string ToString()
            {
                return $"FR(ulong[{d_0:x},{d_1:x},{d_2:x},{d_3:x}])";
            }
        }

        /*
	        G1 is defined over Fp
        */
        //typedef struct {
        //    mclBnFp x, y, z;
        //    }
        //    mclBnG1;
        [StructLayout(LayoutKind.Sequential)]
        public struct mclBnG1
        {
            public mclBnFp x;
            public mclBnFp y;
            public mclBnFp z;

            public override string ToString()
            {
                return $"G1(x={x},y={y},z={z})";
            }
        }

        //typedef struct {

        //    mclBnFp2 x, y, z;
        //}
        //mclBnG2;
        [StructLayout(LayoutKind.Sequential)]
        public struct mclBnG2
        {
            public mclBnFp2 x;
            public mclBnFp2 y;
            public mclBnFp2 z;

            public override string ToString()
            {
                return $"G2(x={x},y={y},z={z})";
            }
        }

        //typedef struct {
        //    mclBnFr v;
        //    }
        //    blsSecretKey;
        [StructLayout(LayoutKind.Sequential)]
        public struct blsSecretKey
        {
            public mclBnFr v;

            public override string ToString()
            {
                return v.ToString();
            }
        }

        //typedef struct {
        //#ifdef BLS_SWAP_G
        //	mclBnG1 v;
        //#else
        //    mclBnG2 v;
        //#endif
        //}
        //blsPublicKey;
        [StructLayout(LayoutKind.Sequential)]
        public struct blsPublicKey
        {
            public mclBnG1 v;

            public override string ToString()
            {
                return v.ToString();
            }
        }

        //typedef struct {
        //#ifdef BLS_SWAP_G
        //	mclBnG2 v;
        //#else
        //mclBnG1 v;
        //#endif
        //} blsSignature;
        [StructLayout(LayoutKind.Sequential)]
        public struct blsSignature
        {
            public mclBnG2 v;

            public override string ToString()
            {
                return v.ToString();
            }
        }

        //# ifdef __EMSCRIPTEN__
        //        // avoid 64-bit integer
        //#define mclSize unsigned int
        //#define mclInt int
        //#else
        //        // use #define for cgo
        //#define mclSize size_t
        //#define mclInt int64_t
        //#endif

        /*
	        initialize this library
	        call this once before using the other functions
	        @param curve [in] enum value defined in mcl/bn.h
	        @param compiledTimeVar [in] specify MCLBN_COMPILED_TIME_VAR,
	        which macro is used to make sure that the values
	        are the same when the library is built and used
	        @return 0 if success
	        @note blsInit() is not thread safe
        */
        // BLS_DLL_API int blsInit(int curve, int compiledTimeVar);
        [DllImport(DllName)]
        public static extern int blsInit(int curve, int compiledTimeVar);
        
        /*
	        set secretKey if system has /dev/urandom or CryptGenRandom
	        return 0 if success else -1
        */
        // BLS_DLL_API int blsSecretKeySetByCSPRNG(blsSecretKey* sec);
        [DllImport(DllName)]
        public static extern int blsSecretKeySetByCSPRNG([In, Out] ref blsSecretKey sec);

        // BLS_DLL_API void blsGetPublicKey(blsPublicKey* pub, const blsSecretKey* sec);
        [DllImport(DllName)]
        public static extern int blsGetPublicKey([In, Out] ref blsPublicKey pub, ref blsSecretKey sec);

        // calculate the has of m and sign the hash
        // BLS_DLL_API void blsSign(blsSignature* sig, const blsSecretKey* sec, const void* m, mclSize size);
        [DllImport(DllName)]
        public static extern int blsSign([In, Out] ref blsSignature sig, ref blsSecretKey sec, byte[] m, int size);

        // return 1 if valid
        // BLS_DLL_API int blsVerify(const blsSignature* sig, const blsPublicKey* pub, const void* m, mclSize size);
        [DllImport(DllName)]
        public static extern int blsVerify(ref blsSignature sig, ref blsPublicKey pub, byte[] m, int size);

        //BLS_DLL_API mclSize blsPublicKeyDeserialize(blsPublicKey* pub, const void* buf, mclSize bufSize);
        [DllImport(DllName)]
        public static extern unsafe int blsPublicKeyDeserialize([In, Out] ref blsPublicKey pub, byte* buf, int bufSize);

        //BLS_DLL_API mclSize blsPublicKeySerialize(void *buf, mclSize maxBufSize, const blsPublicKey *pub);
        [DllImport(DllName)]
        public static extern unsafe int blsPublicKeySerialize(byte* buf, int maxBufSize, ref blsPublicKey pub);

        // return read byte size if success else 0
        //BLS_DLL_API mclSize blsIdDeserialize(blsId* id, const void* buf, mclSize bufSize);
        //BLS_DLL_API mclSize blsSecretKeyDeserialize(blsSecretKey* sec, const void* buf, mclSize bufSize);
        [DllImport(DllName)]
        public static extern unsafe int blsSecretKeyDeserialize([In, Out] ref blsSecretKey sec, byte* buf, int bufSize);

        // return written byte size if success else 0
        //BLS_DLL_API mclSize blsIdSerialize(void *buf, mclSize maxBufSize, const blsId *id);
        //BLS_DLL_API mclSize blsSecretKeySerialize(void *buf, mclSize maxBufSize, const blsSecretKey *sec);
        [DllImport(DllName)]
        public static extern unsafe int blsSecretKeySerialize(byte* buf, int maxBufSize, ref blsSecretKey sec);

        //set ETH serialization mode for BLS12-381
        //@param ETHserialization [in] 1:enable,  0:disable
        //@note ignore the flag if curve is not BLS12-381
        //BLS_DLL_API void blsSetETHserialization(int ETHserialization);
        [DllImport(DllName)]
        public static extern void blsSetETHserialization(int ETHserialization);


        static void Main(string[] args)
        {
            Console.WriteLine("Test BLS, LE={0}", BitConverter.IsLittleEndian);
            Console.WriteLine();

            var curveType = MCL_BLS12_381;
            //var r = "52435875175126190479447740508185965837690552500527637822603658699938581184513";
            //var p = "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787";

            int ret = blsInit(curveType, MCLBN_COMPILED_TIME_VAR);
            Console.WriteLine("Init Result {0}", ret);
            Console.WriteLine();

            try 
            {
                bls_use_stackTest();

                Console.WriteLine("Finished. Press ENTER to exit.");
                Console.ReadLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception: {0}", ex);
            }
        }

        static void bls_use_stackTest()
        {
            var msg = "this is a pen";
            var msgBytes = Encoding.UTF8.GetBytes(msg);
            var msgSize = msgBytes.Length;

            //blsSetETHserialization(1);
            //Console.WriteLine("Eth serialization set");

            var privateKeyBytes = new byte[] {
                0x47, 0xb8, 0x19, 0x2d, 0x77, 0xbf, 0x87, 0x1b,
                0x62, 0xe8, 0x78, 0x59, 0xd6, 0x53, 0x92, 0x27,
                0x25, 0x72, 0x4a, 0x5c, 0x03, 0x1a, 0xfe, 0xab,
                0xc6, 0x0b, 0xce, 0xf5, 0xff, 0x66, 0x51, 0x38 };

            Console.WriteLine("Serialized private key: {0}", BitConverter.ToString(privateKeyBytes));

            var sec = new blsSecretKey();
            unsafe
            {
                fixed (byte* privateKeyPtr = privateKeyBytes)
                {
                    blsSecretKeyDeserialize(ref sec, privateKeyPtr, privateKeyBytes.Length);
                }
            }
            //blsSecretKeySetByCSPRNG(out sec);
            Console.WriteLine("Secret key: {0}", sec);
            Console.WriteLine();

            var pub = new blsPublicKey();
            blsGetPublicKey(ref pub, ref sec);
//            unsafe
//            {
//                fixed (blsPublicKey* pubPtr = pub)
//                fixed (blsSecretKey* secPtr = sec)
//                {
//                    blsGetPublicKey(pubPtr, secPtr);
//                }
//            }
            Console.WriteLine("Public key: {0}", pub);
            Console.WriteLine();

            var buffer = new Span<byte>(new byte[48]);
            unsafe
            {
                fixed (byte* ptr = buffer)
                {
                    blsPublicKeySerialize(ptr, buffer.Length, ref pub);
                }
            }
            Console.WriteLine("Expecting public key b301803f...");
            Console.WriteLine("Serialized public key: {0}", BitConverter.ToString(buffer.ToArray()));

            var sig0 = new blsSignature();
            var ret0 = blsVerify(ref sig0, ref pub, msgBytes, msgSize);
            Console.WriteLine("Verify Fail {0}", ret0);

            var sig = new blsSignature();
            blsSign(ref sig, ref sec, msgBytes, msgSize);
            Console.WriteLine("Signature : {0}", sig);
            Console.WriteLine();

            int ret = blsVerify(ref sig, ref pub, msgBytes, msgSize);
            Console.WriteLine("Verify Result {0}", ret);

            msgBytes[0]++;
            int ret2 = blsVerify(ref sig, ref pub, msgBytes, msgSize);
            Console.WriteLine("Verify Result after tamper {0}", ret2);
        }
    }
}
