using System.Text;
using ILGPU;
using ILGPU.Runtime;

#pragma warning disable CS0649
namespace LGPU_Sha256
{

    public unsafe struct Sha256
    {
        /**************************** VARIABLES *****************************/
        static readonly uint[] K =
        {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

        /****************************** FIELDS ******************************/
        private fixed uint state[8];
        private fixed byte data[64];
        private uint dataLen;
        private ulong bitlen;

        /****************************** MACROS ******************************/
        private static uint Rotr(uint x, int n) => x >> n | x << 32 - n;
        private static uint Ch(uint x, uint y, uint z) => x & (y ^ z) ^ z;
        private static uint Maj(uint x, uint y, uint z) => x & (y | z) | y & z;
        private static uint Ep0(uint x) => Rotr(x, 2) ^ Rotr(x, 13) ^ Rotr(x, 22);
        private static uint Ep1(uint x) => Rotr(x, 6) ^ Rotr(x, 11) ^ Rotr(x, 25);
        private static uint Sig0(uint x) => Rotr(x, 7) ^ Rotr(x, 18) ^ x >> 3;
        private static uint Sig1(uint x) => Rotr(x, 17) ^ Rotr(x, 19) ^ x >> 10;

        /*********************** FUNCTION DEFINITIONS ***********************/
        private unsafe void Transform(ArrayView<uint> k)
        {
            uint a, b, c, d, e, f, g, h, i, j, t1, t2;
            uint[] m = new uint[64];

            for (i = 0, j = 0; i < 16; ++i, j += 4)
                m[i] = (uint)(data[j] << 24 | data[j + 1] << 16 | data[j + 2] << 8 |
                              data[j + 3]);

            for (; i < 64; ++i)
                m[i] = Sig1(m[i - 2]) + m[i - 7] + Sig0(m[i - 15]) + m[i - 16];

            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];
            e = state[4];
            f = state[5];
            g = state[6];
            h = state[7];

            for (i = 0; i < 64; ++i)
            {
                t1 = h + Ep1(e) + Ch(e, f, g) + k[(long)i] + m[i];
                t2 = Ep0(a) + Maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            state[5] += f;
            state[6] += g;
            state[7] += h;
        }
        public Sha256()
        {
            dataLen = 0;
            bitlen = 0;
            state[0] = 0x6a09e667;
            state[1] = 0xbb67ae85;
            state[2] = 0x3c6ef372;
            state[3] = 0xa54ff53a;
            state[4] = 0x510e527f;
            state[5] = 0x9b05688c;
            state[6] = 0x1f83d9ab;
            state[7] = 0x5be0cd19;
        }
        public void Update(ArrayView<byte> payload, ArrayView<uint> k)
        {
            for (long i = 0; i < payload.Length; ++i)
            {
                data[dataLen] = payload[i];
                dataLen++;
                if (dataLen == 64)
                {
                    Transform(k);
                    bitlen += 512;
                    dataLen = 0;
                }
            }
        }
        public void Final(ArrayView<byte> hash, ArrayView<uint> k)
        {
            int i;

            i = (int)dataLen;

            // Pad whatever data is left in the buffer.
            if (dataLen < 56)
            {
                data[i++] = 0x80;
                while (i < 56)
                    data[i++] = 0x00;
            }
            else
            {
                data[i++] = 0x80;
                while (i < 64)
                    data[i++] = 0x00;
                Transform(k);
                for (var _ = 0; _ < 56; _++) data[_] = 0;

            }

            // Append to the padding the total message's length in bits and transform.
            bitlen += dataLen * 8;
            data[63] = (byte)bitlen;
            data[62] = (byte)(bitlen >> 8);
            data[61] = (byte)(bitlen >> 16);
            data[60] = (byte)(bitlen >> 24);
            data[59] = (byte)(bitlen >> 32);
            data[58] = (byte)(bitlen >> 40);
            data[57] = (byte)(bitlen >> 48);
            data[56] = (byte)(bitlen >> 56);
            Transform(k);

            // Since this implementation uses little endian byte ordering and SHA uses big endian,
            // reverse all the bytes when copying the final state to the output hash.
            //TODO:   LibDevice.BitReverse()

            for (i = 0; i < 4; ++i)
            {
                hash[i] = (byte)(state[0] >> 24 - i * 8 & 0x000000ff);
                hash[i + 4] = (byte)(state[1] >> 24 - i * 8 & 0x000000ff);
                hash[i + 8] = (byte)(state[2] >> 24 - i * 8 & 0x000000ff);
                hash[i + 12] = (byte)(state[3] >> 24 - i * 8 & 0x000000ff);
                hash[i + 16] = (byte)(state[4] >> 24 - i * 8 & 0x000000ff);
                hash[i + 20] = (byte)(state[5] >> 24 - i * 8 & 0x000000ff);
                hash[i + 24] = (byte)(state[6] >> 24 - i * 8 & 0x000000ff);
                hash[i + 28] = (byte)(state[7] >> 24 - i * 8 & 0x000000ff);
            }
        }

        static void MultiKernel(Index1D idx,
                                ArrayView<uint> k,
                                ArrayView1D<byte, Stride1D.Dense> inData,
                                ArrayView<int> inOffsets,
                                ArrayView1D<byte, Stride1D.Dense> outdata)
        {
            var ctx = new Sha256();
            var subIn = inData.SubView(inOffsets[idx], inOffsets[idx + 1] - inOffsets[idx]);
            var subOut = outdata.SubView(idx * 32, 32);
            ctx.Update(subIn, k);
            ctx.Final(subOut, k);
        }

        static void Kernel(Index1D idx, ArrayView<uint> k, ArrayView<byte> indata, ArrayView<byte> outdata)
        {
            //idx not used yet

            var ctx = new Sha256();
            ctx.Update(indata, k);
            ctx.Final(outdata, k);
        }

        static Context context;
        static Accelerator accelerator;
        static List<int> offsets = new List<int>();
        static List<byte[]> hXs = new();
        static byte[] hXsArray;
        static Action<Index1D, ArrayView<uint>, ArrayView1D<byte, Stride1D.Dense>, ArrayView<int>, ArrayView1D<byte, Stride1D.Dense>> kernel;

        public static void Setup(int HxsSize = 0)
        {
            context = Context.Create(builder =>
            builder.Default().Inlining(InliningMode.Aggressive)

            // .StaticFields(StaticFieldMode.MutableStaticFields | StaticFieldMode.IgnoreStaticFieldStores)
            //     .Arrays(ArrayMode.InlineMutableStaticArrays)
            );

            var device = context.Devices.Where(c => c.AcceleratorType == AcceleratorType.Cuda).First();
            Console.WriteLine(device);

            accelerator = device.CreateAccelerator(context);

            kernel = accelerator
                .LoadAutoGroupedStreamKernel<Index1D, ArrayView<uint>, ArrayView1D<byte, Stride1D.Dense>, ArrayView<int>, ArrayView1D<byte, Stride1D.Dense>>(MultiKernel);

            if (HxsSize > 0)
            {
                hXs = new List<byte[]>(HxsSize);
            }
        }

        public static List<byte[]> Calc(List<string> s)
        {
            var hX = Encoding.UTF8.GetBytes(s.First());

            using var dK = accelerator.Allocate1D(K);
            using var dX = accelerator.Allocate1D(hX);
            using var dY = accelerator.Allocate1D<byte>(32);

            throw new NotImplementedException();
        }

        public static void AddJob(string s)
        {
            var hX = Encoding.UTF8.GetBytes(s);
            hXs.Add(hX);
        }
        public static void ClearJobs()
        {
            hXs.Clear();
        }

        public static List<byte[]> CalcJobs()
        {
            //flatten hxs list to array

            int totalLength = hXs.Sum(arr => arr.Length);
            hXsArray = new byte[totalLength];

            int offset = 0;
            foreach (byte[] arr in hXs)
            {
                offsets.Add(offset);
                Array.Copy(arr, 0, hXsArray, offset, arr.Length);
                offset += arr.Length;
            }
            offsets.Add(offset);
            using var dK = accelerator.Allocate1D<uint>(K.LongLength);
            using var dX = accelerator.Allocate1D<byte>(hXsArray.LongLength);
            using var inOfs = accelerator.Allocate1D<int>(offsets.Count);
            using var dY = accelerator.Allocate1D<byte>(32 * hXs.Count);

            dK.CopyFromCPU(K);
            dX.CopyFromCPU(hXsArray);
            inOfs.CopyFromCPU(offsets.ToArray());
            //  dK.CopyFromCPU<int[]>(K);

            kernel(hXs.Count, dK.View, dX.View, inOfs.View, dY.View);

            accelerator.Synchronize();
            //unflatten results
            int segmentSize = 32;
            int segmentCount = (int)dY.Length / segmentSize;

            List<byte[]> segments = new List<byte[]>(segmentCount);

            var results = dY.GetAsArray1D();

            for (int i = 0; i < segmentCount; i++)
            {
                int outoffset = i * segmentSize;
                byte[] segment = new byte[segmentSize];
                Array.Copy(results, outoffset, segment, 0, segmentSize);
                segments.Add(segment);
            }

            return segments;

        }


        public static byte[] Calc(string s)
        {
            var hX = Encoding.UTF8.GetBytes(s);

            using var dK = accelerator.Allocate1D(K);
            using var dX = accelerator.Allocate1D(hX);
            using var dY = accelerator.Allocate1D<byte>(32);

            var hY = dY.GetAsArray1D();
            return hY;
        }

        public static void Dispose()
        {
            accelerator?.Dispose();
            context?.Dispose();
        }
    }
}
