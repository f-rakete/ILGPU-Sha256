#pragma warning disable CS0649

using ILGPU;
using ILGPU.Runtime;

namespace Hasher;

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
    private static uint Rotr(uint x, int n) => (x >> n) | (x << (32 - n));
    private static uint Ch(uint x, uint y, uint z) => (x & (y ^ z)) ^ z;
    private static uint Maj(uint x, uint y, uint z) => (x & (y | z)) | (y & z);
    private static uint Ep0(uint x) => Rotr(x, 2) ^ Rotr(x, 13) ^ Rotr(x, 22);
    private static uint Ep1(uint x) => Rotr(x, 6) ^ Rotr(x, 11) ^ Rotr(x, 25);
    private static uint Sig0(uint x) => Rotr(x, 7) ^ Rotr(x, 18) ^ (x >> 3);
    private static uint Sig1(uint x) => Rotr(x, 17) ^ Rotr(x, 19) ^ (x >> 10);

    /*********************** FUNCTION DEFINITIONS ***********************/
    private void Transform(ArrayView<uint> k)
    {
        uint a, b, c, d, e, f, g, h, i, j, t1, t2;
        uint[] m = new uint[64];

        for (i = 0, j = 0; i < 16; ++i, j += 4)
            m[i] = (uint)((this.data[j] << 24) | (this.data[j + 1] << 16) | (this.data[j + 2] << 8) |
                          this.data[j + 3]);

        for (; i < 64; ++i)
            m[i] = Sig1(m[i - 2]) + m[i - 7] + Sig0(m[i - 15]) + m[i - 16];

        a = this.state[0];
        b = this.state[1];
        c = this.state[2];
        d = this.state[3];
        e = this.state[4];
        f = this.state[5];
        g = this.state[6];
        h = this.state[7];

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

        this.state[0] += a;
        this.state[1] += b;
        this.state[2] += c;
        this.state[3] += d;
        this.state[4] += e;
        this.state[5] += f;
        this.state[6] += g;
        this.state[7] += h;
    }

    public Sha256()
    {
        this.dataLen = 0;
        this.bitlen = 0;
        this.state[0] = 0x6a09e667;
        this.state[1] = 0xbb67ae85;
        this.state[2] = 0x3c6ef372;
        this.state[3] = 0xa54ff53a;
        this.state[4] = 0x510e527f;
        this.state[5] = 0x9b05688c;
        this.state[6] = 0x1f83d9ab;
        this.state[7] = 0x5be0cd19;
    }

    public void Update(ArrayView<byte> payload, ArrayView<uint> k)
    {
        for (long i = 0; i < payload.Length; ++i)
        {
            this.data[this.dataLen] = payload[i];
            this.dataLen++;
            if (this.dataLen == 64)
            {
                this.Transform(k);
                this.bitlen += 512;
                this.dataLen = 0;
            }
        }
    }

    public void Final(ArrayView<byte> hash, ArrayView<uint> k)
    {
        int i;

        i = (int)this.dataLen;

        // Pad whatever data is left in the buffer.
        if (this.dataLen < 56)
        {
            this.data[i++] = 0x80;
            while (i < 56)
                this.data[i++] = 0x00;
        }
        else
        {
            this.data[i++] = 0x80;
            while (i < 64)
                this.data[i++] = 0x00;
            this.Transform(k);
            for (var _ = 0; _ < 56; _++) this.data[_] = 0;
        }

        // Append to the padding the total message's length in bits and transform.
        this.bitlen += this.dataLen * 8;
        this.data[63] = (byte)(this.bitlen);
        this.data[62] = (byte)(this.bitlen >> 8);
        this.data[61] = (byte)(this.bitlen >> 16);
        this.data[60] = (byte)(this.bitlen >> 24);
        this.data[59] = (byte)(this.bitlen >> 32);
        this.data[58] = (byte)(this.bitlen >> 40);
        this.data[57] = (byte)(this.bitlen >> 48);
        this.data[56] = (byte)(this.bitlen >> 56);
        this.Transform(k);

        // Since this implementation uses little endian byte ordering and SHA uses big endian,
        // reverse all the bytes when copying the final state to the output hash.
        for (i = 0; i < 4; ++i)
        {
            hash[i] = (byte)((this.state[0] >> (24 - i * 8)) & 0x000000ff);
            hash[i + 4] = (byte)((this.state[1] >> (24 - i * 8)) & 0x000000ff);
            hash[i + 8] = (byte)((this.state[2] >> (24 - i * 8)) & 0x000000ff);
            hash[i + 12] = (byte)((this.state[3] >> (24 - i * 8)) & 0x000000ff);
            hash[i + 16] = (byte)((this.state[4] >> (24 - i * 8)) & 0x000000ff);
            hash[i + 20] = (byte)((this.state[5] >> (24 - i * 8)) & 0x000000ff);
            hash[i + 24] = (byte)((this.state[6] >> (24 - i * 8)) & 0x000000ff);
            hash[i + 28] = (byte)((this.state[7] >> (24 - i * 8)) & 0x000000ff);
        }
    }

    static void Kernel(Index1D index, ArrayView<uint> k, ArrayView<byte> data, ArrayView<byte> outdata)
    {
        var ctx = new Sha256();
        ctx.Update(data, k);
        ctx.Final(outdata, k);
    }

    public static void Main(string[] args)
    {
        var hX = "abc"u8.ToArray();

        using var context = Context.CreateDefault();

        var device = context.Devices.First();
        Console.WriteLine(device);

        using var accelerator = device.CreateAccelerator(context);

        var kernel = accelerator
            .LoadAutoGroupedStreamKernel<Index1D, ArrayView<uint>, ArrayView<byte>, ArrayView<byte>>(Kernel);

        using var dK = accelerator.Allocate1D(K);
        using var dX = accelerator.Allocate1D(hX);
        using var dY = accelerator.Allocate1D<byte>(32);

        kernel(1, dK.View, dX.View, dY.View);

        var hY = dY.GetAsArray1D();
        Console.WriteLine(BitConverter.ToString(hY).Replace("-", "").ToLower());
    }
}