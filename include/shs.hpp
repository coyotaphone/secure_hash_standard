#pragma once

#include <cstdint>
#include <cstring>

namespace shs {

  using dgst160_t = uint32_t[160 / 32];
  using dgst224_t = uint32_t[224 / 32];
  using dgst256_t = uint32_t[256 / 32];
  using dgst384_t = uint64_t[384 / 64];
  using dgst512_t = uint64_t[512 / 64];

  template<typename word_t, typename dgst_t, typename out_t>
  class sha_base {

    dgst_t digest;
    word_t length[2];
    word_t buffer[16];

    static constexpr dgst160_t init160 {
      0x67452301ui32, 0xefcdab89ui32, 0x98badcfeui32, 0x10325476ui32, 0xc3d2e1f0ui32
    };
    static constexpr dgst256_t init224 {
      0xc1059ed8ui32, 0x367cd507ui32, 0x3070dd17ui32, 0xf70e5939ui32,
      0xffc00b31ui32, 0x68581511ui32, 0x64f98fa7ui32, 0xbefa4fa4ui32
    };
    static constexpr dgst256_t init256 {
      0x6a09e667ui32, 0xbb67ae85ui32, 0x3c6ef372ui32, 0xa54ff53aui32,
      0x510e527fui32, 0x9b05688cui32, 0x1f83d9abui32, 0x5be0cd19ui32
    };
    static constexpr dgst512_t init384 {
      0xcbbb9d5dc1059ed8ui64, 0x629a292a367cd507ui64, 0x9159015a3070dd17ui64, 0x152fecd8f70e5939ui64,
      0x67332667ffc00b31ui64, 0x8eb44a8768581511ui64, 0xdb0c2e0d64f98fa7ui64, 0x47b5481dbefa4fa4ui64
    };
    static constexpr dgst512_t init512 {
      0x6a09e667f3bcc908ui64, 0xbb67ae8584caa73bui64, 0x3c6ef372fe94f82bui64, 0xa54ff53a5f1d36f1ui64,
      0x510e527fade682d1ui64, 0x9b05688c2b3e6c1fui64, 0x1f83d9abfb41bd6bui64, 0x5be0cd19137e2179ui64
    };
    static constexpr dgst512_t init512_224 {
      0x8c3d37c819544da2ui64, 0x73e1996689dcd4d6ui64, 0x1dfab7ae32ff9c82ui64, 0x679dd514582f9fcfui64,
      0x0f6d2b697bd44da8ui64, 0x77e36f7304c48942ui64, 0x3f9d85a86a1d36c8ui64, 0x1112e6ad91d692a1ui64
    };
    static constexpr dgst512_t init512_256 {
      0x22312194fc2bf72cui64, 0x9f555fa3c84c64c2ui64, 0x2393b86b6f53b151ui64, 0x963877195940eabdui64,
      0x96283ee2a88effe3ui64, 0xbe5e1e2553863992ui64, 0x2b0199fc2c85b8aaui64, 0x0eb72ddc81c52ca2ui64
    };

    static constexpr const void* findinit() {
      switch (sizeof(out_t)) {
      case sizeof(dgst160_t):
        return (const void*)init160;
      case sizeof(dgst224_t):
        return sizeof(dgst_t) == sizeof(dgst512_t) ? (const void*)init512_224 : (const void*)init224;
      case sizeof(dgst256_t):
        return sizeof(dgst_t) == sizeof(dgst512_t) ? (const void*)init512_256 : (const void*)init256;
      case sizeof(dgst384_t):
        return (const void*)init384;
      case sizeof(dgst512_t) :
        return (const void*)init512;
      default:
        static_assert(true, "Unsupported combination");
        return nullptr;
      }
    }

    static constexpr const void* inithash = findinit();

    static constexpr int w = sizeof(word_t) << 3;
    static constexpr int m = sizeof(buffer) << 3;

    static constexpr int pow2log2(int x) {
      int y = 0;
      while (!(x & 1)) {
        x >>= 1;
        ++y;
      }
      return y;
    }

    bool expand32(size_t bitc) {
      size_t oldlen;
      memcpy(&oldlen, length, sizeof(size_t));
      size_t newlen = oldlen + bitc;
      if (newlen < oldlen)
        return false;
      memcpy(length, &newlen, sizeof(size_t));
      return true;
    }

    bool expand64(size_t bitc) {
      uint64_t newlen[2] { length[0], length[1] };
      if ((newlen[0] += bitc) < length[0] && ++newlen[1] < length[1])
        return false;
      memcpy(length, newlen, sizeof(length));
      return true;
    }

    static constexpr auto expand = w < 64 ? &expand32 : &expand64;

    template<typename word_t>
    static constexpr word_t RotateRight(word_t x, int n) { return (x >> n) | (x << (w - n)); }
    
    static constexpr uint32_t RotateLeft(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

    template<typename word_t>
    static constexpr word_t Ch(word_t x, word_t y, word_t z) { return (x & y) ^ (~x & z); }
    
    template<typename word_t>
    static constexpr word_t Maj(word_t x, word_t y, word_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    
    static constexpr uint32_t Parity(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
    
    static constexpr int abc32[2][2][3] {
      {
        { 7, 18, 3 },   // small sigma zero 32
        { 17, 19, 10 }  // small sigma one 32
      },
      {
        { 2, 13, 22 },  // big sigma zero 32
        { 6, 11, 25 }   // big sigma one 32
      }
    };

    static constexpr int abc64[2][2][3] {
      {
        { 1, 8, 7 },    // small sigma zero 64
        { 19, 61, 6 }   // small sigma one 64
      },
      {
        { 28, 34, 39 }, // big sigma zero 64
        { 14, 18, 41 }  // big sigma one 64
      }
    };

    static constexpr const auto abc = w < 64 ? abc32 : abc64;

    static constexpr word_t sigma(word_t x, int i) { return RotateRight(x, abc[0][i][0]) ^ RotateRight(x, abc[0][i][1]) ^ (x >> abc[0][i][2]); }
    static constexpr word_t Sigma(word_t x, int i) { return RotateRight(x, abc[1][i][0]) ^ RotateRight(x, abc[1][i][1]) ^ RotateRight(x, abc[1][i][2]); }

    void stack160(void* vdst, const void* vblock) {

      auto dst = (uint32_t*)vdst;
      auto block = (const uint32_t*)vblock;

      dgst160_t H;
      memcpy(H, dst, sizeof(dgst160_t));
      uint32_t W[80];
      for (int t = 0; t < 80; ++t) {
        if (t < 16)
          W[t] = block[t];
        else
          W[t] = RotateLeft(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
        uint32_t T = RotateLeft(H[0], 5) + H[4] + W[t];
        if (t < 20)
          T += Ch(H[1], H[2], H[3]) + 0x5a827999ui32;
        else if (t < 40)
          T += Parity(H[1], H[2], H[3]) + 0x6ed9eba1ui32;
        else if (t < 60)
          T += Maj(H[1], H[2], H[3]) + 0x8f1bbcdcui32;
        else
          T += Parity(H[1], H[2], H[3]) + 0xca62c1d6ui32;
        H[4] = H[3];
        H[3] = H[2];
        H[2] = RotateLeft(H[1], 30);
        H[1] = H[0];
        H[0] = T;
      }
      for (int t = 0; t < 5; ++t)
        dst[t] += H[t];

    }

    void defstack(void* vdst, const void* vblock) {

      auto dst = (word_t*)vdst;
      auto block = (const word_t*)vblock;

      static constexpr uint32_t K32[64] {
        0x428a2f98ui32, 0x71374491ui32, 0xb5c0fbcfui32, 0xe9b5dba5ui32, 0x3956c25bui32, 0x59f111f1ui32, 0x923f82a4ui32, 0xab1c5ed5ui32,
        0xd807aa98ui32, 0x12835b01ui32, 0x243185beui32, 0x550c7dc3ui32, 0x72be5d74ui32, 0x80deb1feui32, 0x9bdc06a7ui32, 0xc19bf174ui32,
        0xe49b69c1ui32, 0xefbe4786ui32, 0x0fc19dc6ui32, 0x240ca1ccui32, 0x2de92c6fui32, 0x4a7484aaui32, 0x5cb0a9dcui32, 0x76f988daui32,
        0x983e5152ui32, 0xa831c66dui32, 0xb00327c8ui32, 0xbf597fc7ui32, 0xc6e00bf3ui32, 0xd5a79147ui32, 0x06ca6351ui32, 0x14292967ui32,
        0x27b70a85ui32, 0x2e1b2138ui32, 0x4d2c6dfcui32, 0x53380d13ui32, 0x650a7354ui32, 0x766a0abbui32, 0x81c2c92eui32, 0x92722c85ui32,
        0xa2bfe8a1ui32, 0xa81a664bui32, 0xc24b8b70ui32, 0xc76c51a3ui32, 0xd192e819ui32, 0xd6990624ui32, 0xf40e3585ui32, 0x106aa070ui32,
        0x19a4c116ui32, 0x1e376c08ui32, 0x2748774cui32, 0x34b0bcb5ui32, 0x391c0cb3ui32, 0x4ed8aa4aui32, 0x5b9cca4fui32, 0x682e6ff3ui32,
        0x748f82eeui32, 0x78a5636fui32, 0x84c87814ui32, 0x8cc70208ui32, 0x90befffaui32, 0xa4506cebui32, 0xbef9a3f7ui32, 0xc67178f2ui32
      };

      static constexpr uint64_t K64[80] {
        0x428a2f98d728ae22ui64, 0x7137449123ef65cdui64, 0xb5c0fbcfec4d3b2fui64, 0xe9b5dba58189dbbcui64,
        0x3956c25bf348b538ui64, 0x59f111f1b605d019ui64, 0x923f82a4af194f9bui64, 0xab1c5ed5da6d8118ui64,
        0xd807aa98a3030242ui64, 0x12835b0145706fbeui64, 0x243185be4ee4b28cui64, 0x550c7dc3d5ffb4e2ui64,
        0x72be5d74f27b896fui64, 0x80deb1fe3b1696b1ui64, 0x9bdc06a725c71235ui64, 0xc19bf174cf692694ui64,
        0xe49b69c19ef14ad2ui64, 0xefbe4786384f25e3ui64, 0x0fc19dc68b8cd5b5ui64, 0x240ca1cc77ac9c65ui64,
        0x2de92c6f592b0275ui64, 0x4a7484aa6ea6e483ui64, 0x5cb0a9dcbd41fbd4ui64, 0x76f988da831153b5ui64,
        0x983e5152ee66dfabui64, 0xa831c66d2db43210ui64, 0xb00327c898fb213fui64, 0xbf597fc7beef0ee4ui64,
        0xc6e00bf33da88fc2ui64, 0xd5a79147930aa725ui64, 0x06ca6351e003826fui64, 0x142929670a0e6e70ui64,
        0x27b70a8546d22ffcui64, 0x2e1b21385c26c926ui64, 0x4d2c6dfc5ac42aedui64, 0x53380d139d95b3dfui64,
        0x650a73548baf63deui64, 0x766a0abb3c77b2a8ui64, 0x81c2c92e47edaee6ui64, 0x92722c851482353bui64,
        0xa2bfe8a14cf10364ui64, 0xa81a664bbc423001ui64, 0xc24b8b70d0f89791ui64, 0xc76c51a30654be30ui64,
        0xd192e819d6ef5218ui64, 0xd69906245565a910ui64, 0xf40e35855771202aui64, 0x106aa07032bbd1b8ui64,
        0x19a4c116b8d2d0c8ui64, 0x1e376c085141ab53ui64, 0x2748774cdf8eeb99ui64, 0x34b0bcb5e19b48a8ui64,
        0x391c0cb3c5c95a63ui64, 0x4ed8aa4ae3418acbui64, 0x5b9cca4f7763e373ui64, 0x682e6ff3d6b2b8a3ui64,
        0x748f82ee5defb2fcui64, 0x78a5636f43172f60ui64, 0x84c87814a1f0ab72ui64, 0x8cc702081a6439ecui64,
        0x90befffa23631e28ui64, 0xa4506cebde82bde9ui64, 0xbef9a3f7b2c67915ui64, 0xc67178f2e372532bui64,
        0xca273eceea26619cui64, 0xd186b8c721c0c207ui64, 0xeada7dd6cde0eb1eui64, 0xf57d4f7fee6ed178ui64,
        0x06f067aa72176fbaui64, 0x0a637dc5a2c898a6ui64, 0x113f9804bef90daeui64, 0x1b710b35131c471bui64,
        0x28db77f523047d84ui64, 0x32caab7b40c72493ui64, 0x3c9ebe0a15c9bebcui64, 0x431d67c49c100d4cui64,
        0x4cc5d4becb3e42b6ui64, 0x597f299cfc657e2aui64, 0x5fcb6fab3ad6faecui64, 0x6c44198c4a475817ui64
      };

      static constexpr const word_t* K = w < 64 ? (const word_t*)K32 : (const word_t*)K64;
      static constexpr int count = w < 64 ? 64 : 80;

      dgst_t H;
      memcpy(H, dst, sizeof(dgst_t));
      word_t W[count];
      for (int t = 0; t < count; ++t) {
        if (t < 16)
          W[t] = block[t];
        else
          W[t] = sigma(W[t - 2], 1) + W[t - 7] + sigma(W[t - 15], 0) + W[t - 16];
        word_t T1 = H[7] + Sigma(H[4], 1) + Ch(H[4], H[5], H[6]) + K[t] + W[t];
        word_t T2 = Sigma(H[0], 0) + Maj(H[0], H[1], H[2]);
        H[7] = H[6];
        H[6] = H[5];
        H[5] = H[4];
        H[4] = H[3] + T1;
        H[3] = H[2];
        H[2] = H[1];
        H[1] = H[0];
        H[0] = T1 + T2;
      }
      for (int t = 0; t < 8; ++t)
        dst[t] += H[t];

    }

    static constexpr auto stack = sizeof(dgst_t) == sizeof(dgst160_t) ? &stack160 : &defstack;

    void trunc512_224(void* vdst, const void* vtmp) {
      auto dst = (uint32_t*)vdst;
      auto tmp = (uint64_t*)vtmp;
      for (int i = 0; i < 3; ++i) {
        dst[2 * i] = tmp[i] >> 32;
        dst[2 * i + 1] = tmp[i] & UINT32_MAX;
      }
      dst[6] = tmp[3] >> 32;
    }

    void trunc512_256(void* vdst, const void* vtmp) {
      trunc512_224(vdst, vtmp);
      ((uint32_t*)vdst)[7] = ((uint64_t*)vtmp)[3] & UINT32_MAX;
    }

    void deftrunc(void* vdst, const void* vtmp) { memcpy(vdst, vtmp, sizeof(out_t)); }

    static constexpr auto truncate = sizeof(dgst_t) == sizeof(dgst512_t) ?
      sizeof(out_t) == sizeof(dgst224_t) ? &trunc512_224 :
      sizeof(out_t) == sizeof(dgst256_t) ? &trunc512_256 : &deftrunc :
      &deftrunc;

  public:

    sha_base() : length(), buffer() { memcpy(digest, inithash, sizeof(dgst_t)); }
    sha_base(size_t bitc, const void* bitv) : sha_base() { write(bitc, bitv); }
    sha_base(size_t bitc, const void* bitv, out_t& dst) : sha_base(bitc, bitv) { snapshot(dst); }

    bool write(size_t bitc, const void* bitv) {

      int offbit = length[0] & (w - 1);

      word_t* dstptr = buffer + ((length[0] & (m - 1)) >> pow2log2(w));
      word_t* dstend = buffer + 16;

      if (!(this->*expand)(bitc))
        return false;

      auto srcptr = (const uint8_t*)bitv;

      int len;
      do {
        len = bitc < 8 ? (int)bitc : 8;
        word_t byte = *srcptr >> (8 - len);
        int off = w - len;
        *dstptr |= byte << off >> offbit;
        if (offbit < off) {
          if (bitc - len) {
            offbit += len;
            ++srcptr;
            continue;
          }
          break;
        }
        if (++dstptr >= dstend) {
          (this->*stack)(digest, buffer);
          memset(buffer, 0, sizeof(buffer));
          dstptr = buffer;
        }
        offbit = len - (w - offbit);
        *dstptr |= (byte & (0xff >> (8 - offbit))) << (w - offbit);
        ++srcptr;
      } while (bitc -= len);

      return true;

    }

    sha_base& snapshot(out_t& dst) {

      dgst_t tmp;
      word_t block[16];
      memcpy(tmp, digest, sizeof(dgst_t));
      memcpy(block, buffer, sizeof(buffer));

      int offbit = length[0] & (w - 1);

      word_t* dstptr = block + ((length[0] & (m - 1)) >> pow2log2(w));
      word_t* dstlen = block + 14;

      *dstptr |= (word_t)1 << (w - 1 - offbit);
      if (++dstptr > dstlen) {
        (this->*stack)(tmp, block);
        memset(block, 0, (size_t)14 << pow2log2(sizeof(word_t)));
      }
      *dstlen = length[1];
      *++dstlen = length[0];

      //the block check
      //for (int i = 0; i < 16; ++i)
      //  std::cout << std::bitset<w>(block[i]);
      //std::cout << '\n';

      (this->*stack)(tmp, block);
      (this->*truncate)(dst, tmp);
      
      return *this;

    }

    sha_base& reset() {
      memcpy(digest, inithash, sizeof(dgst_t));
      memset(length, 0, sizeof(length));
      memset(buffer, 0, sizeof(buffer));
      return *this;
    }

  };

  using sha1 = sha_base<uint32_t, dgst160_t, dgst160_t>;
  using sha224 = sha_base<uint32_t, dgst256_t, dgst224_t>;
  using sha256 = sha_base<uint32_t, dgst256_t, dgst256_t>;
  using sha384 = sha_base<uint64_t, dgst512_t, dgst384_t>;
  using sha512 = sha_base<uint64_t, dgst512_t, dgst512_t>;
  using sha512_224 = sha_base<uint64_t, dgst512_t, dgst224_t>;
  using sha512_256 = sha_base<uint64_t, dgst512_t, dgst256_t>;

}
