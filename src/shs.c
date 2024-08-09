#include "../include/shs.h"

typedef struct {
  uint64_t loword;
  uint64_t hiword;
} uint128_t;

typedef uint32_t block512_t[512 / 32];
typedef uint64_t block1024_t[1024 / 64];

typedef uint32_t schedule_t[64];
typedef uint64_t schedule64_t[80];

struct SHA1 {
  uint64_t length;
  block512_t buffer;
  digest160_t digest;
};

struct SHA256 {
  uint64_t length;
  block512_t buffer;
  digest256_t digest;
};

struct SHA512 {
  uint128_t length;
  block1024_t buffer;
  digest512_t digest;
};

static inline uint32_t RotateRight(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static inline uint64_t RotateRight64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

static inline uint32_t RotateLeft(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static inline uint64_t Ch64(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (~x & z); }

static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static inline uint64_t Maj64(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (x & z) ^ (y & z); }

static inline uint32_t Parity(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }

static inline uint32_t BigSigmaZero(uint32_t x) { return RotateRight(x, 2) ^ RotateRight(x, 13) ^ RotateRight(x, 22); }
static inline uint64_t BigSigmaZero64(uint64_t x) { return RotateRight64(x, 28) ^ RotateRight64(x, 34) ^ RotateRight64(x, 39); }

static inline uint32_t BigSigmaOne(uint32_t x) { return RotateRight(x, 6) ^ RotateRight(x, 11) ^ RotateRight(x, 25); }
static inline uint64_t BigSigmaOne64(uint64_t x) { return RotateRight64(x, 14) ^ RotateRight64(x, 18) ^ RotateRight64(x, 41); }

static inline uint32_t SmallSigmaZero(uint32_t x) { return RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3); }
static inline uint64_t SmallSigmaZero64(uint64_t x) { return RotateRight64(x, 1) ^ RotateRight64(x, 8) ^ (x >> 7); }

static inline uint32_t SmallSigmaOne(uint32_t x) { return RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10); }
static inline uint64_t SmallSigmaOne64(uint64_t x) { return RotateRight64(x, 19) ^ RotateRight64(x, 61) ^ (x >> 6); }

static void WriteBlockSHA1(const block512_t block, digest160_t dst) {
  uint32_t W[80];
  digest160_t H;
  memcpy(H, dst, sizeof(digest160_t));
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

static void WriteBlockSHA256(const block512_t block, digest256_t dst) {
  schedule_t W;
  static const schedule_t K = {
    0x428a2f98ui32, 0x71374491ui32, 0xb5c0fbcfui32, 0xe9b5dba5ui32, 0x3956c25bui32, 0x59f111f1ui32, 0x923f82a4ui32, 0xab1c5ed5ui32,
    0xd807aa98ui32, 0x12835b01ui32, 0x243185beui32, 0x550c7dc3ui32, 0x72be5d74ui32, 0x80deb1feui32, 0x9bdc06a7ui32, 0xc19bf174ui32,
    0xe49b69c1ui32, 0xefbe4786ui32, 0x0fc19dc6ui32, 0x240ca1ccui32, 0x2de92c6fui32, 0x4a7484aaui32, 0x5cb0a9dcui32, 0x76f988daui32,
    0x983e5152ui32, 0xa831c66dui32, 0xb00327c8ui32, 0xbf597fc7ui32, 0xc6e00bf3ui32, 0xd5a79147ui32, 0x06ca6351ui32, 0x14292967ui32,
    0x27b70a85ui32, 0x2e1b2138ui32, 0x4d2c6dfcui32, 0x53380d13ui32, 0x650a7354ui32, 0x766a0abbui32, 0x81c2c92eui32, 0x92722c85ui32,
    0xa2bfe8a1ui32, 0xa81a664bui32, 0xc24b8b70ui32, 0xc76c51a3ui32, 0xd192e819ui32, 0xd6990624ui32, 0xf40e3585ui32, 0x106aa070ui32,
    0x19a4c116ui32, 0x1e376c08ui32, 0x2748774cui32, 0x34b0bcb5ui32, 0x391c0cb3ui32, 0x4ed8aa4aui32, 0x5b9cca4fui32, 0x682e6ff3ui32,
    0x748f82eeui32, 0x78a5636fui32, 0x84c87814ui32, 0x8cc70208ui32, 0x90befffaui32, 0xa4506cebui32, 0xbef9a3f7ui32, 0xc67178f2ui32
  };
  digest256_t H;
  memcpy(H, dst, sizeof(digest256_t));
  for (int t = 0; t < 64; ++t) {
    if (t < 16)
      W[t] = block[t];
    else
      W[t] = SmallSigmaOne(W[t - 2]) + W[t - 7] + SmallSigmaZero(W[t - 15]) + W[t - 16];
    uint32_t T1 = H[7] + BigSigmaOne(H[4]) + Ch(H[4], H[5], H[6]) + K[t] + W[t];
    uint32_t T2 = BigSigmaZero(H[0]) + Maj(H[0], H[1], H[2]);
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

static void WriteBlockSHA512(const block1024_t block, digest512_t dst) {
  schedule64_t W;
  static const schedule64_t K = {
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
  digest512_t H;
  memcpy(H, dst, sizeof(digest512_t));
  for (int t = 0; t < 80; ++t) {
    if (t < 16)
      W[t] = block[t];
    else
      W[t] = SmallSigmaOne64(W[t - 2]) + W[t - 7] + SmallSigmaZero64(W[t - 15]) + W[t - 16];
    uint64_t T1 = H[7] + BigSigmaOne64(H[4]) + Ch64(H[4], H[5], H[6]) + K[t] + W[t];
    uint64_t T2 = BigSigmaZero64(H[0]) + Maj64(H[0], H[1], H[2]);
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

static bool SafeDestroy(void* msg) {
  if (!msg)
    return false;
  free(msg);
  return true;
}

// SHA-1

bool CreateSHA1(SHA1** msg) {
  return msg && (*msg = malloc(sizeof(SHA1))) && ResetSHA1(*msg);
}

bool WriteSHA1(SHA1* msg, size_t bitc, const void* bitv) {

  if (!msg || !bitv || msg->length + bitc <= msg->length)
    return false;

  uint32_t* dstptr = msg->buffer + ((msg->length & 511) >> 5);
  uint32_t* dstend = msg->buffer + 16;

  const uint8_t* srcptr = (const uint8_t*)bitv;

  size_t len;
  size_t offbit = msg->length & 31;
  do {
    len = bitc < 8 ? bitc : 8;
    uint32_t byte = (uint32_t)*srcptr >> (8 - len);
    size_t off = 32 - len;
    *dstptr |= byte << off >> offbit;
    if (offbit < off) {
      msg->length += len;
      if (bitc - len) {
        offbit += len;
        ++srcptr;
        continue;
      }
      break;
    }
    if (++dstptr >= dstend) {
      WriteBlockSHA1(msg->buffer, msg->digest);
      memset(msg->buffer, 0, sizeof(block512_t));
      dstptr = msg->buffer;
    }
    offbit = len - (32 - offbit);
    *dstptr |= (byte & (0xffui32 >> (8 - offbit))) << (32 - offbit);
    msg->length += len;
    ++srcptr;
  } while (bitc -= len);
  return true;

}

bool SnapshotSHA1(const SHA1* msg, digest160_t dst) {

  if (!msg || !dst)
    return false;

  block512_t block;
  memcpy(block, msg->buffer, sizeof(block512_t));
  memcpy(dst, msg->digest, sizeof(digest160_t));
  uint32_t* dstptr = block + ((msg->length & 511) >> 5);
  uint32_t* dstlen = block + 14;
  int offbit = msg->length & 31;
  *dstptr |= 1ui32 << (31 - offbit++);
  if (++dstptr > dstlen) {
    WriteBlockSHA1(block, dst);
    memset(block, 0, (dstlen - block) << 2);
  }
  *dstlen++ = msg->length >> 32;
  *dstlen = msg->length & 0xffffffffui64;
  WriteBlockSHA1(block, dst);
  return true;

}

bool ResetSHA1(SHA1* msg) {
  if (!msg)
    return false;
  static const SHA1 sha1 = {
    0ui64, { 0x00000000ui32 },
    { 0x67452301ui32, 0xefcdab89ui32, 0x98badcfeui32, 0x10325476ui32, 0xc3d2e1f0ui32 }
  };
  memcpy(msg, &sha1, sizeof(SHA1));
  return true;
}

bool DestroySHA1(SHA1* msg) { return SafeDestroy(msg); }

// SHA-224

bool CreateSHA224(SHA224** msg) {
  return msg && (*msg = malloc(sizeof(SHA224))) && ResetSHA224(*msg);
}

bool WriteSHA224(SHA224* msg, size_t bitc, const void* bitv) { return WriteSHA256(msg, bitc, bitv); }

bool SnapshotSHA224(const SHA224* msg, digest224_t dst) {
  digest256_t tmp;
  if (!dst || !SnapshotSHA256(msg, tmp))
    return false;
  memcpy(dst, tmp, sizeof(digest224_t));
  return true;
}

bool ResetSHA224(SHA224* msg) {
  if (!msg)
    return false;
  static const SHA224 sha224 = {
    0ui64, { 0x00000000ui32 },
    { 0xc1059ed8ui32, 0x367cd507ui32, 0x3070dd17ui32, 0xf70e5939ui32, 0xffc00b31ui32, 0x68581511ui32, 0x64f98fa7ui32, 0xbefa4fa4ui32 }
  };
  memcpy(msg, &sha224, sizeof(SHA224));
  return true;
}

bool DestroySHA224(SHA224* msg) { return SafeDestroy(msg); }

// SHA-256

bool CreateSHA256(SHA256** msg) {
  return msg && (*msg = malloc(sizeof(SHA256))) && ResetSHA256(*msg);
}

bool WriteSHA256(SHA256* msg, size_t bitc, const void* bitv) {

  if (!msg || !bitv || msg->length + bitc <= msg->length)
    return false;

  uint32_t* dstptr = msg->buffer + ((msg->length & 511) >> 5);
  uint32_t* dstend = msg->buffer + 16;

  const uint8_t* srcptr = (const uint8_t*)bitv;

  size_t len;
  size_t offbit = msg->length & 31;
  do {
    len = bitc < 8 ? bitc : 8;
    uint32_t byte = (uint32_t)*srcptr >> (8 - len);
    size_t off = 32 - len;
    *dstptr |= byte << off >> offbit;
    if (offbit < off) {
      msg->length += len;
      if (bitc - len) {
        offbit += len;
        ++srcptr;
        continue;
      }
      break;
    }
    if (++dstptr >= dstend) {
      WriteBlockSHA256(msg->buffer, msg->digest);
      memset(msg->buffer, 0, sizeof(block512_t));
      dstptr = msg->buffer;
    }
    offbit = len - (32 - offbit);
    *dstptr |= (byte & (0xffui32 >> (8 - offbit))) << (32 - offbit);
    msg->length += len;
    ++srcptr;
  } while (bitc -= len);
  return true;

}

bool SnapshotSHA256(const SHA256* msg, digest256_t dst) {

  if (!msg || !dst)
    return false;

  block512_t block;
  memcpy(block, msg->buffer, sizeof(block512_t));
  memcpy(dst, msg->digest, sizeof(digest256_t));
  uint32_t* dstptr = block + ((msg->length & 511) >> 5);
  uint32_t* dstlen = block + 14;
  int offbit = msg->length & 31;
  *dstptr |= 1ui32 << (31 - offbit++);
  if (++dstptr > dstlen) {
    WriteBlockSHA256(block, dst);
    memset(block, 0, (dstlen - block) << 2);
  }
  *dstlen++ = msg->length >> 32;
  *dstlen = msg->length & 0xffffffffui64;
  WriteBlockSHA256(block, dst);
  return true;

}

bool ResetSHA256(SHA256* msg) {
  if (!msg)
    return false;
  static const SHA256 sha256 = {
    0ui64, { 0x00000000ui32 },
    { 0x6a09e667ui32, 0xbb67ae85ui32, 0x3c6ef372ui32, 0xa54ff53aui32, 0x510e527fui32, 0x9b05688cui32, 0x1f83d9abui32, 0x5be0cd19ui32 }
  };
  memcpy(msg, &sha256, sizeof(SHA256));
  return true;
}

bool DestroySHA256(SHA256* msg) { return SafeDestroy(msg); }

// SHA-384

bool CreateSHA384(SHA384** msg) {
  return msg && (*msg = malloc(sizeof(SHA384))) && ResetSHA384(*msg);
}

bool WriteSHA384(SHA384* msg, size_t bitc, const void* bitv) { return WriteSHA512(msg, bitc, bitv); }

bool SnapshotSHA384(const SHA384* msg, digest384_t dst) {
  digest512_t tmp;
  if (!dst || !SnapshotSHA512(msg, tmp))
    return false;
  memcpy(dst, tmp, sizeof(digest384_t));
  return true;
}

bool ResetSHA384(SHA384* msg) {
  if (!msg)
    return false;
  static const SHA384 sha384 = {
    { 0ui64, 0ui64 }, { 0x0000000000000000ui64 }, {
      0xcbbb9d5dc1059ed8ui64, 0x629a292a367cd507ui64, 0x9159015a3070dd17ui64, 0x152fecd8f70e5939ui64,
      0x67332667ffc00b31ui64, 0x8eb44a8768581511ui64, 0xdb0c2e0d64f98fa7ui64, 0x47b5481dbefa4fa4ui64
    }
  };
  memcpy(msg, &sha384, sizeof(SHA384));
  return true;
}

bool DestroySHA384(SHA384* msg) { return SafeDestroy(msg); }

// SHA-512

bool CreateSHA512(SHA512** msg) {
  return msg && (*msg = malloc(sizeof(SHA512))) && ResetSHA512(*msg);
}

bool WriteSHA512(SHA512* msg, size_t bitc, const void* bitv) {

  if (!msg || !bitc || !bitv ||
    (msg->length.loword + bitc < msg->length.loword &&
    msg->length.hiword + 1ui64 < msg->length.hiword))
    return false;

  uint64_t* dstptr = msg->buffer + ((msg->length.loword & 1023) >> 6);
  uint64_t* dstend = msg->buffer + 16;

  const uint8_t* srcptr = (const uint8_t*)bitv;

  size_t len;
  size_t offbit = msg->length.loword & 63;
  do {
    len = bitc < 8 ? bitc : 8;
    uint64_t byte = (uint64_t)*srcptr >> (8 - len);
    size_t off = 64 - len;
    *dstptr |= byte << off >> offbit;
    if (offbit < off) {
      uint64_t tmp = msg->length.loword;
      if ((msg->length.loword += len) < tmp)
        ++msg->length.hiword;
      if (bitc - len) {
        offbit += len;
        ++srcptr;
        continue;
      }
      break;
    }
    if (++dstptr >= dstend) {
      WriteBlockSHA512(msg->buffer, msg->digest);
      memset(msg->buffer, 0, sizeof(block1024_t));
      dstptr = msg->buffer;
    }
    offbit = len - (64 - offbit);
    *dstptr |= (byte & (0xffui64 >> (8 - offbit))) << (64 - offbit);
    uint64_t prev = msg->length.loword;
    if ((msg->length.loword += len) < prev)
      ++msg->length.hiword;
    ++srcptr;
  } while (bitc -= len);
  return true;

}

bool SnapshotSHA512(const SHA512* msg, digest512_t dst) {

  if (!msg || !dst)
    return false;

  block1024_t block;
  memcpy(block, msg->buffer, sizeof(block1024_t));
  memcpy(dst, msg->digest, sizeof(digest512_t));
  uint64_t* dstptr = block + ((msg->length.loword & 1023) >> 6);
  uint64_t* dstlen = block + 14;
  int offbit = msg->length.loword & 63;
  *dstptr |= 1ui64 << (63 - offbit++);
  if (++dstptr > dstlen) {
    WriteBlockSHA512(block, dst);
    memset(block, 0, (dstlen - block) << 3);
  }
  *dstlen++ = msg->length.hiword;
  *dstlen = msg->length.loword;
  WriteBlockSHA512(block, dst);
  return true;

}

bool ResetSHA512(SHA512* msg) {
  if (!msg)
    return false;
  static const SHA512 sha512 = {
    { 0ui64, 0ui64 }, { 0x0000000000000000ui64 }, {
      0x6a09e667f3bcc908ui64, 0xbb67ae8584caa73bui64, 0x3c6ef372fe94f82bui64, 0xa54ff53a5f1d36f1ui64,
      0x510e527fade682d1ui64, 0x9b05688c2b3e6c1fui64, 0x1f83d9abfb41bd6bui64, 0x5be0cd19137e2179ui64
    }
  };
  memcpy(msg, &sha512, sizeof(SHA512));
  return true;
}

bool DestroySHA512(SHA512* msg) { return SafeDestroy(msg); }

// SHA-512/224

bool CreateSHA512_224(SHA512_224** msg) {
  return msg && (*msg = malloc(sizeof(SHA512_224))) && ResetSHA512_224(*msg);
}

bool WriteSHA512_224(SHA512_224* msg, size_t bitc, const void* bitv) { return WriteSHA512(msg, bitc, bitv); }

bool SnapshotSHA512_224(const SHA512_224* msg, digest224_t dst) {
  digest512_t tmp;
  if (!dst || !SnapshotSHA512(msg, tmp))
    return false;
  for (int i = 0; i < 3; ++i) {
    dst[2 * i] = tmp[i] >> 32;
    dst[2 * i + 1] = tmp[i] & UINT32_MAX;
  }
  dst[6] = tmp[3] >> 32;
  return true;
}

bool ResetSHA512_224(SHA512_224* msg) {
  if (!msg)
    return false;
  static const SHA512_224 sha512_224 = {
    { 0ui64, 0ui64 }, { 0x0000000000000000ui64 }, {
      0x8C3D37C819544DA2ui64, 0x73E1996689DCD4D6ui64, 0x1DFAB7AE32FF9C82ui64, 0x679DD514582F9FCFui64,
      0x0F6D2B697BD44DA8ui64, 0x77E36F7304C48942ui64, 0x3F9D85A86A1D36C8ui64, 0x1112E6AD91D692A1ui64
    }
  };
  memcpy(msg, &sha512_224, sizeof(SHA512_224));
  return true;
}

bool DestroySHA512_224(SHA512_224* msg) { return SafeDestroy(msg); }

// SHA-512/256

bool CreateSHA512_256(SHA512_256** msg) {
  return msg && (*msg = malloc(sizeof(SHA512_224))) && ResetSHA512_256(*msg);
}

bool WriteSHA512_256(SHA512_256* msg, size_t bitc, const void* bitv) { return WriteSHA512(msg, bitc, bitv); }

bool SnapshotSHA512_256(const SHA512_256* msg, digest256_t dst) {
  digest512_t tmp;
  if (!dst || !SnapshotSHA512(msg, tmp))
    return false;
  for (int i = 0; i < 4; i++) {
    dst[2 * i] = tmp[i] >> 32;
    dst[2 * i + 1] = tmp[i] & UINT32_MAX;
  }
  return true;
}

bool ResetSHA512_256(SHA512_256* msg) {
  if (!msg)
    return false;
  static const SHA512_256 sha512_256 = {
    { 0ui64, 0ui64 }, { 0x0000000000000000ui64 }, {
      0x22312194FC2BF72Cui64, 0x9F555FA3C84C64C2ui64, 0x2393B86B6F53B151ui64, 0x963877195940EABDui64,
      0x96283EE2A88EFFE3ui64, 0xBE5E1E2553863992ui64, 0x2B0199FC2C85B8AAui64, 0x0EB72DDC81C52CA2ui64
    }
  };
  memcpy(msg, &sha512_256, sizeof(SHA512_256));
  return true;
}

bool DestroySHA512_256(SHA512_256* msg) { return SafeDestroy(msg); }
