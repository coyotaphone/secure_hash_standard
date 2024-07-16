#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#include <stdlib.h>
#include <string.h>

typedef uint32_t digest160_t[160 / 32];
typedef uint32_t digest224_t[224 / 32];
typedef uint32_t digest256_t[256 / 32];
typedef uint64_t digest384_t[384 / 64];
typedef uint64_t digest512_t[512 / 64];

typedef struct SHA1 SHA1;
typedef struct SHA256 SHA224, SHA256;
typedef struct SHA512 SHA384, SHA512, SHA512_224, SHA512_256;

bool CreateSHA1(SHA1** msg);
bool WriteSHA1(SHA1* msg, size_t bitc, const void* bitv);
bool SnapshotSHA1(const SHA1* msg, digest160_t dst);
bool ResetSHA1(SHA1* msg);
bool DestroySHA1(SHA1* msg);

bool CreateSHA224(SHA224** msg);
bool WriteSHA224(SHA224* msg, size_t bitc, const void* bitv);
bool SnapshotSHA224(const SHA224* msg, digest224_t dst);
bool ResetSHA224(SHA224* msg);
bool DestroySHA224(SHA224* msg);

bool CreateSHA256(SHA256** msg);
bool WriteSHA256(SHA256* msg, size_t bitc, const void* bitv);
bool SnapshotSHA256(const SHA256* msg, digest256_t dst);
bool ResetSHA256(SHA256* msg);
bool DestroySHA256(SHA256* msg);

bool CreateSHA384(SHA384** msg);
bool WriteSHA384(SHA384* msg, size_t bitc, const void* bitv);
bool SnapshotSHA384(const SHA384* msg, digest384_t dst);
bool ResetSHA384(SHA384* msg);
bool DestroySHA384(SHA384* msg);

bool CreateSHA512(SHA512** msg);
bool WriteSHA512(SHA512* msg, size_t bitc, const void* bitv);
bool SnapshotSHA512(const SHA512* msg, digest512_t dst);
bool ResetSHA512(SHA512* msg);
bool DestroySHA512(SHA512* msg);

bool CreateSHA512_224(SHA512_224** msg);
bool WriteSHA512_224(SHA512_224* msg, size_t bitc, const void* bitv);
bool SnapshotSHA512_224(const SHA512_224* msg, digest224_t dst);
bool ResetSHA512_224(SHA512_224* msg);
bool DestroySHA512_224(SHA512_224* msg);

bool CreateSHA512_256(SHA512_256** msg);
bool WriteSHA512_256(SHA512_256* msg, size_t bitc, const void* bitv);
bool SnapshotSHA512_256(const SHA512_256* msg, digest256_t dst);
bool ResetSHA512_256(SHA512_256* msg);
bool DestroySHA512_256(SHA512_256* msg);

#ifdef __cplusplus
}
#endif
