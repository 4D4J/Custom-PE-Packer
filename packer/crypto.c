#define _CRT_RAND_S
#include "crypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>    /* SecureZeroMemory */
#include <wmmintrin.h>  /* AES-NI intrinsics */
#include <emmintrin.h>  /* SSE2 */

/* --- XOR 1-byte --- */

typedef struct {
    uint8_t key;
} XORContext;

static CryptoContext *xor_init(const uint8_t *key, size_t key_size) {
    if (!key || key_size < 1) {
        fprintf(stderr, "[crypto/xor] Clé invalide (taille %zu).\n", key_size);
        return NULL;
    }
    XORContext *ctx = malloc(sizeof(XORContext));
    if (!ctx) return NULL;
    ctx->key = key[0];
    return (CryptoContext *)ctx;
}

static void xor_encrypt(CryptoContext *ctx, uint8_t *data, size_t size, uint32_t section_rva) {
    (void)section_rva;
    XORContext *xctx = (XORContext *)ctx;
    for (size_t i = 0; i < size; i++) {
        data[i] ^= xctx->key;
    }
}

static void xor_decrypt(CryptoContext *ctx, uint8_t *data, size_t size, uint32_t section_rva) {
    xor_encrypt(ctx, data, size, section_rva);
}

static size_t xor_get_key_bytes(CryptoContext *ctx, uint8_t *out, size_t out_size) {
    XORContext *xctx = (XORContext *)ctx;
    if (out_size < 1) return 0;
    out[0] = xctx->key;
    return 1;
}

static void xor_destroy(CryptoContext *ctx) {
    if (ctx) {
        memset(ctx, 0, sizeof(XORContext));
        free(ctx);
    }
}

CryptoAlgorithm xor_cipher = {
    .name = "XOR",
    .init = xor_init,
    .encrypt = xor_encrypt,
    .decrypt = xor_decrypt,
    .get_key_bytes = xor_get_key_bytes,
    .destroy = xor_destroy,
};




typedef struct {
    uint8_t  master_key[16];
    uint8_t  nonce[8];
    __m128i  round_keys[11];
} AesCtrContext;

/* Standard AES-NI key expansion helper (same recipe as stub.asm::aes128_key_expand). */
static __m128i aes128_expand_step(__m128i prev, __m128i kgen) {
    kgen  = _mm_shuffle_epi32(kgen, 0xFF);
    __m128i t = prev;
    t = _mm_xor_si128(t, _mm_slli_si128(prev, 4));
    __m128i s2 = _mm_slli_si128(prev, 8);
    t = _mm_xor_si128(t, s2);
    __m128i s3 = _mm_slli_si128(prev, 12);
    t = _mm_xor_si128(t, s3);
    t = _mm_xor_si128(t, kgen);
    return t;
}

static void aes128_key_schedule(const uint8_t key[16], __m128i rk[11]) {
    rk[0]  = _mm_loadu_si128((const __m128i *)key);
    rk[1]  = aes128_expand_step(rk[0],  _mm_aeskeygenassist_si128(rk[0],  0x01));
    rk[2]  = aes128_expand_step(rk[1],  _mm_aeskeygenassist_si128(rk[1],  0x02));
    rk[3]  = aes128_expand_step(rk[2],  _mm_aeskeygenassist_si128(rk[2],  0x04));
    rk[4]  = aes128_expand_step(rk[3],  _mm_aeskeygenassist_si128(rk[3],  0x08));
    rk[5]  = aes128_expand_step(rk[4],  _mm_aeskeygenassist_si128(rk[4],  0x10));
    rk[6]  = aes128_expand_step(rk[5],  _mm_aeskeygenassist_si128(rk[5],  0x20));
    rk[7]  = aes128_expand_step(rk[6],  _mm_aeskeygenassist_si128(rk[6],  0x40));
    rk[8]  = aes128_expand_step(rk[7],  _mm_aeskeygenassist_si128(rk[7],  0x80));
    rk[9]  = aes128_expand_step(rk[8],  _mm_aeskeygenassist_si128(rk[8],  0x1B));
    rk[10] = aes128_expand_step(rk[9],  _mm_aeskeygenassist_si128(rk[9],  0x36));
}

static __m128i aes128_encrypt_block(__m128i block, const __m128i rk[11]) {
    block = _mm_xor_si128(block, rk[0]);
    block = _mm_aesenc_si128(block, rk[1]);
    block = _mm_aesenc_si128(block, rk[2]);
    block = _mm_aesenc_si128(block, rk[3]);
    block = _mm_aesenc_si128(block, rk[4]);
    block = _mm_aesenc_si128(block, rk[5]);
    block = _mm_aesenc_si128(block, rk[6]);
    block = _mm_aesenc_si128(block, rk[7]);
    block = _mm_aesenc_si128(block, rk[8]);
    block = _mm_aesenc_si128(block, rk[9]);
    block = _mm_aesenclast_si128(block, rk[10]);
    return block;
}

/* Fills *nonce with 8 bytes from the OS RNG (rand_s on Windows). */
static int generate_nonce(uint8_t nonce[8]) {
    unsigned int r;
    for (int i = 0; i < 8; i += 4) {
        if (rand_s(&r) != 0) return -1;
        memcpy(nonce + i, &r, 4);
    }
    return 0;
}

static CryptoContext *aes128_ctr_init(const uint8_t *key, size_t key_size) {
    if (!key || key_size != 16) {
        fprintf(stderr, "[crypto/aes] Clé AES-128 invalide (taille %zu, attendu 16).\n", key_size);
        return NULL;
    }
    AesCtrContext *ctx = _aligned_malloc(sizeof(AesCtrContext), 16);
    if (!ctx) return NULL;

    memcpy(ctx->master_key, key, 16);
    if (generate_nonce(ctx->nonce) != 0) {
        _aligned_free(ctx);
        fprintf(stderr, "[crypto/aes] Génération du nonce échouée.\n");
        return NULL;
    }
    aes128_key_schedule(ctx->master_key, ctx->round_keys);
    return (CryptoContext *)ctx;
}

static void aes128_ctr_crypt(CryptoContext *c, uint8_t *data, size_t size, uint32_t section_rva) {
    AesCtrContext *ctx = (AesCtrContext *)c;
    uint8_t ctr_block[16];
    memcpy(ctr_block + 0, ctx->nonce, 8);
    memcpy(ctr_block + 8, &section_rva, 4);
    /* bytes 12..15 are the little-endian block counter, set per iteration. */

    size_t full_blocks = size / 16;
    size_t tail        = size % 16;

    for (size_t i = 0; i < full_blocks; i++) {
        uint32_t block_idx = (uint32_t)i;
        memcpy(ctr_block + 12, &block_idx, 4);
        __m128i cb = _mm_loadu_si128((const __m128i *)ctr_block);
        __m128i ks = aes128_encrypt_block(cb, ctx->round_keys);
        __m128i pt = _mm_loadu_si128((const __m128i *)(data + i * 16));
        _mm_storeu_si128((__m128i *)(data + i * 16), _mm_xor_si128(pt, ks));
    }

    if (tail > 0) {
        uint32_t block_idx = (uint32_t)full_blocks;
        memcpy(ctr_block + 12, &block_idx, 4);
        __m128i cb = _mm_loadu_si128((const __m128i *)ctr_block);
        __m128i ks_vec = aes128_encrypt_block(cb, ctx->round_keys);
        uint8_t ks[16];
        _mm_storeu_si128((__m128i *)ks, ks_vec);
        uint8_t *dst = data + full_blocks * 16;
        for (size_t j = 0; j < tail; j++) dst[j] ^= ks[j];
    }
}

static size_t aes128_ctr_get_key_bytes(CryptoContext *c, uint8_t *out, size_t out_size) {
    AesCtrContext *ctx = (AesCtrContext *)c;
    if (out_size < 16) return 0;
    memcpy(out, ctx->master_key, 16);
    return 16;
}

static void aes128_ctr_destroy(CryptoContext *c) {
    if (!c) return;
    SecureZeroMemory(c, sizeof(AesCtrContext));
    _aligned_free(c);
}

CryptoAlgorithm aes128_ctr_cipher = {
    .name = "AES-128-CTR",
    .init = aes128_ctr_init,
    .encrypt = aes128_ctr_crypt,
    .decrypt = aes128_ctr_crypt,
    .get_key_bytes = aes128_ctr_get_key_bytes,
    .destroy = aes128_ctr_destroy,
};


/* --- Public helpers --- */

CryptoContext *crypto_create(CryptoAlgorithm *algo, const uint8_t *key, size_t key_size) {
    if (!algo || !algo->init) return NULL;
    return algo->init(key, key_size);
}

void crypto_encrypt_section(CryptoAlgorithm *algo, CryptoContext *ctx,
                             uint8_t *section_data, size_t section_size, uint32_t section_rva) {
    if (!algo || !algo->encrypt || !section_data || section_size == 0) return;
    algo->encrypt(ctx, section_data, section_size, section_rva);
}

void crypto_decrypt_section(CryptoAlgorithm *algo, CryptoContext *ctx,
                             uint8_t *section_data, size_t section_size, uint32_t section_rva) {
    if (!algo || !algo->decrypt || !section_data || section_size == 0) return;
    algo->decrypt(ctx, section_data, section_size, section_rva);
}

size_t crypto_get_nonce(CryptoAlgorithm *algo, CryptoContext *ctx, uint8_t *out, size_t out_size) {
    if (algo != &aes128_ctr_cipher || !ctx || !out || out_size < 8) return 0;
    AesCtrContext *actx = (AesCtrContext *)ctx;
    memcpy(out, actx->nonce, 8);
    return 8;
}
