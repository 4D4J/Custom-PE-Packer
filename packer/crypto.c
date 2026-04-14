#include "crypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

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

static void xor_encrypt(CryptoContext *ctx, uint8_t *data, size_t size) {
    XORContext *xctx = (XORContext *)ctx;
    for (size_t i = 0; i < size; i++) {
        data[i] ^= xctx->key;
    }
}

static void xor_decrypt(CryptoContext *ctx, uint8_t *data, size_t size) {
    xor_encrypt(ctx, data, size);
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


CryptoContext *crypto_create(CryptoAlgorithm *algo, const uint8_t *key, size_t key_size) {
    if (!algo || !algo->init) return NULL;
    return algo->init(key, key_size);
}

void crypto_encrypt_section(CryptoAlgorithm *algo, CryptoContext *ctx,
                             uint8_t *section_data, size_t section_size) {
    if (!algo || !algo->encrypt || !section_data || section_size == 0) return;
    algo->encrypt(ctx, section_data, section_size);
}
