#ifndef CRYPTO_H
#define CRYPTO_H
#include <stdint.h>
#include <stddef.h>
#define CRYPTO_MAX_KEY_SIZE 32

typedef struct CryptoContext CryptoContext;

typedef struct {
    const char *name;  

    CryptoContext *(*init)(const uint8_t *key, size_t key_size);

    void (*encrypt)(CryptoContext *ctx, uint8_t *data, size_t size);

    void (*decrypt)(CryptoContext *ctx, uint8_t *data, size_t size);

    size_t (*get_key_bytes)(CryptoContext *ctx, uint8_t *out, size_t out_size);

    void (*destroy)(CryptoContext *ctx);
} CryptoAlgorithm;

extern CryptoAlgorithm xor_cipher;

CryptoContext *crypto_create(CryptoAlgorithm *algo, const uint8_t *key, size_t key_size);

void crypto_encrypt_section(CryptoAlgorithm *algo, CryptoContext *ctx, uint8_t *section_data, size_t section_size);

void crypto_decrypt_section(CryptoAlgorithm *algo, CryptoContext *ctx, uint8_t *section_data, size_t section_size);

#endif
