#ifndef CRYPTO_H
#define CRYPTO_H
#include <stdint.h>
#include <stddef.h>
#define CRYPTO_MAX_KEY_SIZE 32

typedef struct CryptoContext CryptoContext;

typedef struct {
    const char *name;

    CryptoContext *(*init)(const uint8_t *key, size_t key_size);

    void (*encrypt)(CryptoContext *ctx, uint8_t *data, size_t size, uint32_t section_rva);

    void (*decrypt)(CryptoContext *ctx, uint8_t *data, size_t size, uint32_t section_rva);

    size_t (*get_key_bytes)(CryptoContext *ctx, uint8_t *out, size_t out_size);

    void (*destroy)(CryptoContext *ctx);
} CryptoAlgorithm;

extern CryptoAlgorithm xor_cipher;
extern CryptoAlgorithm aes128_ctr_cipher;

CryptoContext *crypto_create(CryptoAlgorithm *algo, const uint8_t *key, size_t key_size);

void crypto_encrypt_section(CryptoAlgorithm *algo, CryptoContext *ctx,
                             uint8_t *section_data, size_t section_size, uint32_t section_rva);

void crypto_decrypt_section(CryptoAlgorithm *algo, CryptoContext *ctx,
                             uint8_t *section_data, size_t section_size, uint32_t section_rva);

/* Returns the 8-byte nonce for the CTR cipher (ignored for XOR). */
size_t crypto_get_nonce(CryptoAlgorithm *algo, CryptoContext *ctx, uint8_t *out, size_t out_size);

#endif
