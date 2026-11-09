#define _CRT_RAND_S
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "pe_utils.h"
#include "crypto.h"

#define STUB_CODE_OFFSET 0xE0U
#define STUB_MAX_SECTIONS 16
#define STUB_SECTION_NAME_DEFAULT ".text"  /* blends with existing .text */

#define STUB_SECTION_FLAGS (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)

/* Offsets inside stub.bin's config block. Must match stub.asm layout. */
#define CFG_OFF_MAGIC            0x00
#define CFG_OFF_NUM_SECTIONS     0x08
#define CFG_OFF_XOR_KEY          0x09
#define CFG_OFF_ALGO             0x0A
#define CFG_OFF_ORIGINAL_OEP     0x0C
#define CFG_OFF_IMAGE_BASE       0x10
#define CFG_OFF_IMPORT_RVA       0x18
#define CFG_OFF_IMPORT_SIZE      0x1C
#define CFG_OFF_TLS_RVA          0x20
#define CFG_OFF_TLS_SIZE         0x24
#define CFG_OFF_HASH_GETPROCADDR 0x28
#define CFG_OFF_HASH_LOADLIB     0x2C
#define CFG_OFF_HASH_VIRTUALALLOC 0x30
#define CFG_OFF_SECTIONS         0x40
#define CFG_OFF_AES_KEY          0xC0
#define CFG_OFF_AES_NONCE        0xD0
#define CONFIG_MAGIC_VALUE       0xDEADBEEF

#define CRYPTO_ALGO_XOR     0x00
#define CRYPTO_ALGO_AES128  0x01

static uint32_t djb2(const char *s) {
    uint32_t h = 5381;
    for (; *s; s++) {
        h = (h * 33u) + (uint8_t)*s;
    }
    return h;
}

static uint8_t *load_stub_blob(const char *stub_path, size_t *out_size) {
    FILE *f = fopen(stub_path, "rb");
    if (!f) {
        fprintf(stderr, "[packer] Impossible d'ouvrir %s : avez-vous compilé le stub ?\n" 
			            " Commande : nasm -f bin stub.asm -o stub.bin\n", stub_path);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);

    if (sz < (long)STUB_CODE_OFFSET) {
        fprintf(stderr, "[packer] stub.bin trop petit (%ld octets < %u attendus).\n", sz, STUB_CODE_OFFSET);
        fclose(f);
        return NULL;
    }

    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }

    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (n != (size_t)sz) {
        fprintf(stderr, "[packer] Lecture incomplète de %s (%zu/%ld octets).\n", stub_path, n, sz);
        free(buf);
        return NULL;
    }

    *out_size = (size_t)sz;
    return buf;
}


static void write_u32_le(uint8_t *buf, size_t offset, uint32_t value) {
    buf[offset + 0] = (uint8_t)(value & 0xFF);
    buf[offset + 1] = (uint8_t)((value >> 8)  & 0xFF);
    buf[offset + 2] = (uint8_t)((value >> 16) & 0xFF);
    buf[offset + 3] = (uint8_t)((value >> 24) & 0xFF);
}

static void write_u64_le(uint8_t *buf, size_t offset, uint64_t value) {
    for (int i = 0; i < 8; i++) {
        buf[offset + i] = (uint8_t)((value >> (i * 8)) & 0xFF);
    }
}


static const char *const SKIP_ENCRYPT_SECTIONS[] = {
    ".rsrc",
    ".pdata",
    ".reloc",
    ".00cfg",
    NULL,
};

static int should_encrypt_section(IMAGE_SECTION_HEADER *sect) {
    if (sect->SizeOfRawData == 0) return 0;

    /* Called BEFORE our section is added, so no self-check needed. */
    for (int i = 0; SKIP_ENCRYPT_SECTIONS[i]; i++) {
        if (strncmp((char *)sect->Name, SKIP_ENCRYPT_SECTIONS[i], 8) == 0) {
            return 0;
        }
    }

    return 1;
}


typedef enum {
    TS_MODE_PRESERVE = 0, 
    TS_MODE_ZERO,          
    TS_MODE_RANDOM,        
} TimestampMode;

typedef struct {
    const char    *section_name;   /* 1..8 chars, truncated if longer */
    TimestampMode  ts_mode;
    int            fix_checksum;   /* 1 to recompute OptionalHeader.CheckSum */
} HygieneOptions;

static int pack_pe(const char *input_path, const char *output_path, const char *stub_path,
                    uint8_t algo_id, const uint8_t *key, size_t key_size,
                    const HygieneOptions *hy) {
    int ret = -1;
    CryptoContext *ctx = NULL;
    CryptoAlgorithm *algo = (algo_id == CRYPTO_ALGO_AES128) ? &aes128_ctr_cipher : &xor_cipher;
    const char *section_name = (hy && hy->section_name) ? hy->section_name : STUB_SECTION_NAME_DEFAULT;

    printf("[*] Chargement de %s...\n", input_path);
    PEContext *pe = pe_load(input_path);
    if (!pe) return -1;

    if (pe_validate(pe) != 0) {
        pe_free(pe);
        return -1;
    }
    printf("[+] PE valide : %u sections, entry=0x%08X, imagebase=0x%016llX\n", pe->num_sections, pe->nt_hdrs->OptionalHeader.AddressOfEntryPoint, (unsigned long long)pe->nt_hdrs->OptionalHeader.ImageBase);

    uint32_t original_oep = pe->nt_hdrs->OptionalHeader.AddressOfEntryPoint;
    uint64_t original_imgbase = pe->nt_hdrs->OptionalHeader.ImageBase;

    uint32_t import_rva = pe->nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    uint32_t import_size = pe->nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

    uint32_t tls_rva = pe->nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    uint32_t tls_size = pe->nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;

    printf("[+] OEP original : 0x%08X\n", original_oep);
    printf("[+] Import Dir   : RVA=0x%08X, size=%u\n", import_rva, import_size);
    printf("[+] TLS Dir      : RVA=0x%08X, size=%u%s\n", tls_rva, tls_size,
           tls_rva ? "" : " (aucun TLS callback)");


    IMAGE_DATA_DIRECTORY *dirs = pe->nt_hdrs->OptionalHeader.DataDirectory;
    dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = 0;
    dirs[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size = 0;

    pe->nt_hdrs->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    pe->nt_hdrs->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
    pe->nt_hdrs->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_GUARD_CF;

    ctx = crypto_create(algo, key, key_size);
    if (!ctx) {
        fprintf(stderr, "[packer] Initialisation du contexte crypto échouée.\n");
        goto cleanup;
    }

    struct { uint32_t va; uint32_t raw_size; } encrypted_sections[STUB_MAX_SECTIONS];
    int num_encrypted = 0;

    for (int i = 0; i < pe->num_sections; i++) {
        IMAGE_SECTION_HEADER *sect = pe_get_section_by_index(pe, i);
        if (!should_encrypt_section(sect)) {
            printf("[ ] Skip section [%.*s]\n", 8, sect->Name);
            continue;
        }

        uint8_t *sect_data = pe->data + sect->PointerToRawData;
        size_t sect_size = sect->SizeOfRawData;

        printf("[*] Chiffrement de [%.*s] : offset=0x%X, size=%u, rva=0x%08X\n",
               8, sect->Name, sect->PointerToRawData, (unsigned)sect_size, sect->VirtualAddress);

        crypto_encrypt_section(algo, ctx, sect_data, sect_size, sect->VirtualAddress);

        sect->Characteristics |= IMAGE_SCN_MEM_WRITE;

        if (num_encrypted < STUB_MAX_SECTIONS) {
            encrypted_sections[num_encrypted].va = sect->VirtualAddress;
            encrypted_sections[num_encrypted].raw_size = (uint32_t)sect_size;
            num_encrypted++;
        }
    }

    uint8_t nonce_buf[8] = {0};
    (void)crypto_get_nonce(algo, ctx, nonce_buf, sizeof(nonce_buf));

    printf("[+] %d section(s) chiffrée(s) avec %s\n", num_encrypted, algo->name);

    size_t stub_size;
    uint8_t *stub_blob = load_stub_blob(stub_path, &stub_size);
    if (!stub_blob) goto cleanup;

    uint64_t magic;
    memcpy(&magic, stub_blob + CFG_OFF_MAGIC, 8);
    if (magic != CONFIG_MAGIC_VALUE) {
        fprintf(stderr, "[packer] Le stub.bin ne contient pas le magic attendu "
                        "(0x%016llX != 0x%016llX).\n",
                        (unsigned long long)magic,
                		(unsigned long long)CONFIG_MAGIC_VALUE);
        free(stub_blob);
        goto cleanup;
    }
    printf("[+] stub.bin chargé (%zu octets), magic OK.\n", stub_size);

    stub_blob[CFG_OFF_NUM_SECTIONS] = (uint8_t)num_encrypted;
    stub_blob[CFG_OFF_ALGO] = algo_id;
    if (algo_id == CRYPTO_ALGO_XOR) {
        stub_blob[CFG_OFF_XOR_KEY] = key[0];
    } else {
        memcpy(stub_blob + CFG_OFF_AES_KEY,   key,       16);
        memcpy(stub_blob + CFG_OFF_AES_NONCE, nonce_buf, 8);
        printf("[+] AES key  : ");
        for (int i = 0; i < 16; i++) printf("%02X", key[i]);
        printf("\n[+] AES nonce: ");
        for (int i = 0; i < 8;  i++) printf("%02X", nonce_buf[i]);
        printf("\n");
    }

    algo->destroy(ctx);
    ctx = NULL;

    write_u32_le(stub_blob, CFG_OFF_ORIGINAL_OEP, original_oep);

    write_u64_le(stub_blob, CFG_OFF_IMAGE_BASE, original_imgbase);

    write_u32_le(stub_blob, CFG_OFF_IMPORT_RVA,  import_rva);
    write_u32_le(stub_blob, CFG_OFF_IMPORT_SIZE, import_size);

    write_u32_le(stub_blob, CFG_OFF_TLS_RVA,  tls_rva);
    write_u32_le(stub_blob, CFG_OFF_TLS_SIZE, tls_size);

    uint32_t h_getproc  = djb2("GetProcAddress");
    uint32_t h_loadlib  = djb2("LoadLibraryA");
    uint32_t h_vralloc  = djb2("VirtualAlloc");
    write_u32_le(stub_blob, CFG_OFF_HASH_GETPROCADDR,  h_getproc);
    write_u32_le(stub_blob, CFG_OFF_HASH_LOADLIB,      h_loadlib);
    write_u32_le(stub_blob, CFG_OFF_HASH_VIRTUALALLOC, h_vralloc);
    printf("[+] API hashes (DJB2): GetProcAddress=0x%08X, LoadLibraryA=0x%08X, VirtualAlloc=0x%08X\n",
           h_getproc, h_loadlib, h_vralloc);

    for (int i = 0; i < num_encrypted; i++) {
        size_t entry_offset = CFG_OFF_SECTIONS + (size_t)(i * 8);
        write_u32_le(stub_blob, entry_offset, encrypted_sections[i].va);
        write_u32_le(stub_blob, entry_offset + 4, encrypted_sections[i].raw_size);
    }

    printf("[+] Bloc de configuration rempli (%d sections référencées).\n", num_encrypted);

    printf("[*] Ajout de la section [%s]...\n", section_name);
    if (pe_add_section(pe, section_name, stub_blob, stub_size, STUB_SECTION_FLAGS) != 0) {
        fprintf(stderr, "[packer] Échec de l'ajout de la section.\n");
        free(stub_blob);
        goto cleanup;
    }
    free(stub_blob);
    stub_blob = NULL;

    /* pe_get_section_by_name returns the FIRST match — our section is at the
       end of the table, so look it up by index to avoid aliasing with an
       existing section that has the same name. */
    IMAGE_SECTION_HEADER *stub_sect = pe_get_section_by_index(pe, pe->num_sections - 1);
    if (!stub_sect) {
        fprintf(stderr, "[packer] Section introuvable après l'ajout — bug interne.\n");
        goto cleanup;
    }
    printf("[+] Section [%.*s] : VA=0x%08X, offset=0x%X, size=%u\n",
           8, stub_sect->Name, stub_sect->VirtualAddress, stub_sect->PointerToRawData, stub_sect->SizeOfRawData);

    uint32_t new_ep = stub_sect->VirtualAddress + STUB_CODE_OFFSET;
    pe->nt_hdrs->OptionalHeader.AddressOfEntryPoint = new_ep;
    printf("[+] AddressOfEntryPoint redirigé : 0x%08X → 0x%08X\n",
           original_oep, new_ep);

    /* --- PE hygiene pass --- */
    if (hy) {
        uint32_t orig_ts = pe->nt_hdrs->FileHeader.TimeDateStamp;
        uint32_t new_ts = orig_ts;
        switch (hy->ts_mode) {
            case TS_MODE_ZERO:   new_ts = 0; break;
            case TS_MODE_RANDOM: {
                unsigned int r = 0;
                rand_s(&r);
                /* Anchor around Jan 2016 (1451606400) + up to ~10 years span. */
                new_ts = 1451606400u + (r % (10u * 365u * 86400u));
                break;
            }
            case TS_MODE_PRESERVE:
            default: break;
        }
        if (new_ts != orig_ts) {
            pe->nt_hdrs->FileHeader.TimeDateStamp = new_ts;
            printf("[+] TimeDateStamp : 0x%08X -> 0x%08X\n", orig_ts, new_ts);
        }

        if (hy->fix_checksum) {
            pe->nt_hdrs->OptionalHeader.CheckSum = 0;
            uint32_t new_sum = pe_compute_checksum(pe);
            pe->nt_hdrs->OptionalHeader.CheckSum = new_sum;
            printf("[+] CheckSum recalculé : 0x%08X\n", new_sum);
        }
    }

    printf("[*] Écriture de %s...\n", output_path);
    if (pe_save(pe, output_path) != 0) {
        goto cleanup;
    }

    printf("[✓] PE packagé avec succès : %s (taille=%zu octets)\n",
           output_path, pe->size);
    ret = 0;

cleanup:
    if (ctx) algo->destroy(ctx);
    pe_free(pe);
    return ret;
}

static int generate_aes_key(uint8_t key[16]) {
    unsigned int r;
    for (int i = 0; i < 16; i += 4) {
        if (rand_s(&r) != 0) return -1;
        memcpy(key + i, &r, 4);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    printf("PE Packer Pédagogique x64\n\n");

    const char *input_path  = NULL;
    const char *output_path = NULL;
    const char *stub_path   = "stub.bin";
    uint8_t algo_id = CRYPTO_ALGO_AES128;
    uint8_t xor_key = 0xAB;
    HygieneOptions hy = { .section_name = NULL, .ts_mode = TS_MODE_PRESERVE, .fix_checksum = 1 };
    int positional = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--algo") == 0 && i + 1 < argc) {
            const char *v = argv[++i];
            if (strcmp(v, "xor") == 0)       algo_id = CRYPTO_ALGO_XOR;
            else if (strcmp(v, "aes") == 0)  algo_id = CRYPTO_ALGO_AES128;
            else { fprintf(stderr, "[packer] --algo doit être xor|aes.\n"); return 1; }
        } else if (strcmp(argv[i], "--stub") == 0 && i + 1 < argc) {
            stub_path = argv[++i];
        } else if (strcmp(argv[i], "--xor-key") == 0 && i + 1 < argc) {
            long v = strtol(argv[++i], NULL, 16);
            if (v < 0 || v > 255) { fprintf(stderr, "[packer] --xor-key doit être 0x00–0xFF.\n"); return 1; }
            xor_key = (uint8_t)v;
        } else if (strcmp(argv[i], "--section-name") == 0 && i + 1 < argc) {
            hy.section_name = argv[++i];
            if (strlen(hy.section_name) == 0 || strlen(hy.section_name) > 8) {
                fprintf(stderr, "[packer] --section-name doit faire 1 à 8 caractères.\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--timestamp") == 0 && i + 1 < argc) {
            const char *v = argv[++i];
            if      (strcmp(v, "preserve") == 0) hy.ts_mode = TS_MODE_PRESERVE;
            else if (strcmp(v, "zero")     == 0) hy.ts_mode = TS_MODE_ZERO;
            else if (strcmp(v, "random")   == 0) hy.ts_mode = TS_MODE_RANDOM;
            else { fprintf(stderr, "[packer] --timestamp doit être preserve|zero|random.\n"); return 1; }
        } else if (strcmp(argv[i], "--no-checksum") == 0) {
            hy.fix_checksum = 0;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "[packer] Option inconnue : %s\n", argv[i]);
            return 1;
        } else {
            if (positional == 0)      input_path = argv[i];
            else if (positional == 1) output_path = argv[i];
            positional++;
        }
    }

    if (!input_path || !output_path) {
        fprintf(stderr,
            "Usage : %s <target.exe> <output.exe> [options]\n"
            "  --algo xor|aes       : chiffrement (défaut: aes, AES-128-CTR via AES-NI)\n"
            "  --xor-key HH         : clé XOR en hex (défaut: 0xAB), ignoré si --algo aes\n"
            "  --stub path          : chemin vers stub.bin (défaut: stub.bin)\n"
            "  --section-name NAME  : nom de la section stub, 1..8 chars (défaut: .text)\n"
            "  --timestamp MODE     : preserve|zero|random (défaut: preserve)\n"
            "  --no-checksum        : ne pas recalculer OptionalHeader.CheckSum\n"
            "\nExemple : %s calc.exe calc_packed.exe --algo aes --timestamp random\n",
            argv[0], argv[0]);
        return 1;
    }

    uint8_t key_buf[16];
    size_t  key_size;
    if (algo_id == CRYPTO_ALGO_AES128) {
        if (generate_aes_key(key_buf) != 0) {
            fprintf(stderr, "[packer] Génération de la clé AES échouée.\n");
            return 1;
        }
        key_size = 16;
    } else {
        key_buf[0] = xor_key;
        key_size = 1;
    }

    const char *ts_label = (hy.ts_mode == TS_MODE_ZERO)   ? "zero"
                         : (hy.ts_mode == TS_MODE_RANDOM) ? "random"
                                                          : "preserve";
    printf("[*] Cible      : %s\n", input_path);
    printf("[*] Sortie     : %s\n", output_path);
    printf("[*] Stub       : %s\n", stub_path);
    printf("[*] Algo       : %s\n", (algo_id == CRYPTO_ALGO_AES128) ? "AES-128-CTR (AES-NI)" : "XOR 1-octet");
    printf("[*] Section    : %s\n", hy.section_name ? hy.section_name : STUB_SECTION_NAME_DEFAULT);
    printf("[*] Timestamp  : %s\n", ts_label);
    printf("[*] Checksum   : %s\n\n", hy.fix_checksum ? "recalculé" : "inchangé");

    return pack_pe(input_path, output_path, stub_path, algo_id, key_buf, key_size, &hy);
}
