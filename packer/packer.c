#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "pe_utils.h"
#include "crypto.h"

#define STUB_CODE_OFFSET 0xB0U
#define STUB_MAX_SECTIONS 16
#define STUB_SECTION_NAME ".stub"
#define STUB_SECTION_FLAGS (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)

#define CFG_OFF_MAGIC 0x00
#define CFG_OFF_NUM_SECTIONS 0x08
#define CFG_OFF_XOR_KEY 0x09
#define CFG_OFF_ORIGINAL_OEP 0x0C
#define CFG_OFF_IMAGE_BASE 0x10
#define CFG_OFF_IMPORT_RVA 0x18
#define CFG_OFF_IMPORT_SIZE 0x1C
#define CFG_OFF_RELOC_RVA 0x20
#define CFG_OFF_RELOC_SIZE 0x24
#define CFG_OFF_SECTIONS 0x30
#define CONFIG_MAGIC_VALUE 0xDEADBEEF

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

    fread(buf, 1, (size_t)sz, f);
    fclose(f);

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


static int should_encrypt_section(IMAGE_SECTION_HEADER *sect) {
    if (sect->SizeOfRawData == 0) return 0;

    if (strncmp((char *)sect->Name, STUB_SECTION_NAME, 8) == 0) return 0;

    return 1;
}


static int pack_pe(const char *input_path, const char *output_path, const char *stub_path, uint8_t xor_key) {
    int ret = -1;

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

    uint32_t reloc_rva = pe->nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    uint32_t reloc_size = pe->nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    printf("[+] OEP original : 0x%08X\n", original_oep);
    printf("[+] Import Dir : RVA=0x%08X, size=%u\n", import_rva, import_size);
    printf("[+] Reloc Dir : RVA=0x%08X, size=%u\n", reloc_rva, reloc_size);

    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        pe->nt_hdrs->OptionalHeader.DataDirectory[i].VirtualAddress = 0;
        pe->nt_hdrs->OptionalHeader.DataDirectory[i].Size = 0;
    }

    pe->nt_hdrs->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    pe->nt_hdrs->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;

    CryptoAlgorithm *algo = &xor_cipher;
    CryptoContext *ctx = crypto_create(algo, &xor_key, 1);
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

        printf("[*] Chiffrement de [%.*s] : offset=0x%X, size=%u\n", 8, sect->Name, sect->PointerToRawData, (unsigned)sect_size);

        crypto_encrypt_section(algo, ctx, sect_data, sect_size);

        sect->Characteristics |= IMAGE_SCN_MEM_WRITE;

        if (num_encrypted < STUB_MAX_SECTIONS) {
            encrypted_sections[num_encrypted].va = sect->VirtualAddress;
            encrypted_sections[num_encrypted].raw_size = (uint32_t)sect_size;
            num_encrypted++;
        }
    }

    algo->destroy(ctx);
    ctx = NULL;

    printf("[+] %d section(s) chiffrée(s) avec %s (clé=0x%02X)\n", num_encrypted, algo->name, xor_key);

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
    stub_blob[CFG_OFF_XOR_KEY] = xor_key;

    write_u32_le(stub_blob, CFG_OFF_ORIGINAL_OEP, original_oep);

    write_u64_le(stub_blob, CFG_OFF_IMAGE_BASE, original_imgbase);

    write_u32_le(stub_blob, CFG_OFF_IMPORT_RVA,  import_rva);
    write_u32_le(stub_blob, CFG_OFF_IMPORT_SIZE, import_size);

    write_u32_le(stub_blob, CFG_OFF_RELOC_RVA,  reloc_rva);
    write_u32_le(stub_blob, CFG_OFF_RELOC_SIZE, reloc_size);

    for (int i = 0; i < num_encrypted; i++) {
        size_t entry_offset = CFG_OFF_SECTIONS + (size_t)(i * 8);
        write_u32_le(stub_blob, entry_offset, encrypted_sections[i].va);
        write_u32_le(stub_blob, entry_offset + 4, encrypted_sections[i].raw_size);
    }

    printf("[+] Bloc de configuration rempli (%d sections référencées).\n", num_encrypted);

    printf("[*] Ajout de la section .stub...\n");
    if (pe_add_section(pe, STUB_SECTION_NAME, stub_blob, stub_size, STUB_SECTION_FLAGS) != 0) {
        fprintf(stderr, "[packer] Échec de l'ajout de la section .stub.\n");
        free(stub_blob);
        goto cleanup;
    }
    free(stub_blob);
    stub_blob = NULL;

    IMAGE_SECTION_HEADER *stub_sect = pe_get_section_by_name(pe, STUB_SECTION_NAME);
    if (!stub_sect) {
        fprintf(stderr, "[packer] Section .stub introuvable après l'ajout — bug interne.\n");
        goto cleanup;
    }
    printf("[+] Section .stub : VA=0x%08X, offset=0x%X, size=%u\n", stub_sect->VirtualAddress, stub_sect->PointerToRawData, stub_sect->SizeOfRawData);

    uint32_t new_ep = stub_sect->VirtualAddress + STUB_CODE_OFFSET;
    pe->nt_hdrs->OptionalHeader.AddressOfEntryPoint = new_ep;
    printf("[+] AddressOfEntryPoint redirigé : 0x%08X → 0x%08X\n",
           original_oep, new_ep);
		   
    printf("[*] Écriture de %s...\n", output_path);
    if (pe_save(pe, output_path) != 0) {
        goto cleanup;
    }

    printf("[✓] PE packagé avec succès : %s (taille=%zu octets)\n",
           output_path, pe->size);
    ret = 0;

cleanup:
    pe_free(pe);
    return ret;
}

int main(int argc, char *argv[]) {
    printf("PE Packer Pédagogique x64\n\n");

    if (argc < 3) {
        fprintf(stderr, "Usage : %s <target.exe> <output.exe> [xor_key_hex] [stub.bin_path]\n"
                        " xor_key_hex : clé XOR en hexadécimal (défaut: 0xAB)\n"
                        " stub.bin : chemin vers le bytecode du stub (défaut: stub.bin)\n"
                        "\nExemple : %s calc.exe calc_packed.exe 0x42\n",
                argv[0], argv[0]);
        return 1;
    }

    const char *input_path  = argv[1];
    const char *output_path = argv[2];
    const char *stub_path   = (argc >= 5) ? argv[4] : "stub.bin";

    uint8_t xor_key = 0xAB; 
    if (argc >= 4) {
        long key_val = strtol(argv[3], NULL, 16);
        if (key_val < 0 || key_val > 255) {
            fprintf(stderr, "[packer] Clé XOR invalide (doit être 0x00–0xFF).\n");
            return 1;
        }
        xor_key = (uint8_t)key_val;
    }

    printf("[*] Cible : %s\n", input_path);
    printf("[*] Sortie : %s\n", output_path);
    printf("[*] Stub : %s\n", stub_path);
    printf("[*] Clé XOR : 0x%02X\n\n", xor_key);

    return pack_pe(input_path, output_path, stub_path, xor_key);
}
