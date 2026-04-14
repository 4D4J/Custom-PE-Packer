
#include "pe_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t align_up(uint32_t value, uint32_t alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~(alignment - 1);
}

PEContext *pe_load(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("[pe_load] fopen");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);

    if (file_size <= 0) {
        fprintf(stderr, "[pe_load] Fichier vide ou erreur.\n");
        fclose(f);
        return NULL;
    }

    PEContext *pe = calloc(1, sizeof(PEContext));
    if (!pe) { fclose(f); return NULL; }

    pe->size = (size_t)file_size;
    pe->data = malloc(pe->size);
    if (!pe->data) {
        free(pe);
        fclose(f);
        return NULL;
    }

    if (fread(pe->data, 1, pe->size, f) != pe->size) {
        fprintf(stderr, "[pe_load] Lecture incomplète du fichier.\n");
        pe_free(pe);
        fclose(f);
        return NULL;
    }
    fclose(f);
    pe->dos_hdr = (IMAGE_DOS_HEADER *)pe->data;

    uint32_t nt_offset = pe->dos_hdr->e_lfanew;
    pe->nt_hdrs  = (IMAGE_NT_HEADERS64 *)(pe->data + nt_offset);

    pe->sections = (IMAGE_SECTION_HEADER *)(
        (uint8_t *)pe->nt_hdrs
        + offsetof(IMAGE_NT_HEADERS64, OptionalHeader)
        + pe->nt_hdrs->FileHeader.SizeOfOptionalHeader
    );
    pe->num_sections = pe->nt_hdrs->FileHeader.NumberOfSections;

    return pe;
}

int pe_validate(PEContext *pe) {
    if (!pe || !pe->data || pe->size < sizeof(IMAGE_DOS_HEADER)) {
        fprintf(stderr, "[pe_validate] Buffer PE invalide.\n");
        return -1;
    }

    if (pe->dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "[pe_validate] Signature MZ manquante (0x%04X).\n",
                pe->dos_hdr->e_magic);
        return -1;
    }

    uint32_t nt_offset = pe->dos_hdr->e_lfanew;
    if (nt_offset + sizeof(IMAGE_NT_HEADERS64) > pe->size) {
        fprintf(stderr, "[pe_validate] e_lfanew (0x%X) pointe hors du buffer.\n",
                nt_offset);
        return -1;
    }

    if (pe->nt_hdrs->Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "[pe_validate] Signature PE manquante (0x%08X).\n",
                pe->nt_hdrs->Signature);
        return -1;
    }

    if (pe->nt_hdrs->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        fprintf(stderr, "[pe_validate] Machine non-AMD64 (0x%04X). "
                "Ce packer supporte uniquement les PE x64.\n",
                pe->nt_hdrs->FileHeader.Machine);
        return -1;
    }

    if (pe->nt_hdrs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        fprintf(stderr, "[pe_validate] Magic PE32+ attendu (0x020B), reçu 0x%04X.\n",
                pe->nt_hdrs->OptionalHeader.Magic);
        return -1;
    }
    return 0;
}

int pe_save(PEContext *pe, const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        perror("[pe_save] fopen");
        return -1;
    }
    size_t written = fwrite(pe->data, 1, pe->size, f);
    fclose(f);

    if (written != pe->size) {
        fprintf(stderr, "[pe_save] Écriture incomplète (%zu/%zu octets).\n",
                written, pe->size);
        return -1;
    }
    return 0;
}

void pe_free(PEContext *pe) {
    if (!pe) return;
    free(pe->data);
    free(pe);
}

IMAGE_SECTION_HEADER *pe_get_section_by_index(PEContext *pe, int index) {
    if (!pe || index < 0 || index >= pe->num_sections) return NULL;
    return &pe->sections[index];
}

IMAGE_SECTION_HEADER *pe_get_section_by_name(PEContext *pe, const char *name) {
    if (!pe || !name) return NULL;
    for (int i = 0; i < pe->num_sections; i++) {
        /* Les noms de sections sont sur 8 octets, pas forcément null-terminés */
        if (strncmp((char *)pe->sections[i].Name, name, 8) == 0) {
            return &pe->sections[i];
        }
    }
    return NULL;
}

size_t pe_rva_to_offset(PEContext *pe, uint32_t rva) {
    for (int i = 0; i < pe->num_sections; i++) {
        IMAGE_SECTION_HEADER *s = &pe->sections[i];
        uint32_t section_va_end = s->VirtualAddress + s->SizeOfRawData;

        if (rva >= s->VirtualAddress && rva < section_va_end) {
            return (size_t)s->PointerToRawData + (rva - s->VirtualAddress);
        }
    }
    return (size_t)-1;
}

int pe_add_section(PEContext *pe, const char *name,
                   const uint8_t *data, size_t data_size, uint32_t flags) {
    if (!pe || !name || !data || data_size == 0) return -1;

    IMAGE_OPTIONAL_HEADER64 *opt = &pe->nt_hdrs->OptionalHeader;
    uint32_t file_align = opt->FileAlignment;
    uint32_t sect_align = opt->SectionAlignment;

    if (pe->num_sections == 0) {
        fprintf(stderr, "[pe_add_section] PE sans sections — cas non géré.\n");
        return -1;
    }

    IMAGE_SECTION_HEADER *last = &pe->sections[pe->num_sections - 1];

    uint32_t new_rva = align_up(last->VirtualAddress + last->VirtualSize, sect_align);

    uint32_t last_end_offset = last->PointerToRawData + last->SizeOfRawData;
    uint32_t new_file_offset = align_up(last_end_offset, file_align);

    uint32_t raw_size = align_up((uint32_t)data_size, file_align);

    size_t new_file_size = (size_t)new_file_offset + raw_size;
    uint8_t *new_data = realloc(pe->data, new_file_size);
    if (!new_data) {
        fprintf(stderr, "[pe_add_section] realloc échoué (%zu octets).\n",
                new_file_size);
        return -1;
    }

    memset(new_data + pe->size, 0, new_file_size - pe->size);
    pe->data = new_data;
    pe->size = new_file_size;

    pe->dos_hdr  = (IMAGE_DOS_HEADER *)pe->data;
    pe->nt_hdrs  = (IMAGE_NT_HEADERS64 *)(pe->data + pe->dos_hdr->e_lfanew);
    opt = &pe->nt_hdrs->OptionalHeader;
    pe->sections = (IMAGE_SECTION_HEADER *)(
        (uint8_t *)pe->nt_hdrs
        + offsetof(IMAGE_NT_HEADERS64, OptionalHeader)
        + pe->nt_hdrs->FileHeader.SizeOfOptionalHeader
    );

    last = &pe->sections[pe->num_sections - 1];

    IMAGE_SECTION_HEADER *new_sect = &pe->sections[pe->num_sections];
    memset(new_sect, 0, sizeof(IMAGE_SECTION_HEADER));

    strncpy((char *)new_sect->Name, name, 8);
    new_sect->VirtualSize = (uint32_t)data_size;
    new_sect->VirtualAddress = new_rva;
    new_sect->SizeOfRawData = raw_size;
    new_sect->PointerToRawData = new_file_offset;
    new_sect->Characteristics = flags;

    memcpy(pe->data + new_file_offset, data, data_size);

    pe->nt_hdrs->FileHeader.NumberOfSections++;
    pe->num_sections++;

    opt->SizeOfImage = align_up(new_rva + (uint32_t)data_size, sect_align);

    return 0;
}
