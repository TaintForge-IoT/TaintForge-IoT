#include <assert.h>
#include <elf.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "phase1_resources.h"
#include "provenance.h"

int main(int argc, char **argv) {
    assert(argc == 2);
    FILE *file = fopen(argv[1], "rb");
    assert(file);
    Elf32_Ehdr header;
    assert(fread(&header, sizeof(header), 1, file) == 1);
    assert(!memcmp(header.e_ident, ELFMAG, SELFMAG));
    assert(header.e_ident[EI_CLASS] == ELFCLASS32 && header.e_ident[EI_DATA] == ELFDATA2LSB);
    assert(header.e_type == ET_EXEC && header.e_machine == EM_386);
    assert(header.e_phentsize == sizeof(Elf32_Phdr));
    char *options[] = {"m4-memory-bytes=536870912"};
    assert(tf_resources_configure(1, options));
    ProvRegistry *registry = prov_registry_create(NULL);
    assert(registry);
    ProvResourceKey resource_key = {.kind = PROV_RESOURCE_FILE, .scope_id = 1, .object_id = 1};
    ProvResourceId resource = prov_resource_intern(registry, &resource_key, "budget-guest",
                                                  PROV_RESOURCE_ROLE_MAIN_IMAGE);
    assert(resource != PROV_RESOURCE_ID_INVALID);
    uint64_t file_bytes = 0, zero_fill_bytes = 0;
    for (unsigned i = 0; i < header.e_phnum; i++) {
        assert(fseek(file, header.e_phoff + i * sizeof(Elf32_Phdr), SEEK_SET) == 0);
        Elf32_Phdr load;
        assert(fread(&load, sizeof(load), 1, file) == 1);
        if (load.p_type != PT_LOAD) continue;
        assert(load.p_filesz <= load.p_memsz);
        file_bytes += load.p_filesz;
        zero_fill_bytes += load.p_memsz - load.p_filesz;
        for (uint64_t byte = 0; byte < load.p_filesz; byte++) {
            ProvRootKey key = {.kind = PROV_ROOT_RESOURCE_BYTE, .source_id = resource,
                               .offset = load.p_offset + byte};
            ProvRootId root = prov_root_intern(registry, &key);
            assert(root != PROV_ROOT_ID_INVALID);
            assert(prov_label_from_root(registry, root, PROV_CHANNEL_DATA) != PROV_LABEL_ID_INVALID);
        }
    }
    assert(fclose(file) == 0);
    printf("{\"file_bytes\":%" PRIu64 ",\"zero_fill_bytes\":%" PRIu64 ",\"before\":",
           file_bytes, zero_fill_bytes);
    tf_resources_json(stdout, true);
    prov_registry_destroy(registry);
    assert(tf_resources_remaining() == 0);
    fputs(",\"after\":", stdout);
    tf_resources_json(stdout, true);
    puts("}");
    return 0;
}
