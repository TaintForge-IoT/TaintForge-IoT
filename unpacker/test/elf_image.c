#include "elf_image.h"

#include <elf.h>
#include <string.h>

static uint64_t number(const uint8_t *p, unsigned size, bool big_endian) {
    uint64_t value = 0;
    for (unsigned i = 0; i < size; i++)
        value = (value << 8) | p[big_endian ? i : size - 1 - i];
    return value;
}

static bool contains(uint64_t start, uint64_t length, uint64_t offset, uint64_t size) {
    return offset >= start && offset - start <= length && size <= length - (offset - start);
}

static bool overlaps_load_pages(const TfElfImage *image, uint64_t address, uint64_t size,
                                 uint64_t page_size) {
    const uint64_t mask = ~(page_size - 1);
    for (size_t i = 0; i < image->load_count; i++) {
        const TfElfLoad *other = &image->loads[i];
        if ((address & mask) <= ((other->address + other->memory_size - 1) & mask) &&
            (other->address & mask) <= ((address + size - 1) & mask))
            return true;
    }
    return false;
}

TfElfStatus tf_elf_image_resolve(TfElfRead file_read, void *file_context, uint64_t file_size,
                                 TfElfRead guest_read, void *guest_context, const TfElfAux *aux,
                                 uint64_t seed_budget, TfElfImage *out) {
    if (!file_read || !guest_read || !aux || !out ||
        (aux->pointer_bytes != 4 && aux->pointer_bytes != 8) || !aux->page_size ||
        (aux->page_size & (aux->page_size - 1)))
        return TF_ELF_INVALID;
    const bool wide = aux->pointer_bytes == 8, be = aux->big_endian;
    const unsigned header_size = wide ? 64 : 52, phent = wide ? 56 : 32;
    const uint64_t limit = wide ? UINT64_MAX : UINT64_C(1) << 32;
    uint8_t header[64], guest[64];
    if (file_size < header_size || !file_read(file_context, 0, header, header_size))
        return TF_ELF_READ_FAILED;
    if (memcmp(header, "\177ELF", 4) || header[4] != (wide ? 2 : 1) || header[5] != (be ? 2 : 1) ||
        header[6] != 1 || number(header + 20, 4, be) != 1 ||
        number(header + (wide ? 52 : 40), 2, be) != header_size)
        return TF_ELF_INVALID;
    const uint64_t type = number(header + 16, 2, be);
    const uint64_t entry = number(header + 24, aux->pointer_bytes, be);
    const uint64_t phoff = number(header + (wide ? 32 : 28), aux->pointer_bytes, be);
    const uint64_t count = number(header + (wide ? 56 : 44), 2, be);
    if ((type != 2 && type != 3) || !count || count > TF_ELF_MAX_LOADS ||
        number(header + (wide ? 54 : 42), 2, be) != phent || aux->phent != phent ||
        aux->phnum != count || phoff < header_size || !contains(0, file_size, phoff, count * phent))
        return TF_ELF_INVALID;
    if (aux->entry >= limit || aux->phdr >= limit || aux->entry < entry ||
        (type == 2 && aux->entry != entry))
        return TF_ELF_ADDRESS_MISMATCH;
    TfElfImage image = {.bias = aux->entry - entry, .entry = aux->entry, .lo = UINT64_MAX};
    const uint64_t table_size = count * phent;
    if (image.bias % aux->page_size || !contains(0, limit, aux->phdr, table_size))
        return TF_ELF_ADDRESS_MISMATCH;
    bool phdr_mapped = false, entry_mapped = false, explicit_phdr = false;
    for (uint64_t i = 0; i < count; i++) {
        uint8_t ph[56];
        if (!file_read(file_context, phoff + i * phent, ph, phent) ||
            !guest_read(guest_context, aux->phdr + i * phent, guest, phent))
            return TF_ELF_READ_FAILED;
        if (memcmp(ph, guest, phent))
            return TF_ELF_IDENTITY_MISMATCH;
        const uint64_t kind = number(ph, 4, be);
        if (kind != 1 && kind != 6)
            continue;
        const uint64_t offset = number(ph + (wide ? 8 : 4), aux->pointer_bytes, be);
        const uint64_t vaddr = number(ph + (wide ? 16 : 8), aux->pointer_bytes, be);
        const uint64_t filesz = number(ph + (wide ? 32 : 16), aux->pointer_bytes, be);
        const uint64_t memsz = number(ph + (wide ? 40 : 20), aux->pointer_bytes, be);
        const uint64_t align = number(ph + (wide ? 48 : 28), aux->pointer_bytes, be);
        const uint32_t flags = (uint32_t)number(ph + (wide ? 4 : 24), 4, be);
        if (filesz > memsz || !contains(0, file_size, offset, filesz) ||
            (align > 1 && ((align & (align - 1)) || vaddr % align != offset % align)))
            return TF_ELF_INVALID;
        if (vaddr >= limit || image.bias >= limit - vaddr || memsz > limit - vaddr - image.bias)
            return TF_ELF_ADDRESS_MISMATCH;
        const uint64_t address = vaddr + image.bias;
        if (kind == 6) {
            if (explicit_phdr || offset != phoff || filesz != table_size || memsz != table_size ||
                address != aux->phdr)
                return TF_ELF_ADDRESS_MISMATCH;
            explicit_phdr = true;
            continue;
        }
        if (vaddr % aux->page_size != offset % aux->page_size)
            return TF_ELF_INVALID;
        if (contains(offset, filesz, phoff, table_size) && address + (phoff - offset) == aux->phdr)
            phdr_mapped = true;
        if ((flags & 1) && contains(address, memsz, aux->entry, 1))
            entry_mapped = true;
        if (!memsz)
            continue;
        if (filesz > seed_budget - image.file_bytes)
            return TF_ELF_BUDGET;
        if (overlaps_load_pages(&image, address, memsz, aux->page_size))
            return TF_ELF_OVERLAPPING_LOADS;
        image.loads[image.load_count++] = (TfElfLoad){address, memsz, offset, filesz, flags};
        image.file_bytes += filesz;
        if (address < image.lo)
            image.lo = address;
        if (address + memsz > image.hi)
            image.hi = address + memsz;
    }
    if (!phdr_mapped || !entry_mapped || !image.load_count)
        return TF_ELF_ADDRESS_MISMATCH;
    /* Check a mapped copy of the file header as well. Replacing the path with
     * another ELF must not supply an unobserved e_type/e_entry to this resolver. */
    bool header_matched = false;
    for (size_t i = 0; i < image.load_count; i++) {
        const TfElfLoad *load = &image.loads[i];
        if (load->file_offset || load->file_size < header_size)
            continue;
        if (!guest_read(guest_context, load->address, guest, header_size))
            return TF_ELF_READ_FAILED;
        if (memcmp(header, guest, header_size))
            return TF_ELF_IDENTITY_MISMATCH;
        header_matched = true;
    }
    if (!header_matched)
        return TF_ELF_IDENTITY_MISMATCH;
    *out = image;
    return TF_ELF_OK;
}

bool tf_elf_i386_payload(const uint8_t *page, uint64_t base, uint64_t entry, TfElfImage *out) {
    const uint64_t page_size = TF_ELF_I386_PAGE_SIZE, limit = UINT64_C(1) << 32;
    const uint64_t ehsize = sizeof(Elf32_Ehdr), phsize = sizeof(Elf32_Phdr);
    if (base < 0x10000 || base >= limit || base % page_size ||
        memcmp(page, ELFMAG, SELFMAG) || page[EI_CLASS] != ELFCLASS32 ||
        page[EI_DATA] != ELFDATA2LSB || page[EI_VERSION] != EV_CURRENT ||
        number(page + 16, 2, false) != ET_EXEC || number(page + 18, 2, false) != EM_386 ||
        number(page + 20, 4, false) != EV_CURRENT || number(page + 24, 4, false) != entry ||
        number(page + 40, 2, false) != ehsize || number(page + 42, 2, false) != phsize)
        return false;

    const uint64_t phoff = number(page + 28, 4, false), count = number(page + 44, 2, false);
    if (!count || count > TF_ELF_MAX_LOADS || phoff < ehsize ||
        !contains(0, page_size, phoff, count * phsize))
        return false;

    TfElfImage image = {.entry = entry, .lo = UINT64_MAX};
    bool header_mapped = false, entry_mapped = false;
    for (uint64_t i = 0; i < count; i++) {
        const uint8_t *ph = page + phoff + i * phsize;
        const uint64_t kind = number(ph, 4, false);
        if (kind == PT_DYNAMIC || kind == PT_INTERP)
            return false;
        if (kind != PT_LOAD)
            continue;
        const uint64_t offset = number(ph + 4, 4, false), addr = number(ph + 8, 4, false);
        const uint64_t filesz = number(ph + 16, 4, false), memsz = number(ph + 20, 4, false);
        const uint32_t flags = (uint32_t)number(ph + 24, 4, false);
        const uint64_t align = number(ph + 28, 4, false);
        if (filesz > memsz || offset + filesz > limit || addr + memsz > limit ||
            flags & ~(PF_R | PF_W | PF_X) || addr % page_size != offset % page_size ||
            (align > 1 && ((align & (align - 1)) || addr % align != offset % align)))
            return false;
        if (!memsz)
            continue;
        if (addr < base || !(flags & PF_R) || overlaps_load_pages(&image, addr, memsz, page_size))
            return false;

        header_mapped |= addr == base && offset == 0 && phoff + count * phsize <= filesz;
        entry_mapped |= (flags & PF_X) && contains(addr, filesz, entry, 1);
        image.loads[image.load_count++] = (TfElfLoad){addr, memsz, offset, filesz, flags};
        image.file_bytes += filesz;
        if (addr < image.lo)
            image.lo = addr;
        if (addr + memsz > image.hi)
            image.hi = addr + memsz;
    }
    if (!header_mapped || !entry_mapped)
        return false;
    *out = image;
    return true;
}

const char *tf_elf_status_name(TfElfStatus status) {
    switch (status) {
    case TF_ELF_OK:
        return "ok";
    case TF_ELF_INVALID:
        return "invalid_elf_or_auxv";
    case TF_ELF_READ_FAILED:
        return "metadata_read_failed";
    case TF_ELF_IDENTITY_MISMATCH:
        return "file_guest_identity_mismatch";
    case TF_ELF_ADDRESS_MISMATCH:
        return "address_evidence_mismatch";
    case TF_ELF_OVERLAPPING_LOADS:
        return "overlapping_virtual_loads";
    case TF_ELF_BUDGET:
        return "initial_seed_budget";
    }
    return "invalid_status";
}
