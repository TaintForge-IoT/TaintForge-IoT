ENTRY(_start)
PHDRS {
    headers PT_PHDR PHDRS FLAGS(4);
    ro PT_LOAD FILEHDR PHDRS FLAGS(4);
    text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}
SECTIONS {
    . = 0x08048000 + SIZEOF_HEADERS;
    .rodata : { *(.rodata*) } :ro
    . = ALIGN(4096);
    .text : { *(.text*) } :text
    . = ALIGN(4096);
    .data : { *(.data*) } :data
    .bss : { *(.bss*) } :data
    /DISCARD/ : { *(.note*) *(.comment*) }
}
