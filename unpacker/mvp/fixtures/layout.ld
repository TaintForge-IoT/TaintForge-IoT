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
    .text : { KEEP(*(.text.start)) *(.text*) } :text
    . = ALIGN(4096);
    .data : { LONG(0x57434654); *(.data*) } :data
    .bss : { *(.bss*) *(COMMON) } :data
    /DISCARD/ : { *(.note*) *(.comment*) *(.eh_frame*) }
}
