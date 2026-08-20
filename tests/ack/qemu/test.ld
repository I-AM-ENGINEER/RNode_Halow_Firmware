MEMORY
{
    RAM : ORIGIN = 0x20000000, LENGTH = 0x1000000
}

ENTRY(_start)

SECTIONS
{
    .text : {
        *(.text.start)
        *(.text*)
        *(.rodata*)
        . = ALIGN(4);
    } > RAM

    .data : {
        *(.data*)
        . = ALIGN(4);
    } > RAM

    .bss (NOLOAD) : {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        __bss_end = .;
    } > RAM

    . = ALIGN(8);
    __stack_top = ORIGIN(RAM) + LENGTH(RAM);
}
