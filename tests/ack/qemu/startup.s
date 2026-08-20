    .text
    .global _start
_start:
    lrw     r13, __stack_top
    mov     sp, r13
    jbsr    c_start
1:
    br      1b
