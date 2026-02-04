
disasm/libosal/obj/csky_timer.o:     file format elf32-csky-little


Disassembly of section .text._os_timer_cb:

00000000 <_os_timer_cb>:
   0:	14d0      	push      	r15
   2:	9064      	ld.w      	r3, (r0, 0x10)
   4:	2300      	addi      	r3, 1
   6:	b064      	st.w      	r3, (r0, 0x10)
   8:	9062      	ld.w      	r3, (r0, 0x8)
   a:	9003      	ld.w      	r0, (r0, 0xc)
   c:	7bcd      	jsr      	r3
   e:	1490      	pop      	r15

Disassembly of section .text.os_timer_init:

00000000 <os_timer_init>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d03      	mov      	r4, r0
   4:	10ae      	lrw      	r5, 0x6a7b3c4d	// 3c <os_timer_init+0x3c>
   6:	6c0b      	mov      	r0, r2
   8:	9440      	ld.w      	r2, (r4, 0x0)
   a:	654a      	cmpne      	r2, r5
   c:	0c12      	bf      	0x30	// 30 <os_timer_init+0x30>
   e:	e9010011 	bez      	r1, 0x30	// 30 <os_timer_init+0x30>
  12:	b463      	st.w      	r3, (r4, 0xc)
  14:	3300      	movi      	r3, 0
  16:	b422      	st.w      	r1, (r4, 0x8)
  18:	b465      	st.w      	r3, (r4, 0x14)
  1a:	6c43      	mov      	r1, r0
  1c:	b466      	st.w      	r3, (r4, 0x18)
  1e:	b464      	st.w      	r3, (r4, 0x10)
  20:	6c93      	mov      	r2, r4
  22:	1008      	lrw      	r0, 0x0	// 40 <os_timer_init+0x40>
  24:	e0000000 	bsr      	0x0	// 0 <csi_kernel_timer_new>
  28:	b401      	st.w      	r0, (r4, 0x4)
  2a:	e9000003 	bez      	r0, 0x30	// 30 <os_timer_init+0x30>
  2e:	b4a0      	st.w      	r5, (r4, 0x0)
  30:	9461      	ld.w      	r3, (r4, 0x4)
  32:	3b40      	cmpnei      	r3, 0
  34:	64c3      	mvcv      	r3
  36:	3000      	movi      	r0, 0
  38:	600e      	subu      	r0, r3
  3a:	1492      	pop      	r4-r5, r15
  3c:	6a7b3c4d 	.long	0x6a7b3c4d
  40:	00000000 	.long	0x00000000

Disassembly of section .text.os_timer_start:

00000000 <os_timer_start>:
   0:	14d1      	push      	r4, r15
   2:	9081      	ld.w      	r4, (r0, 0x4)
   4:	e904000a 	bez      	r4, 0x18	// 18 <os_timer_start+0x18>
   8:	6c07      	mov      	r0, r1
   a:	e0000000 	bsr      	0x0	// 0 <csi_kernel_ms2tick>
   e:	6c43      	mov      	r1, r0
  10:	6c13      	mov      	r0, r4
  12:	e0000000 	bsr      	0x0	// 0 <csi_kernel_timer_start>
  16:	1491      	pop      	r4, r15
  18:	6c13      	mov      	r0, r4
  1a:	07fe      	br      	0x16	// 16 <os_timer_start+0x16>

Disassembly of section .text.os_timer_stop:

00000000 <os_timer_stop>:
   0:	14d0      	push      	r15
   2:	9001      	ld.w      	r0, (r0, 0x4)
   4:	e9000004 	bez      	r0, 0xc	// c <os_timer_stop+0xc>
   8:	e0000000 	bsr      	0x0	// 0 <csi_kernel_timer_stop>
   c:	3000      	movi      	r0, 0
   e:	1490      	pop      	r15

Disassembly of section .text.os_timer_del:

00000000 <os_timer_del>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	9001      	ld.w      	r0, (r0, 0x4)
   6:	e9000007 	bez      	r0, 0x14	// 14 <os_timer_del+0x14>
   a:	e0000000 	bsr      	0x0	// 0 <csi_kernel_timer_del>
   e:	3300      	movi      	r3, 0
  10:	b461      	st.w      	r3, (r4, 0x4)
  12:	b460      	st.w      	r3, (r4, 0x0)
  14:	3000      	movi      	r0, 0
  16:	1491      	pop      	r4, r15

Disassembly of section .text.os_timer_stat:

00000000 <os_timer_stat>:
   0:	14d0      	push      	r15
   2:	9001      	ld.w      	r0, (r0, 0x4)
   4:	e9000004 	bez      	r0, 0xc	// c <os_timer_stat+0xc>
   8:	e0000000 	bsr      	0x0	// 0 <csi_kernel_timer_get_stat>
   c:	1490      	pop      	r15
