
disasm/libosal/obj/csky_msgqueue.o:     file format elf32-csky-little


Disassembly of section .text.os_msgq_init:

00000000 <os_msgq_init>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d03      	mov      	r4, r0
   4:	10a9      	lrw      	r5, 0x4a8b1c9d	// 28 <os_msgq_init+0x28>
   6:	9460      	ld.w      	r3, (r4, 0x0)
   8:	654e      	cmpne      	r3, r5
   a:	6c07      	mov      	r0, r1
   c:	0c08      	bf      	0x1c	// 1c <os_msgq_init+0x1c>
   e:	3104      	movi      	r1, 4
  10:	e0000000 	bsr      	0x0	// 0 <csi_kernel_msgq_new>
  14:	b401      	st.w      	r0, (r4, 0x4)
  16:	e9000003 	bez      	r0, 0x1c	// 1c <os_msgq_init+0x1c>
  1a:	b4a0      	st.w      	r5, (r4, 0x0)
  1c:	9461      	ld.w      	r3, (r4, 0x4)
  1e:	3b40      	cmpnei      	r3, 0
  20:	64c3      	mvcv      	r3
  22:	3000      	movi      	r0, 0
  24:	600e      	subu      	r0, r3
  26:	1492      	pop      	r4-r5, r15
  28:	4a8b1c9d 	.long	0x4a8b1c9d

Disassembly of section .text.os_msgq_get:

00000000 <os_msgq_get>:
   0:	14d1      	push      	r4, r15
   2:	1421      	subi      	r14, r14, 4
   4:	9081      	ld.w      	r4, (r0, 0x4)
   6:	3300      	movi      	r3, 0
   8:	6c07      	mov      	r0, r1
   a:	b860      	st.w      	r3, (r14, 0x0)
   c:	e0000000 	bsr      	0x0	// 0 <csi_kernel_ms2tick>
  10:	6c83      	mov      	r2, r0
  12:	6c7b      	mov      	r1, r14
  14:	6c13      	mov      	r0, r4
  16:	e0000000 	bsr      	0x0	// 0 <csi_kernel_msgq_get>
  1a:	9800      	ld.w      	r0, (r14, 0x0)
  1c:	1401      	addi      	r14, r14, 4
  1e:	1491      	pop      	r4, r15

Disassembly of section .text.os_msgq_put:

00000000 <os_msgq_put>:
   0:	14d1      	push      	r4, r15
   2:	1421      	subi      	r14, r14, 4
   4:	9081      	ld.w      	r4, (r0, 0x4)
   6:	6c0b      	mov      	r0, r2
   8:	b820      	st.w      	r1, (r14, 0x0)
   a:	e0000000 	bsr      	0x0	// 0 <csi_kernel_ms2tick>
   e:	6cc3      	mov      	r3, r0
  10:	3200      	movi      	r2, 0
  12:	6c7b      	mov      	r1, r14
  14:	6c13      	mov      	r0, r4
  16:	e0000000 	bsr      	0x0	// 0 <csi_kernel_msgq_put>
  1a:	1401      	addi      	r14, r14, 4
  1c:	1491      	pop      	r4, r15

Disassembly of section .text.os_msgq_del:

00000000 <os_msgq_del>:
   0:	14d1      	push      	r4, r15
   2:	9061      	ld.w      	r3, (r0, 0x4)
   4:	6d03      	mov      	r4, r0
   6:	e9230007 	bnez      	r3, 0x14	// 14 <os_msgq_del+0x14>
   a:	1047      	lrw      	r2, 0x0	// 24 <os_msgq_del+0x24>
   c:	3120      	movi      	r1, 32
   e:	1007      	lrw      	r0, 0x0	// 28 <os_msgq_del+0x28>
  10:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  14:	9401      	ld.w      	r0, (r4, 0x4)
  16:	e0000000 	bsr      	0x0	// 0 <csi_kernel_msgq_del>
  1a:	3000      	movi      	r0, 0
  1c:	b401      	st.w      	r0, (r4, 0x4)
  1e:	b400      	st.w      	r0, (r4, 0x0)
  20:	1491      	pop      	r4, r15
	...

Disassembly of section .text.os_msgq_cnt:

00000000 <os_msgq_cnt>:
   0:	14d0      	push      	r15
   2:	9001      	ld.w      	r0, (r0, 0x4)
   4:	e0000000 	bsr      	0x0	// 0 <csi_kernel_msgq_get_count>
   8:	1490      	pop      	r15
