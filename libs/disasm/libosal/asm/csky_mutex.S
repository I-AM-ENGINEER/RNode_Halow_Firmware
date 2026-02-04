
disasm/libosal/obj/csky_mutex.o:     file format elf32-csky-little


Disassembly of section .text.os_mutex_init:

00000000 <os_mutex_init>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d03      	mov      	r4, r0
   4:	e900000c 	bez      	r0, 0x1c	// 1c <os_mutex_init+0x1c>
   8:	9060      	ld.w      	r3, (r0, 0x0)
   a:	10a8      	lrw      	r5, 0xa8b4c2d5	// 28 <os_mutex_init+0x28>
   c:	654e      	cmpne      	r3, r5
   e:	0c07      	bf      	0x1c	// 1c <os_mutex_init+0x1c>
  10:	e0000000 	bsr      	0x0	// 0 <csi_kernel_mutex_new>
  14:	b401      	st.w      	r0, (r4, 0x4)
  16:	e9000003 	bez      	r0, 0x1c	// 1c <os_mutex_init+0x1c>
  1a:	b4a0      	st.w      	r5, (r4, 0x0)
  1c:	9461      	ld.w      	r3, (r4, 0x4)
  1e:	3b40      	cmpnei      	r3, 0
  20:	64c3      	mvcv      	r3
  22:	3000      	movi      	r0, 0
  24:	600e      	subu      	r0, r3
  26:	1492      	pop      	r4-r5, r15
  28:	a8b4c2d5 	.long	0xa8b4c2d5

Disassembly of section .text.os_mutex_lock:

00000000 <os_mutex_lock>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d03      	mov      	r4, r0
   4:	6d47      	mov      	r5, r1
   6:	e9000005 	bez      	r0, 0x10	// 10 <os_mutex_lock+0x10>
   a:	9061      	ld.w      	r3, (r0, 0x4)
   c:	e9230007 	bnez      	r3, 0x1a	// 1a <os_mutex_lock+0x1a>
  10:	1047      	lrw      	r2, 0x0	// 2c <os_mutex_lock+0x2c>
  12:	3114      	movi      	r1, 20
  14:	1007      	lrw      	r0, 0x0	// 30 <os_mutex_lock+0x30>
  16:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  1a:	6c17      	mov      	r0, r5
  1c:	9481      	ld.w      	r4, (r4, 0x4)
  1e:	e0000000 	bsr      	0x0	// 0 <csi_kernel_ms2tick>
  22:	6c43      	mov      	r1, r0
  24:	6c13      	mov      	r0, r4
  26:	e0000000 	bsr      	0x0	// 0 <csi_kernel_mutex_lock>
  2a:	1492      	pop      	r4-r5, r15
	...

Disassembly of section .text.os_mutex_unlock:

00000000 <os_mutex_unlock>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	e9000005 	bez      	r0, 0xe	// e <os_mutex_unlock+0xe>
   8:	9061      	ld.w      	r3, (r0, 0x4)
   a:	e9230007 	bnez      	r3, 0x18	// 18 <os_mutex_unlock+0x18>
   e:	1045      	lrw      	r2, 0x0	// 20 <os_mutex_unlock+0x20>
  10:	311a      	movi      	r1, 26
  12:	1005      	lrw      	r0, 0x0	// 24 <os_mutex_unlock+0x24>
  14:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  18:	9401      	ld.w      	r0, (r4, 0x4)
  1a:	e0000000 	bsr      	0x0	// 0 <csi_kernel_mutex_unlock>
  1e:	1491      	pop      	r4, r15
	...

Disassembly of section .text.os_mutex_del:

00000000 <os_mutex_del>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	e9000005 	bez      	r0, 0xe	// e <os_mutex_del+0xe>
   8:	9061      	ld.w      	r3, (r0, 0x4)
   a:	e9230007 	bnez      	r3, 0x18	// 18 <os_mutex_del+0x18>
   e:	1047      	lrw      	r2, 0x0	// 28 <os_mutex_del+0x28>
  10:	3121      	movi      	r1, 33
  12:	1007      	lrw      	r0, 0x0	// 2c <os_mutex_del+0x2c>
  14:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  18:	9401      	ld.w      	r0, (r4, 0x4)
  1a:	e0000000 	bsr      	0x0	// 0 <csi_kernel_mutex_del>
  1e:	3300      	movi      	r3, 0
  20:	b461      	st.w      	r3, (r4, 0x4)
  22:	b460      	st.w      	r3, (r4, 0x0)
  24:	1491      	pop      	r4, r15
	...
