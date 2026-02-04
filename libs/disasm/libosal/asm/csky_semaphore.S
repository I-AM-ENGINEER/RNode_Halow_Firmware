
disasm/libosal/obj/csky_semaphore.o:     file format elf32-csky-little


Disassembly of section .text.os_sema_init:

00000000 <os_sema_init>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d03      	mov      	r4, r0
   4:	6d87      	mov      	r6, r1
   6:	e9200007 	bnez      	r0, 0x14	// 14 <os_sema_init+0x14>
   a:	104d      	lrw      	r2, 0x0	// 3c <os_sema_init+0x3c>
   c:	310c      	movi      	r1, 12
   e:	100d      	lrw      	r0, 0x0	// 40 <os_sema_init+0x40>
  10:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  14:	9460      	ld.w      	r3, (r4, 0x0)
  16:	10ac      	lrw      	r5, 0x3a8d7c1d	// 44 <os_sema_init+0x44>
  18:	654e      	cmpne      	r3, r5
  1a:	0c0a      	bf      	0x2e	// 2e <os_sema_init+0x2e>
  1c:	6c5b      	mov      	r1, r6
  1e:	ea00ffff 	movi      	r0, 65535
  22:	e0000000 	bsr      	0x0	// 0 <csi_kernel_sem_new>
  26:	b401      	st.w      	r0, (r4, 0x4)
  28:	e9000003 	bez      	r0, 0x2e	// 2e <os_sema_init+0x2e>
  2c:	b4a0      	st.w      	r5, (r4, 0x0)
  2e:	9461      	ld.w      	r3, (r4, 0x4)
  30:	3b40      	cmpnei      	r3, 0
  32:	64c3      	mvcv      	r3
  34:	3000      	movi      	r0, 0
  36:	600e      	subu      	r0, r3
  38:	1493      	pop      	r4-r6, r15
	...
  42:	0000      	.short	0x0000
  44:	3a8d7c1d 	.long	0x3a8d7c1d

Disassembly of section .text.os_sema_down:

00000000 <os_sema_down>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d03      	mov      	r4, r0
   4:	6d47      	mov      	r5, r1
   6:	e9000005 	bez      	r0, 0x10	// 10 <os_sema_down+0x10>
   a:	9061      	ld.w      	r3, (r0, 0x4)
   c:	e9230007 	bnez      	r3, 0x1a	// 1a <os_sema_down+0x1a>
  10:	1048      	lrw      	r2, 0x0	// 30 <os_sema_down+0x30>
  12:	3117      	movi      	r1, 23
  14:	1008      	lrw      	r0, 0x0	// 34 <os_sema_down+0x34>
  16:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  1a:	6c17      	mov      	r0, r5
  1c:	9481      	ld.w      	r4, (r4, 0x4)
  1e:	e0000000 	bsr      	0x0	// 0 <csi_kernel_ms2tick>
  22:	6c43      	mov      	r1, r0
  24:	6c13      	mov      	r0, r4
  26:	e0000000 	bsr      	0x0	// 0 <csi_kernel_sem_wait>
  2a:	3840      	cmpnei      	r0, 0
  2c:	6403      	mvcv      	r0
  2e:	1492      	pop      	r4-r5, r15
	...

Disassembly of section .text.os_sema_up:

00000000 <os_sema_up>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	e9000005 	bez      	r0, 0xe	// e <os_sema_up+0xe>
   8:	9061      	ld.w      	r3, (r0, 0x4)
   a:	e9230007 	bnez      	r3, 0x18	// 18 <os_sema_up+0x18>
   e:	1045      	lrw      	r2, 0x0	// 20 <os_sema_up+0x20>
  10:	311e      	movi      	r1, 30
  12:	1005      	lrw      	r0, 0x0	// 24 <os_sema_up+0x24>
  14:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  18:	9401      	ld.w      	r0, (r4, 0x4)
  1a:	e0000000 	bsr      	0x0	// 0 <csi_kernel_sem_post>
  1e:	1491      	pop      	r4, r15
	...

Disassembly of section .text.os_sema_del:

00000000 <os_sema_del>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	e9000005 	bez      	r0, 0xe	// e <os_sema_del+0xe>
   8:	9061      	ld.w      	r3, (r0, 0x4)
   a:	e9230007 	bnez      	r3, 0x18	// 18 <os_sema_del+0x18>
   e:	1047      	lrw      	r2, 0x0	// 28 <os_sema_del+0x28>
  10:	3124      	movi      	r1, 36
  12:	1007      	lrw      	r0, 0x0	// 2c <os_sema_del+0x2c>
  14:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  18:	9401      	ld.w      	r0, (r4, 0x4)
  1a:	e0000000 	bsr      	0x0	// 0 <csi_kernel_sem_del>
  1e:	3300      	movi      	r3, 0
  20:	b461      	st.w      	r3, (r4, 0x4)
  22:	b460      	st.w      	r3, (r4, 0x0)
  24:	1491      	pop      	r4, r15
	...

Disassembly of section .text.os_sema_count:

00000000 <os_sema_count>:
   0:	14d0      	push      	r15
   2:	e9000007 	bez      	r0, 0x10	// 10 <os_sema_count+0x10>
   6:	9001      	ld.w      	r0, (r0, 0x4)
   8:	e9000004 	bez      	r0, 0x10	// 10 <os_sema_count+0x10>
   c:	e0000000 	bsr      	0x0	// 0 <csi_kernel_sem_get_count>
  10:	1490      	pop      	r15
