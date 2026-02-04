
disasm/libosal/obj/csky_condv.o:     file format elf32-csky-little


Disassembly of section .text.os_condv_init:

00000000 <os_condv_init>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d03      	mov      	r4, r0
   4:	e9200007 	bnez      	r0, 0x12	// 12 <os_condv_init+0x12>
   8:	1050      	lrw      	r2, 0x0	// 48 <os_condv_init+0x48>
   a:	310e      	movi      	r1, 14
   c:	1010      	lrw      	r0, 0x0	// 4c <os_condv_init+0x4c>
   e:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  12:	9460      	ld.w      	r3, (r4, 0x0)
  14:	10af      	lrw      	r5, 0x3a8d7c1d	// 50 <os_condv_init+0x50>
  16:	654e      	cmpne      	r3, r5
  18:	0c10      	bf      	0x38	// 38 <os_condv_init+0x38>
  1a:	3100      	movi      	r1, 0
  1c:	ea00ffff 	movi      	r0, 65535
  20:	e0000000 	bsr      	0x0	// 0 <csi_kernel_sem_new>
  24:	b402      	st.w      	r0, (r4, 0x8)
  26:	e9000009 	bez      	r0, 0x38	// 38 <os_condv_init+0x38>
  2a:	b4a0      	st.w      	r5, (r4, 0x0)
  2c:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_save>
  30:	3300      	movi      	r3, 0
  32:	b461      	st.w      	r3, (r4, 0x4)
  34:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_restore>
  38:	9440      	ld.w      	r2, (r4, 0x0)
  3a:	1066      	lrw      	r3, 0x3a8d7c1d	// 50 <os_condv_init+0x50>
  3c:	64ca      	cmpne      	r2, r3
  3e:	c4000503 	mvc      	r3
  42:	3000      	movi      	r0, 0
  44:	600e      	subu      	r0, r3
  46:	1492      	pop      	r4-r5, r15
	...
  50:	3a8d7c1d 	.long	0x3a8d7c1d

Disassembly of section .text.os_condv_broadcast:

00000000 <os_condv_broadcast>:
   0:	14d4      	push      	r4-r7, r15
   2:	9040      	ld.w      	r2, (r0, 0x0)
   4:	1072      	lrw      	r3, 0x3a8d7c1d	// 4c <os_condv_broadcast+0x4c>
   6:	64ca      	cmpne      	r2, r3
   8:	6d43      	mov      	r5, r0
   a:	9081      	ld.w      	r4, (r0, 0x4)
   c:	0c06      	bf      	0x18	// 18 <os_condv_broadcast+0x18>
   e:	1051      	lrw      	r2, 0x0	// 50 <os_condv_broadcast+0x50>
  10:	311e      	movi      	r1, 30
  12:	1011      	lrw      	r0, 0x0	// 54 <os_condv_broadcast+0x54>
  14:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  18:	3700      	movi      	r7, 0
  1a:	e9240004 	bnez      	r4, 0x22	// 22 <os_condv_broadcast+0x22>
  1e:	6c13      	mov      	r0, r4
  20:	1494      	pop      	r4-r7, r15
  22:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_save>
  26:	95c1      	ld.w      	r6, (r5, 0x4)
  28:	6592      	cmpne      	r4, r6
  2a:	0802      	bt      	0x2e	// 2e <os_condv_broadcast+0x2e>
  2c:	b5e1      	st.w      	r7, (r5, 0x4)
  2e:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_restore>
  32:	6592      	cmpne      	r4, r6
  34:	0c03      	bf      	0x3a	// 3a <os_condv_broadcast+0x3a>
  36:	9581      	ld.w      	r4, (r5, 0x4)
  38:	07f1      	br      	0x1a	// 1a <os_condv_broadcast+0x1a>
  3a:	3600      	movi      	r6, 0
  3c:	9502      	ld.w      	r0, (r5, 0x8)
  3e:	2600      	addi      	r6, 1
  40:	e0000000 	bsr      	0x0	// 0 <csi_kernel_sem_post>
  44:	6592      	cmpne      	r4, r6
  46:	0bfb      	bt      	0x3c	// 3c <os_condv_broadcast+0x3c>
  48:	07f7      	br      	0x36	// 36 <os_condv_broadcast+0x36>
  4a:	0000      	.short	0x0000
  4c:	3a8d7c1d 	.long	0x3a8d7c1d
	...

Disassembly of section .text.os_condv_signal:

00000000 <os_condv_signal>:
   0:	14d3      	push      	r4-r6, r15
   2:	9040      	ld.w      	r2, (r0, 0x0)
   4:	106f      	lrw      	r3, 0x3a8d7c1d	// 40 <os_condv_signal+0x40>
   6:	64ca      	cmpne      	r2, r3
   8:	6d03      	mov      	r4, r0
   a:	90a1      	ld.w      	r5, (r0, 0x4)
   c:	0c06      	bf      	0x18	// 18 <os_condv_signal+0x18>
   e:	104e      	lrw      	r2, 0x0	// 44 <os_condv_signal+0x44>
  10:	312e      	movi      	r1, 46
  12:	100e      	lrw      	r0, 0x0	// 48 <os_condv_signal+0x48>
  14:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  18:	e9050010 	bez      	r5, 0x38	// 38 <os_condv_signal+0x38>
  1c:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_save>
  20:	94c1      	ld.w      	r6, (r4, 0x4)
  22:	6596      	cmpne      	r5, r6
  24:	0803      	bt      	0x2a	// 2a <os_condv_signal+0x2a>
  26:	5d63      	subi      	r3, r5, 1
  28:	b461      	st.w      	r3, (r4, 0x4)
  2a:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_restore>
  2e:	6596      	cmpne      	r5, r6
  30:	0806      	bt      	0x3c	// 3c <os_condv_signal+0x3c>
  32:	9402      	ld.w      	r0, (r4, 0x8)
  34:	e0000000 	bsr      	0x0	// 0 <csi_kernel_sem_post>
  38:	3000      	movi      	r0, 0
  3a:	1493      	pop      	r4-r6, r15
  3c:	94a1      	ld.w      	r5, (r4, 0x4)
  3e:	07ed      	br      	0x18	// 18 <os_condv_signal+0x18>
  40:	3a8d7c1d 	.long	0x3a8d7c1d
	...

Disassembly of section .text.os_condv_del:

00000000 <os_condv_del>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	e9000006 	bez      	r0, 0x10	// 10 <os_condv_del+0x10>
   8:	9040      	ld.w      	r2, (r0, 0x0)
   a:	1068      	lrw      	r3, 0x3a8d7c1d	// 28 <os_condv_del+0x28>
   c:	64ca      	cmpne      	r2, r3
   e:	0c06      	bf      	0x1a	// 1a <os_condv_del+0x1a>
  10:	1047      	lrw      	r2, 0x0	// 2c <os_condv_del+0x2c>
  12:	313b      	movi      	r1, 59
  14:	1007      	lrw      	r0, 0x0	// 30 <os_condv_del+0x30>
  16:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  1a:	9402      	ld.w      	r0, (r4, 0x8)
  1c:	e0000000 	bsr      	0x0	// 0 <csi_kernel_sem_del>
  20:	3000      	movi      	r0, 0
  22:	b402      	st.w      	r0, (r4, 0x8)
  24:	b400      	st.w      	r0, (r4, 0x0)
  26:	1491      	pop      	r4, r15
  28:	3a8d7c1d 	.long	0x3a8d7c1d
	...

Disassembly of section .text.os_condv_wait:

00000000 <os_condv_wait>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d03      	mov      	r4, r0
   4:	6d47      	mov      	r5, r1
   6:	6d8b      	mov      	r6, r2
   8:	e9000006 	bez      	r0, 0x14	// 14 <os_condv_wait+0x14>
   c:	9040      	ld.w      	r2, (r0, 0x0)
   e:	1077      	lrw      	r3, 0x3a8d7c1d	// 68 <os_condv_wait+0x68>
  10:	64ca      	cmpne      	r2, r3
  12:	0c06      	bf      	0x1e	// 1e <os_condv_wait+0x1e>
  14:	1056      	lrw      	r2, 0x0	// 6c <os_condv_wait+0x6c>
  16:	3145      	movi      	r1, 69
  18:	1016      	lrw      	r0, 0x0	// 70 <os_condv_wait+0x70>
  1a:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  1e:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_save>
  22:	9461      	ld.w      	r3, (r4, 0x4)
  24:	2300      	addi      	r3, 1
  26:	b461      	st.w      	r3, (r4, 0x4)
  28:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_restore>
  2c:	6c17      	mov      	r0, r5
  2e:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  32:	6c5b      	mov      	r1, r6
  34:	9402      	ld.w      	r0, (r4, 0x8)
  36:	e0000000 	bsr      	0x0	// 0 <csi_kernel_sem_wait>
  3a:	6d83      	mov      	r6, r0
  3c:	3100      	movi      	r1, 0
  3e:	2900      	subi      	r1, 1
  40:	6c17      	mov      	r0, r5
  42:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  46:	e906000d 	bez      	r6, 0x60	// 60 <os_condv_wait+0x60>
  4a:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_save>
  4e:	9461      	ld.w      	r3, (r4, 0x4)
  50:	e9030004 	bez      	r3, 0x58	// 58 <os_condv_wait+0x58>
  54:	2b00      	subi      	r3, 1
  56:	b461      	st.w      	r3, (r4, 0x4)
  58:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_restore>
  5c:	3000      	movi      	r0, 0
  5e:	1493      	pop      	r4-r6, r15
  60:	3000      	movi      	r0, 0
  62:	286d      	subi      	r0, 110
  64:	07fd      	br      	0x5e	// 5e <os_condv_wait+0x5e>
  66:	0000      	.short	0x0000
  68:	3a8d7c1d 	.long	0x3a8d7c1d
	...
