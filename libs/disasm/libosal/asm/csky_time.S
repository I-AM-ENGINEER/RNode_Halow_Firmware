
disasm/libosal/obj/csky_time.o:     file format elf32-csky-little


Disassembly of section .text.os_jiffies:

00000000 <os_jiffies>:
   0:	1062      	lrw      	r3, 0x0	// 8 <os_jiffies+0x8>
   2:	9300      	ld.w      	r0, (r3, 0x0)
   4:	9321      	ld.w      	r1, (r3, 0x4)
   6:	783c      	jmp      	r15
   8:	00000000 	.long	0x00000000

Disassembly of section .text.os_systime:

00000000 <os_systime>:
   0:	1066      	lrw      	r3, 0x0	// 18 <os_systime+0x18>
   2:	9340      	ld.w      	r2, (r3, 0x0)
   4:	b040      	st.w      	r2, (r0, 0x0)
   6:	9361      	ld.w      	r3, (r3, 0x4)
   8:	ea02f424 	movi      	r2, 62500
   c:	c4824902 	rotli      	r2, r2, 4
  10:	7cc8      	mult      	r3, r2
  12:	b061      	st.w      	r3, (r0, 0x4)
  14:	783c      	jmp      	r15
  16:	0000      	.short	0x0000
  18:	00000000 	.long	0x00000000

Disassembly of section .text.gettimeofday:

00000000 <gettimeofday>:
   0:	1066      	lrw      	r3, 0x0	// 18 <gettimeofday+0x18>
   2:	9340      	ld.w      	r2, (r3, 0x0)
   4:	b040      	st.w      	r2, (r0, 0x0)
   6:	32fa      	movi      	r2, 250
   8:	9361      	ld.w      	r3, (r3, 0x4)
   a:	4242      	lsli      	r2, r2, 2
   c:	7cc8      	mult      	r3, r2
   e:	535f      	asri      	r2, r3, 31
  10:	b061      	st.w      	r3, (r0, 0x4)
  12:	b042      	st.w      	r2, (r0, 0x8)
  14:	3000      	movi      	r0, 0
  16:	783c      	jmp      	r15
  18:	00000000 	.long	0x00000000

Disassembly of section .text.settimeofday:

00000000 <settimeofday>:
   0:	14d2      	push      	r4-r5, r15
   2:	c0006024 	mfcr      	r4, cr<0, 0>
   6:	c0807020 	psrclr      	ie
   a:	10aa      	lrw      	r5, 0x0	// 30 <settimeofday+0x30>
   c:	32fa      	movi      	r2, 250
   e:	9060      	ld.w      	r3, (r0, 0x0)
  10:	b560      	st.w      	r3, (r5, 0x0)
  12:	9022      	ld.w      	r1, (r0, 0x8)
  14:	9001      	ld.w      	r0, (r0, 0x4)
  16:	4242      	lsli      	r2, r2, 2
  18:	3300      	movi      	r3, 0
  1a:	e4842040 	andi      	r4, r4, 64
  1e:	e0000000 	bsr      	0x0	// 0 <__udivdi3>
  22:	b501      	st.w      	r0, (r5, 0x4)
  24:	e9040004 	bez      	r4, 0x2c	// 2c <settimeofday+0x2c>
  28:	c0807420 	psrset      	ie
  2c:	3000      	movi      	r0, 0
  2e:	1492      	pop      	r4-r5, r15
  30:	0000      	.short	0x0000
	...

Disassembly of section .text.time:

00000000 <time>:
   0:	1064      	lrw      	r3, 0x0	// 10 <time+0x10>
   2:	e9000004 	bez      	r0, 0xa	// a <time+0xa>
   6:	9340      	ld.w      	r2, (r3, 0x0)
   8:	b040      	st.w      	r2, (r0, 0x0)
   a:	9300      	ld.w      	r0, (r3, 0x0)
   c:	783c      	jmp      	r15
   e:	0000      	.short	0x0000
  10:	0000      	.short	0x0000
	...

Disassembly of section .text.clock_gettime:

00000000 <clock_gettime>:
   0:	14d0      	push      	r15
   2:	6c07      	mov      	r0, r1
   4:	e0000000 	bsr      	0x0	// 0 <clock_gettime>
   8:	3000      	movi      	r0, 0
   a:	1490      	pop      	r15

Disassembly of section .text.timespec_validate:

00000000 <timespec_validate>:
   0:	e9000008 	bez      	r0, 0x10	// 10 <timespec_validate+0x10>
   4:	9041      	ld.w      	r2, (r0, 0x4)
   6:	1064      	lrw      	r3, 0x3b9ac9ff	// 14 <timespec_validate+0x14>
   8:	648c      	cmphs      	r3, r2
   a:	c4000500 	mvc      	r0
   e:	7400      	zextb      	r0, r0
  10:	783c      	jmp      	r15
  12:	0000      	.short	0x0000
  14:	c9ff      	.short	0xc9ff
  16:	3b9a      	.short	0x3b9a

Disassembly of section .text.timespec_cmp:

00000000 <timespec_cmp>:
   0:	e9200007 	bnez      	r0, 0xe	// e <timespec_cmp+0xe>
   4:	3940      	cmpnei      	r1, 0
   6:	c4000503 	mvc      	r3
   a:	600e      	subu      	r0, r3
   c:	783c      	jmp      	r15
   e:	e9010014 	bez      	r1, 0x36	// 36 <timespec_cmp+0x36>
  12:	9040      	ld.w      	r2, (r0, 0x0)
  14:	9160      	ld.w      	r3, (r1, 0x0)
  16:	648c      	cmphs      	r3, r2
  18:	0c0f      	bf      	0x36	// 36 <timespec_cmp+0x36>
  1a:	64c8      	cmphs      	r2, r3
  1c:	0c0a      	bf      	0x30	// 30 <timespec_cmp+0x30>
  1e:	9041      	ld.w      	r2, (r0, 0x4)
  20:	9161      	ld.w      	r3, (r1, 0x4)
  22:	648d      	cmplt      	r3, r2
  24:	0809      	bt      	0x36	// 36 <timespec_cmp+0x36>
  26:	64c9      	cmplt      	r2, r3
  28:	c4000503 	mvc      	r3
  2c:	3000      	movi      	r0, 0
  2e:	07ee      	br      	0xa	// a <timespec_cmp+0xa>
  30:	3000      	movi      	r0, 0
  32:	2800      	subi      	r0, 1
  34:	07ec      	br      	0xc	// c <timespec_cmp+0xc>
  36:	3001      	movi      	r0, 1
  38:	07ea      	br      	0xc	// c <timespec_cmp+0xc>

Disassembly of section .text.timespec_to_ticks:

00000000 <timespec_to_ticks>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d03      	mov      	r4, r0
   4:	6d47      	mov      	r5, r1
   6:	e9000024 	bez      	r0, 0x4e	// 4e <timespec_to_ticks+0x4e>
   a:	e9010022 	bez      	r1, 0x4e	// 4e <timespec_to_ticks+0x4e>
   e:	e0000000 	bsr      	0x0	// 0 <timespec_to_ticks>
  12:	e900001e 	bez      	r0, 0x4e	// 4e <timespec_to_ticks+0x4e>
  16:	32fa      	movi      	r2, 250
  18:	4242      	lsli      	r2, r2, 2
  1a:	3300      	movi      	r3, 0
  1c:	9400      	ld.w      	r0, (r4, 0x0)
  1e:	3100      	movi      	r1, 0
  20:	e0000000 	bsr      	0x0	// 0 <__muldi3>
  24:	9441      	ld.w      	r2, (r4, 0x4)
  26:	ea03f424 	movi      	r3, 62500
  2a:	c4834903 	rotli      	r3, r3, 4
  2e:	c462804c 	divs      	r12, r2, r3
  32:	7cf0      	mult      	r3, r12
  34:	64ca      	cmpne      	r2, r3
  36:	c400050d 	mvc      	r13
  3a:	c58d0022 	addu      	r2, r13, r12
  3e:	527f      	asri      	r3, r2, 31
  40:	6401      	cmplt      	r0, r0
  42:	6009      	addc      	r0, r2
  44:	604d      	addc      	r1, r3
  46:	b500      	st.w      	r0, (r5, 0x0)
  48:	b521      	st.w      	r1, (r5, 0x4)
  4a:	3000      	movi      	r0, 0
  4c:	1492      	pop      	r4-r5, r15
  4e:	3000      	movi      	r0, 0
  50:	2815      	subi      	r0, 22
  52:	07fd      	br      	0x4c	// 4c <timespec_to_ticks+0x4c>

Disassembly of section .text.nanosec_to_timespec:

00000000 <nanosec_to_timespec>:
   0:	14d4      	push      	r4-r7, r15
   2:	6d0b      	mov      	r4, r2
   4:	3300      	movi      	r3, 0
   6:	104c      	lrw      	r2, 0x3b9aca00	// 34 <nanosec_to_timespec+0x34>
   8:	6d83      	mov      	r6, r0
   a:	6dc7      	mov      	r7, r1
   c:	e0000000 	bsr      	0x0	// 0 <__divdi3>
  10:	b400      	st.w      	r0, (r4, 0x0)
  12:	6d43      	mov      	r5, r0
  14:	1048      	lrw      	r2, 0x3b9aca00	// 34 <nanosec_to_timespec+0x34>
  16:	3300      	movi      	r3, 0
  18:	6c1b      	mov      	r0, r6
  1a:	6c5f      	mov      	r1, r7
  1c:	e0000000 	bsr      	0x0	// 0 <__moddi3>
  20:	b401      	st.w      	r0, (r4, 0x4)
  22:	e9a00007 	bhsz      	r0, 0x30	// 30 <nanosec_to_timespec+0x30>
  26:	1064      	lrw      	r3, 0x3b9aca00	// 34 <nanosec_to_timespec+0x34>
  28:	2d00      	subi      	r5, 1
  2a:	600c      	addu      	r0, r3
  2c:	b4a0      	st.w      	r5, (r4, 0x0)
  2e:	b401      	st.w      	r0, (r4, 0x4)
  30:	1494      	pop      	r4-r7, r15
  32:	0000      	.short	0x0000
  34:	3b9aca00 	.long	0x3b9aca00

Disassembly of section .text.timespec_add:

00000000 <timespec_add>:
   0:	e902001d 	bez      	r2, 0x3a	// 3a <timespec_add+0x3a>
   4:	e900001b 	bez      	r0, 0x3a	// 3a <timespec_add+0x3a>
   8:	e9010019 	bez      	r1, 0x3a	// 3a <timespec_add+0x3a>
   c:	9061      	ld.w      	r3, (r0, 0x4)
   e:	d9812001 	ld.w      	r12, (r1, 0x4)
  12:	60f0      	addu      	r3, r12
  14:	e9a30005 	bhsz      	r3, 0x1e	// 1e <timespec_add+0x1e>
  18:	b261      	st.w      	r3, (r2, 0x4)
  1a:	3001      	movi      	r0, 1
  1c:	783c      	jmp      	r15
  1e:	ea8c0009 	lrw      	r12, 0x3b9aca00	// 40 <timespec_add+0x40>
  22:	c583804d 	divs      	r13, r3, r12
  26:	7f34      	mult      	r12, r13
  28:	60f2      	subu      	r3, r12
  2a:	9120      	ld.w      	r1, (r1, 0x0)
  2c:	b261      	st.w      	r3, (r2, 0x4)
  2e:	9060      	ld.w      	r3, (r0, 0x0)
  30:	60c4      	addu      	r3, r1
  32:	60f4      	addu      	r3, r13
  34:	b260      	st.w      	r3, (r2, 0x0)
  36:	3000      	movi      	r0, 0
  38:	07f2      	br      	0x1c	// 1c <timespec_add+0x1c>
  3a:	3000      	movi      	r0, 0
  3c:	2800      	subi      	r0, 1
  3e:	07ef      	br      	0x1c	// 1c <timespec_add+0x1c>
  40:	3b9aca00 	.long	0x3b9aca00

Disassembly of section .text.timespec_add_nanosec:

00000000 <timespec_add_nanosec>:
   0:	14d4      	push      	r4-r7, r15
   2:	6dc3      	mov      	r7, r0
   4:	6d07      	mov      	r4, r1
   6:	6d4b      	mov      	r5, r2
   8:	6d8f      	mov      	r6, r3
   a:	e903001d 	bez      	r3, 0x44	// 44 <timespec_add_nanosec+0x44>
   e:	e900001b 	bez      	r0, 0x44	// 44 <timespec_add_nanosec+0x44>
  12:	9041      	ld.w      	r2, (r0, 0x4)
  14:	527f      	asri      	r3, r2, 31
  16:	6511      	cmplt      	r4, r4
  18:	6109      	addc      	r4, r2
  1a:	614d      	addc      	r5, r3
  1c:	e9850017 	blz      	r5, 0x4a	// 4a <timespec_add_nanosec+0x4a>
  20:	104c      	lrw      	r2, 0x3b9aca00	// 50 <timespec_add_nanosec+0x50>
  22:	3300      	movi      	r3, 0
  24:	6c13      	mov      	r0, r4
  26:	6c57      	mov      	r1, r5
  28:	e0000000 	bsr      	0x0	// 0 <__moddi3>
  2c:	b601      	st.w      	r0, (r6, 0x4)
  2e:	3300      	movi      	r3, 0
  30:	1048      	lrw      	r2, 0x3b9aca00	// 50 <timespec_add_nanosec+0x50>
  32:	6c13      	mov      	r0, r4
  34:	6c57      	mov      	r1, r5
  36:	e0000000 	bsr      	0x0	// 0 <__divdi3>
  3a:	9760      	ld.w      	r3, (r7, 0x0)
  3c:	600c      	addu      	r0, r3
  3e:	b600      	st.w      	r0, (r6, 0x0)
  40:	3000      	movi      	r0, 0
  42:	1494      	pop      	r4-r7, r15
  44:	3000      	movi      	r0, 0
  46:	2800      	subi      	r0, 1
  48:	07fd      	br      	0x42	// 42 <timespec_add_nanosec+0x42>
  4a:	3001      	movi      	r0, 1
  4c:	07fb      	br      	0x42	// 42 <timespec_add_nanosec+0x42>
  4e:	0000      	.short	0x0000
  50:	3b9aca00 	.long	0x3b9aca00

Disassembly of section .text.timespec_sub:

00000000 <timespec_sub>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d83      	mov      	r6, r0
   4:	6d47      	mov      	r5, r1
   6:	6d0b      	mov      	r4, r2
   8:	e9020023 	bez      	r2, 0x4e	// 4e <timespec_sub+0x4e>
   c:	e9000021 	bez      	r0, 0x4e	// 4e <timespec_sub+0x4e>
  10:	e901001f 	bez      	r1, 0x4e	// 4e <timespec_sub+0x4e>
  14:	e0000000 	bsr      	0x0	// 0 <timespec_sub>
  18:	3300      	movi      	r3, 0
  1a:	2b00      	subi      	r3, 1
  1c:	64c2      	cmpne      	r0, r3
  1e:	0c1b      	bf      	0x54	// 54 <timespec_sub+0x54>
  20:	e9200005 	bnez      	r0, 0x2a	// 2a <timespec_sub+0x2a>
  24:	b400      	st.w      	r0, (r4, 0x0)
  26:	b401      	st.w      	r0, (r4, 0x4)
  28:	1493      	pop      	r4-r6, r15
  2a:	9560      	ld.w      	r3, (r5, 0x0)
  2c:	9640      	ld.w      	r2, (r6, 0x0)
  2e:	608e      	subu      	r2, r3
  30:	9521      	ld.w      	r1, (r5, 0x4)
  32:	9661      	ld.w      	r3, (r6, 0x4)
  34:	60c6      	subu      	r3, r1
  36:	b440      	st.w      	r2, (r4, 0x0)
  38:	b461      	st.w      	r3, (r4, 0x4)
  3a:	e9a30007 	bhsz      	r3, 0x48	// 48 <timespec_sub+0x48>
  3e:	2a00      	subi      	r2, 1
  40:	b440      	st.w      	r2, (r4, 0x0)
  42:	1046      	lrw      	r2, 0x3b9aca00	// 58 <timespec_sub+0x58>
  44:	60c8      	addu      	r3, r2
  46:	b461      	st.w      	r3, (r4, 0x4)
  48:	9401      	ld.w      	r0, (r4, 0x4)
  4a:	501f      	asri      	r0, r0, 31
  4c:	07ee      	br      	0x28	// 28 <timespec_sub+0x28>
  4e:	3000      	movi      	r0, 0
  50:	2800      	subi      	r0, 1
  52:	07eb      	br      	0x28	// 28 <timespec_sub+0x28>
  54:	3001      	movi      	r0, 1
  56:	07e9      	br      	0x28	// 28 <timespec_sub+0x28>
  58:	3b9aca00 	.long	0x3b9aca00

Disassembly of section .text.timespec_detal_ticks:

00000000 <timespec_detal_ticks>:
   0:	14d1      	push      	r4, r15
   2:	1422      	subi      	r14, r14, 8
   4:	ea0c0000 	movi      	r12, 0
   8:	ea0d0000 	movi      	r13, 0
   c:	6d0b      	mov      	r4, r2
   e:	dd8e2000 	st.w      	r12, (r14, 0x0)
  12:	ddae2001 	st.w      	r13, (r14, 0x4)
  16:	e9200006 	bnez      	r0, 0x22	// 22 <timespec_detal_ticks+0x22>
  1a:	3000      	movi      	r0, 0
  1c:	2815      	subi      	r0, 22
  1e:	1402      	addi      	r14, r14, 8
  20:	1491      	pop      	r4, r15
  22:	e901fffc 	bez      	r1, 0x1a	// 1a <timespec_detal_ticks+0x1a>
  26:	e902fffa 	bez      	r2, 0x1a	// 1a <timespec_detal_ticks+0x1a>
  2a:	6cbb      	mov      	r2, r14
  2c:	e0000000 	bsr      	0x0	// 0 <timespec_detal_ticks>
  30:	3841      	cmpnei      	r0, 1
  32:	0c0c      	bf      	0x4a	// 4a <timespec_detal_ticks+0x4a>
  34:	3300      	movi      	r3, 0
  36:	2b00      	subi      	r3, 1
  38:	64c2      	cmpne      	r0, r3
  3a:	0ff0      	bf      	0x1a	// 1a <timespec_detal_ticks+0x1a>
  3c:	e920fff1 	bnez      	r0, 0x1e	// 1e <timespec_detal_ticks+0x1e>
  40:	6c53      	mov      	r1, r4
  42:	6c3b      	mov      	r0, r14
  44:	e0000000 	bsr      	0x0	// 0 <timespec_detal_ticks>
  48:	07eb      	br      	0x1e	// 1e <timespec_detal_ticks+0x1e>
  4a:	3000      	movi      	r0, 0
  4c:	286d      	subi      	r0, 110
  4e:	07e8      	br      	0x1e	// 1e <timespec_detal_ticks+0x1e>
