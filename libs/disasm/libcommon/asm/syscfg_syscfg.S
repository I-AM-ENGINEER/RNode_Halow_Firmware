
disasm/libcommon/obj/syscfg_syscfg.o:     file format elf32-csky-little


Disassembly of section .text._syscfg_read:

00000000 <_syscfg_read>:
   0:	14d4      	push      	r4-r7, r15
   2:	1424      	subi      	r14, r14, 16
   4:	6d43      	mov      	r5, r0
   6:	320c      	movi      	r2, 12
   8:	6d87      	mov      	r6, r1
   a:	1801      	addi      	r0, r14, 4
   c:	3100      	movi      	r1, 0
   e:	e0000000 	bsr      	0x0	// 0 <memset>
  12:	6c17      	mov      	r0, r5
  14:	e0000000 	bsr      	0x0	// 0 <spi_nor_open>
  18:	6c5b      	mov      	r1, r6
  1a:	330c      	movi      	r3, 12
  1c:	1a01      	addi      	r2, r14, 4
  1e:	6c17      	mov      	r0, r5
  20:	e0000000 	bsr      	0x0	// 0 <spi_nor_read>
  24:	6c17      	mov      	r0, r5
  26:	e0000000 	bsr      	0x0	// 0 <spi_nor_close>
  2a:	d82e1002 	ld.h      	r1, (r14, 0x4)
  2e:	eb411234 	cmpnei      	r1, 4660
  32:	0842      	bt      	0xb6	// b6 <_syscfg_read+0xb6>
  34:	d80e1004 	ld.h      	r0, (r14, 0x8)
  38:	200b      	addi      	r0, 12
  3a:	e0000000 	bsr      	0x0	// 0 <_os_malloc>
  3e:	6d03      	mov      	r4, r0
  40:	e9000035 	bez      	r0, 0xaa	// aa <_syscfg_read+0xaa>
  44:	6c17      	mov      	r0, r5
  46:	e4e4000b 	addi      	r7, r4, 12
  4a:	e0000000 	bsr      	0x0	// 0 <spi_nor_open>
  4e:	d86e1004 	ld.h      	r3, (r14, 0x8)
  52:	6c9f      	mov      	r2, r7
  54:	e426000b 	addi      	r1, r6, 12
  58:	6c17      	mov      	r0, r5
  5a:	e0000000 	bsr      	0x0	// 0 <spi_nor_read>
  5e:	6c17      	mov      	r0, r5
  60:	e0000000 	bsr      	0x0	// 0 <spi_nor_close>
  64:	d84e1004 	ld.h      	r2, (r14, 0x8)
  68:	6c5f      	mov      	r1, r7
  6a:	3006      	movi      	r0, 6
  6c:	e0000000 	bsr      	0x0	// 0 <hw_crc>
  70:	74c1      	zexth      	r3, r0
  72:	d84e1003 	ld.h      	r2, (r14, 0x6)
  76:	64ca      	cmpne      	r2, r3
  78:	6d43      	mov      	r5, r0
  7a:	0809      	bt      	0x8c	// 8c <_syscfg_read+0x8c>
  7c:	320c      	movi      	r2, 12
  7e:	1901      	addi      	r1, r14, 4
  80:	6c13      	mov      	r0, r4
  82:	e0000000 	bsr      	0x0	// 0 <memcpy>
  86:	6c13      	mov      	r0, r4
  88:	1404      	addi      	r14, r14, 16
  8a:	1494      	pop      	r4-r7, r15
  8c:	6c13      	mov      	r0, r4
  8e:	e0000000 	bsr      	0x0	// 0 <_os_free>
  92:	d86e1003 	ld.h      	r3, (r14, 0x6)
  96:	b860      	st.w      	r3, (r14, 0x0)
  98:	d84e1004 	ld.h      	r2, (r14, 0x8)
  9c:	74d5      	zexth      	r3, r5
  9e:	6c5b      	mov      	r1, r6
  a0:	1008      	lrw      	r0, 0x0	// c0 <_syscfg_read+0xc0>
  a2:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  a6:	3400      	movi      	r4, 0
  a8:	07ef      	br      	0x86	// 86 <_syscfg_read+0x86>
  aa:	d82e1004 	ld.h      	r1, (r14, 0x8)
  ae:	1006      	lrw      	r0, 0x0	// c4 <hgprintf+0xc4>
  b0:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  b4:	07e9      	br      	0x86	// 86 <_syscfg_read+0x86>
  b6:	6c9b      	mov      	r2, r6
  b8:	1004      	lrw      	r0, 0x0	// c8 <_syscfg_read+0xc8>
  ba:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  be:	07f4      	br      	0xa6	// a6 <_syscfg_read+0xa6>
	...

Disassembly of section .text.syscfg_read:

00000000 <syscfg_read>:
   0:	14d3      	push      	r4-r6, r15
   2:	1425      	subi      	r14, r14, 20
   4:	6d83      	mov      	r6, r0
   6:	6c3b      	mov      	r0, r14
   8:	6d47      	mov      	r5, r1
   a:	e0000000 	bsr      	0x0	// 0 <syscfg_info_get>
   e:	e900000a 	bez      	r0, 0x22	// 22 <syscfg_read+0x22>
  12:	101c      	lrw      	r0, 0x0	// 80 <syscfg_read+0x80>
  14:	3400      	movi      	r4, 0
  16:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  1a:	2c05      	subi      	r4, 6
  1c:	6c13      	mov      	r0, r4
  1e:	1405      	addi      	r14, r14, 20
  20:	1493      	pop      	r4-r6, r15
  22:	3100      	movi      	r1, 0
  24:	2900      	subi      	r1, 1
  26:	1018      	lrw      	r0, 0x0	// 84 <syscfg_read+0x84>
  28:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  2c:	9822      	ld.w      	r1, (r14, 0x8)
  2e:	9800      	ld.w      	r0, (r14, 0x0)
  30:	e0000000 	bsr      	0x0	// 0 <syscfg_read>
  34:	6d03      	mov      	r4, r0
  36:	e9200009 	bnez      	r0, 0x48	// 48 <syscfg_read+0x48>
  3a:	9823      	ld.w      	r1, (r14, 0xc)
  3c:	9801      	ld.w      	r0, (r14, 0x4)
  3e:	e0000000 	bsr      	0x0	// 0 <syscfg_read>
  42:	6d03      	mov      	r4, r0
  44:	e900001b 	bez      	r0, 0x7a	// 7a <syscfg_read+0x7a>
  48:	8c42      	ld.h      	r2, (r4, 0x4)
  4a:	220b      	addi      	r2, 12
  4c:	6495      	cmplt      	r5, r2
  4e:	6c53      	mov      	r1, r4
  50:	c4450c40 	inct      	r2, r5, 0
  54:	6c1b      	mov      	r0, r6
  56:	e0000000 	bsr      	0x0	// 0 <memcpy>
  5a:	6c13      	mov      	r0, r4
  5c:	e0000000 	bsr      	0x0	// 0 <_os_free>
  60:	3400      	movi      	r4, 0
  62:	1009      	lrw      	r0, 0x0	// 84 <syscfg_read+0x84>
  64:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  68:	3c40      	cmpnei      	r4, 0
  6a:	1068      	lrw      	r3, 0x0	// 88 <syscfg_read+0x88>
  6c:	1028      	lrw      	r1, 0x0	// 8c <syscfg_read+0x8c>
  6e:	c4230c20 	incf      	r1, r3, 0
  72:	1008      	lrw      	r0, 0x0	// 90 <hgprintf+0x90>
  74:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  78:	07d2      	br      	0x1c	// 1c <syscfg_read+0x1c>
  7a:	3400      	movi      	r4, 0
  7c:	2c00      	subi      	r4, 1
  7e:	07f2      	br      	0x62	// 62 <syscfg_read+0x62>
	...

Disassembly of section .text.syscfg_write:

00000000 <syscfg_write>:
   0:	14d8      	push      	r4-r11, r15
   2:	1427      	subi      	r14, r14, 28
   4:	6dc3      	mov      	r7, r0
   6:	3300      	movi      	r3, 0
   8:	1802      	addi      	r0, r14, 8
   a:	6e07      	mov      	r8, r1
   c:	dc6e1002 	st.h      	r3, (r14, 0x4)
  10:	dc6e1003 	st.h      	r3, (r14, 0x6)
  14:	e0000000 	bsr      	0x0	// 0 <syscfg_info_get>
  18:	e900000a 	bez      	r0, 0x2c	// 2c <syscfg_write+0x2c>
  1c:	1304      	lrw      	r0, 0x0	// 1ac <hgprintf+0x1ac>
  1e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  22:	3400      	movi      	r4, 0
  24:	2c00      	subi      	r4, 1
  26:	6c13      	mov      	r0, r4
  28:	1407      	addi      	r14, r14, 28
  2a:	1498      	pop      	r4-r11, r15
  2c:	6c23      	mov      	r0, r8
  2e:	e0000000 	bsr      	0x0	// 0 <_os_malloc>
  32:	6d43      	mov      	r5, r0
  34:	e9200007 	bnez      	r0, 0x42	// 42 <syscfg_write+0x42>
  38:	6c63      	mov      	r1, r8
  3a:	121e      	lrw      	r0, 0x0	// 1b0 <syscfg_write+0x1b0>
  3c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  40:	07f1      	br      	0x22	// 22 <syscfg_write+0x22>
  42:	3100      	movi      	r1, 0
  44:	9882      	ld.w      	r4, (r14, 0x8)
  46:	2900      	subi      	r1, 1
  48:	121b      	lrw      	r0, 0x0	// 1b4 <syscfg_write+0x1b4>
  4a:	98c4      	ld.w      	r6, (r14, 0x10)
  4c:	d94e2003 	ld.w      	r10, (r14, 0xc)
  50:	d96e2005 	ld.w      	r11, (r14, 0x14)
  54:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  58:	6c13      	mov      	r0, r4
  5a:	e0000000 	bsr      	0x0	// 0 <spi_nor_open>
  5e:	3302      	movi      	r3, 2
  60:	1a01      	addi      	r2, r14, 4
  62:	6c5b      	mov      	r1, r6
  64:	6c13      	mov      	r0, r4
  66:	e0000000 	bsr      	0x0	// 0 <spi_nor_read>
  6a:	d86e1002 	ld.h      	r3, (r14, 0x4)
  6e:	eb431234 	cmpnei      	r3, 4660
  72:	080d      	bt      	0x8c	// 8c <syscfg_write+0x8c>
  74:	6c13      	mov      	r0, r4
  76:	e0000000 	bsr      	0x0	// 0 <spi_nor_close>
  7a:	9883      	ld.w      	r4, (r14, 0xc)
  7c:	6c13      	mov      	r0, r4
  7e:	98c5      	ld.w      	r6, (r14, 0x14)
  80:	d94e2002 	ld.w      	r10, (r14, 0x8)
  84:	d96e2004 	ld.w      	r11, (r14, 0x10)
  88:	e0000000 	bsr      	0x0	// 0 <spi_nor_open>
  8c:	9862      	ld.w      	r3, (r14, 0x8)
  8e:	d92e2006 	ld.w      	r9, (r14, 0x18)
  92:	9369      	ld.w      	r3, (r3, 0x24)
  94:	c4698029 	divu      	r9, r9, r3
  98:	7664      	zextb      	r9, r9
  9a:	3300      	movi      	r3, 0
  9c:	748c      	zextb      	r2, r3
  9e:	6648      	cmphs      	r2, r9
  a0:	0c6c      	bf      	0x178	// 178 <syscfg_write+0x178>
  a2:	3300      	movi      	r3, 0
  a4:	e588100b 	subi      	r12, r8, 12
  a8:	2b00      	subi      	r3, 1
  aa:	6cb3      	mov      	r2, r12
  ac:	dd871002 	st.h      	r12, (r7, 0x4)
  b0:	af60      	st.h      	r3, (r7, 0x0)
  b2:	e427000b 	addi      	r1, r7, 12
  b6:	3006      	movi      	r0, 6
  b8:	dd8e2000 	st.w      	r12, (r14, 0x0)
  bc:	e0000000 	bsr      	0x0	// 0 <hw_crc>
  c0:	af01      	st.h      	r0, (r7, 0x2)
  c2:	ea090000 	movi      	r9, 0
  c6:	111d      	lrw      	r0, 0x0	// 1b8 <hgprintf+0x1b8>
  c8:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  cc:	6ce3      	mov      	r3, r8
  ce:	6c9f      	mov      	r2, r7
  d0:	6c5b      	mov      	r1, r6
  d2:	6c13      	mov      	r0, r4
  d4:	e0000000 	bsr      	0x0	// 0 <spi_nor_write>
  d8:	6ce3      	mov      	r3, r8
  da:	6c97      	mov      	r2, r5
  dc:	6c5b      	mov      	r1, r6
  de:	6c13      	mov      	r0, r4
  e0:	dd251000 	st.h      	r9, (r5, 0x0)
  e4:	dd251001 	st.h      	r9, (r5, 0x2)
  e8:	dd251002 	st.h      	r9, (r5, 0x4)
  ec:	e0000000 	bsr      	0x0	// 0 <spi_nor_read>
  f0:	d98e2000 	ld.w      	r12, (r14, 0x0)
  f4:	6cb3      	mov      	r2, r12
  f6:	e425000b 	addi      	r1, r5, 12
  fa:	3006      	movi      	r0, 6
  fc:	e0000000 	bsr      	0x0	// 0 <hw_crc>
 100:	8d60      	ld.h      	r3, (r5, 0x0)
 102:	eb43ffff 	cmpnei      	r3, 65535
 106:	7401      	zexth      	r0, r0
 108:	ad01      	st.h      	r0, (r5, 0x2)
 10a:	0847      	bt      	0x198	// 198 <syscfg_write+0x198>
 10c:	8d42      	ld.h      	r2, (r5, 0x4)
 10e:	8f62      	ld.h      	r3, (r7, 0x4)
 110:	64ca      	cmpne      	r2, r3
 112:	0843      	bt      	0x198	// 198 <syscfg_write+0x198>
 114:	8f61      	ld.h      	r3, (r7, 0x2)
 116:	640e      	cmpne      	r3, r0
 118:	0840      	bt      	0x198	// 198 <syscfg_write+0x198>
 11a:	ea031234 	movi      	r3, 4660
 11e:	dc6e1002 	st.h      	r3, (r14, 0x4)
 122:	1a01      	addi      	r2, r14, 4
 124:	3302      	movi      	r3, 2
 126:	6c5b      	mov      	r1, r6
 128:	6c13      	mov      	r0, r4
 12a:	e0000000 	bsr      	0x0	// 0 <spi_nor_write>
 12e:	3302      	movi      	r3, 2
 130:	e44e0005 	addi      	r2, r14, 6
 134:	6c5b      	mov      	r1, r6
 136:	6c13      	mov      	r0, r4
 138:	e0000000 	bsr      	0x0	// 0 <spi_nor_read>
 13c:	6c13      	mov      	r0, r4
 13e:	e0000000 	bsr      	0x0	// 0 <spi_nor_close>
 142:	d86e1003 	ld.h      	r3, (r14, 0x6)
 146:	eb431234 	cmpnei      	r3, 4660
 14a:	0821      	bt      	0x18c	// 18c <syscfg_write+0x18c>
 14c:	6c2b      	mov      	r0, r10
 14e:	dd2e1002 	st.h      	r9, (r14, 0x4)
 152:	e0000000 	bsr      	0x0	// 0 <spi_nor_open>
 156:	3302      	movi      	r3, 2
 158:	1a01      	addi      	r2, r14, 4
 15a:	6c6f      	mov      	r1, r11
 15c:	6c2b      	mov      	r0, r10
 15e:	e0000000 	bsr      	0x0	// 0 <spi_nor_write>
 162:	6c2b      	mov      	r0, r10
 164:	e0000000 	bsr      	0x0	// 0 <spi_nor_close>
 168:	3400      	movi      	r4, 0
 16a:	1013      	lrw      	r0, 0x0	// 1b4 <syscfg_write+0x1b4>
 16c:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
 170:	6c17      	mov      	r0, r5
 172:	e0000000 	bsr      	0x0	// 0 <_os_free>
 176:	0758      	br      	0x26	// 26 <syscfg_write+0x26>
 178:	9429      	ld.w      	r1, (r4, 0x24)
 17a:	7c4c      	mult      	r1, r3
 17c:	6058      	addu      	r1, r6
 17e:	6c13      	mov      	r0, r4
 180:	b860      	st.w      	r3, (r14, 0x0)
 182:	e0000000 	bsr      	0x0	// 0 <spi_nor_sector_erase>
 186:	9860      	ld.w      	r3, (r14, 0x0)
 188:	2300      	addi      	r3, 1
 18a:	0789      	br      	0x9c	// 9c <syscfg_write+0x9c>
 18c:	100c      	lrw      	r0, 0x0	// 1bc <syscfg_write+0x1bc>
 18e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 192:	3400      	movi      	r4, 0
 194:	2c00      	subi      	r4, 1
 196:	07ea      	br      	0x16a	// 16a <syscfg_write+0x16a>
 198:	1009      	lrw      	r0, 0x0	// 1bc <syscfg_write+0x1bc>
 19a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 19e:	e904fffa 	bez      	r4, 0x192	// 192 <syscfg_write+0x192>
 1a2:	6c13      	mov      	r0, r4
 1a4:	e0000000 	bsr      	0x0	// 0 <spi_nor_close>
 1a8:	07f5      	br      	0x192	// 192 <syscfg_write+0x192>
	...

Disassembly of section .text.syscfg_init:

00000000 <syscfg_init>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d03      	mov      	r4, r0
   4:	1008      	lrw      	r0, 0x0	// 24 <syscfg_init+0x24>
   6:	6d47      	mov      	r5, r1
   8:	e0000000 	bsr      	0x0	// 0 <os_mutex_init>
   c:	e9000007 	bez      	r0, 0x1a	// 1a <syscfg_init+0x1a>
  10:	1046      	lrw      	r2, 0x0	// 28 <syscfg_init+0x28>
  12:	31b4      	movi      	r1, 180
  14:	1006      	lrw      	r0, 0x0	// 2c <syscfg_init+0x2c>
  16:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  1a:	6c57      	mov      	r1, r5
  1c:	6c13      	mov      	r0, r4
  1e:	e0000000 	bsr      	0x0	// 0 <syscfg_init>
  22:	1492      	pop      	r4-r5, r15
	...

Disassembly of section .text.syscfg_loaddef:

00000000 <syscfg_loaddef>:
   0:	14d1      	push      	r4, r15
   2:	143f      	subi      	r14, r14, 124
   4:	1801      	addi      	r0, r14, 4
   6:	3300      	movi      	r3, 0
   8:	dc6e1001 	st.h      	r3, (r14, 0x2)
   c:	e0000000 	bsr      	0x0	// 0 <syscfg_info_get>
  10:	6d03      	mov      	r4, r0
  12:	e920003e 	bnez      	r0, 0x8e	// 8e <syscfg_loaddef+0x8e>
  16:	3100      	movi      	r1, 0
  18:	2900      	subi      	r1, 1
  1a:	101f      	lrw      	r0, 0x0	// 94 <syscfg_loaddef+0x94>
  1c:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  20:	9801      	ld.w      	r0, (r14, 0x4)
  22:	e0000000 	bsr      	0x0	// 0 <spi_nor_open>
  26:	3302      	movi      	r3, 2
  28:	c46e0022 	addu      	r2, r14, r3
  2c:	9823      	ld.w      	r1, (r14, 0xc)
  2e:	9801      	ld.w      	r0, (r14, 0x4)
  30:	e0000000 	bsr      	0x0	// 0 <spi_nor_write>
  34:	9801      	ld.w      	r0, (r14, 0x4)
  36:	e0000000 	bsr      	0x0	// 0 <spi_nor_close>
  3a:	9802      	ld.w      	r0, (r14, 0x8)
  3c:	e0000000 	bsr      	0x0	// 0 <spi_nor_open>
  40:	3302      	movi      	r3, 2
  42:	c46e0022 	addu      	r2, r14, r3
  46:	9824      	ld.w      	r1, (r14, 0x10)
  48:	9802      	ld.w      	r0, (r14, 0x8)
  4a:	e0000000 	bsr      	0x0	// 0 <spi_nor_write>
  4e:	9802      	ld.w      	r0, (r14, 0x8)
  50:	e0000000 	bsr      	0x0	// 0 <spi_nor_close>
  54:	1010      	lrw      	r0, 0x0	// 94 <os_mutex_unlock+0x94>
  56:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  5a:	1010      	lrw      	r0, 0x0	// 98 <hgprintf+0x98>
  5c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  60:	3264      	movi      	r2, 100
  62:	6c53      	mov      	r1, r4
  64:	1806      	addi      	r0, r14, 24
  66:	e0000000 	bsr      	0x0	// 0 <memset>
  6a:	6c13      	mov      	r0, r4
  6c:	3219      	movi      	r2, 25
  6e:	1906      	addi      	r1, r14, 24
  70:	2400      	addi      	r4, 1
  72:	e0000000 	bsr      	0x0	// 0 <memory_write>
  76:	3c49      	cmpnei      	r4, 9
  78:	0bf9      	bt      	0x6a	// 6a <syscfg_loaddef+0x6a>
  7a:	1009      	lrw      	r0, 0x0	// 9c <syscfg_loaddef+0x9c>
  7c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  80:	1008      	lrw      	r0, 0x0	// a0 <hgprintf+0xa0>
  82:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  86:	ea004e20 	movi      	r0, 20000
  8a:	e0000000 	bsr      	0x0	// 0 <delay_us>
  8e:	141f      	addi      	r14, r14, 124
  90:	1491      	pop      	r4, r15
	...
