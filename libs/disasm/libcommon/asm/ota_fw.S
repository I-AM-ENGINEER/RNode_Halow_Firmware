
disasm/libcommon/obj/ota_fw.o:     file format elf32-csky-little


Disassembly of section .text.ota_fwinfo_get:

00000000 <ota_fwinfo_get>:
   0:	3000      	movi      	r0, 0
   2:	2800      	subi      	r0, 1
   4:	783c      	jmp      	r15

Disassembly of section .text.libota_write_fw_ah:

00000000 <libota_write_fw_ah>:
   0:	14d8      	push      	r4-r11, r15
   2:	1424      	subi      	r14, r14, 16
   4:	6dcf      	mov      	r7, r3
   6:	ea8800a6 	lrw      	r8, 0x0	// 29c <libota_write_fw_ah+0x29c>
   a:	3300      	movi      	r3, 0
   c:	2b00      	subi      	r3, 1
   e:	6d8b      	mov      	r6, r2
  10:	b861      	st.w      	r3, (r14, 0x4)
  12:	3201      	movi      	r2, 1
  14:	d8680001 	ld.b      	r3, (r8, 0x1)
  18:	3f41      	cmpnei      	r7, 1
  1a:	c4625c03 	ins      	r3, r2, 3, 3
  1e:	6e43      	mov      	r9, r0
  20:	6d47      	mov      	r5, r1
  22:	dc680001 	st.b      	r3, (r8, 0x1)
  26:	0380      	lrw      	r4, 0x0	// 2a0 <libota_write_fw_ah+0x2a0>
  28:	0c23      	bf      	0x6e	// 6e <libota_write_fw_ah+0x6e>
  2a:	e921008a 	bnez      	r1, 0x13e	// 13e <libota_write_fw_ah+0x13e>
  2e:	6c1b      	mov      	r0, r6
  30:	e0000000 	bsr      	0x0	// 0 <fwinfo_check_customer_id>
  34:	b801      	st.w      	r0, (r14, 0x4)
  36:	e920001c 	bnez      	r0, 0x6e	// 6e <libota_write_fw_ah+0x6e>
  3a:	1901      	addi      	r1, r14, 4
  3c:	6c1b      	mov      	r0, r6
  3e:	e0000000 	bsr      	0x0	// 0 <fwinfo_get_fw_lenght>
  42:	d9642000 	ld.w      	r11, (r4, 0x0)
  46:	6e43      	mov      	r9, r0
  48:	e92b0053 	bnez      	r11, 0xee	// ee <libota_write_fw_ah+0xee>
  4c:	3092      	movi      	r0, 146
  4e:	4001      	lsli      	r0, r0, 1
  50:	e0000000 	bsr      	0x0	// 0 <_os_malloc>
  54:	b400      	st.w      	r0, (r4, 0x0)
  56:	e9000013 	bez      	r0, 0x7c	// 7c <libota_write_fw_ah+0x7c>
  5a:	e0000000 	bsr      	0x0	// 0 <libota_write_fw_ah>
  5e:	6e83      	mov      	r10, r0
  60:	e9000016 	bez      	r0, 0x8c	// 8c <libota_write_fw_ah+0x8c>
  64:	9400      	ld.w      	r0, (r4, 0x0)
  66:	e0000000 	bsr      	0x0	// 0 <_os_free>
  6a:	dd642000 	st.w      	r11, (r4, 0x0)
  6e:	9400      	ld.w      	r0, (r4, 0x0)
  70:	e9000006 	bez      	r0, 0x7c	// 7c <libota_write_fw_ah+0x7c>
  74:	e0000000 	bsr      	0x0	// 0 <_os_free>
  78:	3300      	movi      	r3, 0
  7a:	b460      	st.w      	r3, (r4, 0x0)
  7c:	d8680001 	ld.b      	r3, (r8, 0x1)
  80:	3200      	movi      	r2, 0
  82:	c4625c03 	ins      	r3, r2, 3, 3
  86:	dc680001 	st.b      	r3, (r8, 0x1)
  8a:	0462      	br      	0x14e	// 14e <libota_write_fw_ah+0x14e>
  8c:	9460      	ld.w      	r3, (r4, 0x0)
  8e:	b8a3      	st.w      	r5, (r14, 0xc)
  90:	9300      	ld.w      	r0, (r3, 0x0)
  92:	b304      	st.w      	r0, (r3, 0x10)
  94:	b3a7      	st.w      	r5, (r3, 0x1c)
  96:	e0000000 	bsr      	0x0	// 0 <spi_nor_open>
  9a:	e92000fa 	bnez      	r0, 0x28e	// 28e <libota_write_fw_ah+0x28e>
  9e:	9400      	ld.w      	r0, (r4, 0x0)
  a0:	9062      	ld.w      	r3, (r0, 0x8)
  a2:	9021      	ld.w      	r1, (r0, 0x4)
  a4:	b025      	st.w      	r1, (r0, 0x14)
  a6:	e9030010 	bez      	r3, 0xc6	// c6 <libota_write_fw_ah+0xc6>
  aa:	3302      	movi      	r3, 2
  ac:	1a03      	addi      	r2, r14, 12
  ae:	9004      	ld.w      	r0, (r0, 0x10)
  b0:	e0000000 	bsr      	0x0	// 0 <spi_nor_read>
  b4:	9863      	ld.w      	r3, (r14, 0xc)
  b6:	eb435a69 	cmpnei      	r3, 23145
  ba:	0806      	bt      	0xc6	// c6 <libota_write_fw_ah+0xc6>
  bc:	9460      	ld.w      	r3, (r4, 0x0)
  be:	9343      	ld.w      	r2, (r3, 0xc)
  c0:	b345      	st.w      	r2, (r3, 0x14)
  c2:	9342      	ld.w      	r2, (r3, 0x8)
  c4:	b344      	st.w      	r2, (r3, 0x10)
  c6:	9460      	ld.w      	r3, (r4, 0x0)
  c8:	9304      	ld.w      	r0, (r3, 0x10)
  ca:	e0000000 	bsr      	0x0	// 0 <spi_nor_close>
  ce:	9460      	ld.w      	r3, (r4, 0x0)
  d0:	9304      	ld.w      	r0, (r3, 0x10)
  d2:	9069      	ld.w      	r3, (r0, 0x24)
  d4:	e5431000 	subi      	r10, r3, 1
  d8:	62a4      	addu      	r10, r9
  da:	c46a802a 	divu      	r10, r10, r3
  de:	e0000000 	bsr      	0x0	// 0 <spi_nor_open>
  e2:	656a      	cmpne      	r10, r5
  e4:	0838      	bt      	0x154	// 154 <libota_write_fw_ah+0x154>
  e6:	9460      	ld.w      	r3, (r4, 0x0)
  e8:	9304      	ld.w      	r0, (r3, 0x10)
  ea:	e0000000 	bsr      	0x0	// 0 <spi_nor_close>
  ee:	9460      	ld.w      	r3, (r4, 0x0)
  f0:	8640      	ld.b      	r2, (r6, 0x0)
  f2:	a35c      	st.b      	r2, (r3, 0x1c)
  f4:	8641      	ld.b      	r2, (r6, 0x1)
  f6:	a35d      	st.b      	r2, (r3, 0x1d)
  f8:	9347      	ld.w      	r2, (r3, 0x1c)
  fa:	eb425a69 	cmpnei      	r2, 23145
  fe:	0bb8      	bt      	0x6e	// 6e <libota_write_fw_ah+0x6e>
 100:	9304      	ld.w      	r0, (r3, 0x10)
 102:	e0000000 	bsr      	0x0	// 0 <spi_nor_open>
 106:	9400      	ld.w      	r0, (r4, 0x0)
 108:	e4400023 	addi      	r2, r0, 36
 10c:	9025      	ld.w      	r1, (r0, 0x14)
 10e:	3302      	movi      	r3, 2
 110:	9004      	ld.w      	r0, (r0, 0x10)
 112:	e0000000 	bsr      	0x0	// 0 <spi_nor_read>
 116:	9460      	ld.w      	r3, (r4, 0x0)
 118:	9304      	ld.w      	r0, (r3, 0x10)
 11a:	e0000000 	bsr      	0x0	// 0 <spi_nor_close>
 11e:	9460      	ld.w      	r3, (r4, 0x0)
 120:	d8430024 	ld.b      	r2, (r3, 0x24)
 124:	eb4200ff 	cmpnei      	r2, 255
 128:	0ba3      	bt      	0x6e	// 6e <libota_write_fw_ah+0x6e>
 12a:	d8430025 	ld.b      	r2, (r3, 0x25)
 12e:	eb4200ff 	cmpnei      	r2, 255
 132:	0b9e      	bt      	0x6e	// 6e <libota_write_fw_ah+0x6e>
 134:	5fa7      	subi      	r5, r7, 2
 136:	75d5      	zexth      	r7, r5
 138:	3502      	movi      	r5, 2
 13a:	2601      	addi      	r6, 2
 13c:	b3a6      	st.w      	r5, (r3, 0x18)
 13e:	9400      	ld.w      	r0, (r4, 0x0)
 140:	e900ff9e 	bez      	r0, 0x7c	// 7c <libota_write_fw_ah+0x7c>
 144:	9066      	ld.w      	r3, (r0, 0x18)
 146:	64d4      	cmphs      	r5, r3
 148:	0810      	bt      	0x168	// 168 <libota_write_fw_ah+0x168>
 14a:	3300      	movi      	r3, 0
 14c:	b861      	st.w      	r3, (r14, 0x4)
 14e:	9801      	ld.w      	r0, (r14, 0x4)
 150:	1404      	addi      	r14, r14, 16
 152:	1498      	pop      	r4-r11, r15
 154:	9440      	ld.w      	r2, (r4, 0x0)
 156:	9204      	ld.w      	r0, (r2, 0x10)
 158:	9225      	ld.w      	r1, (r2, 0x14)
 15a:	9069      	ld.w      	r3, (r0, 0x24)
 15c:	7cd4      	mult      	r3, r5
 15e:	604c      	addu      	r1, r3
 160:	e0000000 	bsr      	0x0	// 0 <spi_nor_sector_erase>
 164:	2500      	addi      	r5, 1
 166:	07be      	br      	0xe2	// e2 <libota_write_fw_ah+0xe2>
 168:	654c      	cmphs      	r3, r5
 16a:	0f85      	bf      	0x74	// 74 <libota_write_fw_ah+0x74>
 16c:	e907002b 	bez      	r7, 0x1c2	// 1c2 <libota_write_fw_ah+0x1c2>
 170:	9004      	ld.w      	r0, (r0, 0x10)
 172:	e0000000 	bsr      	0x0	// 0 <spi_nor_open>
 176:	9400      	ld.w      	r0, (r4, 0x0)
 178:	6cdf      	mov      	r3, r7
 17a:	9025      	ld.w      	r1, (r0, 0x14)
 17c:	6c9b      	mov      	r2, r6
 17e:	6054      	addu      	r1, r5
 180:	9004      	ld.w      	r0, (r0, 0x10)
 182:	e0000000 	bsr      	0x0	// 0 <spi_nor_write>
 186:	6e9f      	mov      	r10, r7
 188:	c4c5008b 	subu      	r11, r5, r6
 18c:	9400      	ld.w      	r0, (r4, 0x0)
 18e:	eb0a0100 	cmphsi      	r10, 257
 192:	c5660021 	addu      	r1, r6, r11
 196:	d9802005 	ld.w      	r12, (r0, 0x14)
 19a:	0850      	bt      	0x23a	// 23a <libota_write_fw_ah+0x23a>
 19c:	e4400023 	addi      	r2, r0, 36
 1a0:	6070      	addu      	r1, r12
 1a2:	6ceb      	mov      	r3, r10
 1a4:	9004      	ld.w      	r0, (r0, 0x10)
 1a6:	e0000000 	bsr      	0x0	// 0 <spi_nor_read>
 1aa:	9460      	ld.w      	r3, (r4, 0x0)
 1ac:	9304      	ld.w      	r0, (r3, 0x10)
 1ae:	e0000000 	bsr      	0x0	// 0 <spi_nor_close>
 1b2:	9400      	ld.w      	r0, (r4, 0x0)
 1b4:	6cab      	mov      	r2, r10
 1b6:	6c5b      	mov      	r1, r6
 1b8:	2023      	addi      	r0, 36
 1ba:	e0000000 	bsr      	0x0	// 0 <memcmp>
 1be:	e920ff58 	bnez      	r0, 0x6e	// 6e <libota_write_fw_ah+0x6e>
 1c2:	9460      	ld.w      	r3, (r4, 0x0)
 1c4:	615c      	addu      	r5, r7
 1c6:	9346      	ld.w      	r2, (r3, 0x18)
 1c8:	6566      	cmpne      	r9, r5
 1ca:	609c      	addu      	r2, r7
 1cc:	b346      	st.w      	r2, (r3, 0x18)
 1ce:	0bbe      	bt      	0x14a	// 14a <libota_write_fw_ah+0x14a>
 1d0:	9304      	ld.w      	r0, (r3, 0x10)
 1d2:	3500      	movi      	r5, 0
 1d4:	b8a2      	st.w      	r5, (r14, 0x8)
 1d6:	e0000000 	bsr      	0x0	// 0 <spi_nor_open>
 1da:	9400      	ld.w      	r0, (r4, 0x0)
 1dc:	e440001b 	addi      	r2, r0, 28
 1e0:	9025      	ld.w      	r1, (r0, 0x14)
 1e2:	3302      	movi      	r3, 2
 1e4:	9004      	ld.w      	r0, (r0, 0x10)
 1e6:	e0000000 	bsr      	0x0	// 0 <spi_nor_write>
 1ea:	9400      	ld.w      	r0, (r4, 0x0)
 1ec:	3302      	movi      	r3, 2
 1ee:	9025      	ld.w      	r1, (r0, 0x14)
 1f0:	1a02      	addi      	r2, r14, 8
 1f2:	9004      	ld.w      	r0, (r0, 0x10)
 1f4:	e0000000 	bsr      	0x0	// 0 <spi_nor_read>
 1f8:	9862      	ld.w      	r3, (r14, 0x8)
 1fa:	eb435a69 	cmpnei      	r3, 23145
 1fe:	9460      	ld.w      	r3, (r4, 0x0)
 200:	9304      	ld.w      	r0, (r3, 0x10)
 202:	0831      	bt      	0x264	// 264 <libota_write_fw_ah+0x264>
 204:	e0000000 	bsr      	0x0	// 0 <spi_nor_close>
 208:	9460      	ld.w      	r3, (r4, 0x0)
 20a:	b8a3      	st.w      	r5, (r14, 0xc)
 20c:	9302      	ld.w      	r0, (r3, 0x8)
 20e:	e9000013 	bez      	r0, 0x234	// 234 <libota_write_fw_ah+0x234>
 212:	9325      	ld.w      	r1, (r3, 0x14)
 214:	9341      	ld.w      	r2, (r3, 0x4)
 216:	6486      	cmpne      	r1, r2
 218:	082e      	bt      	0x274	// 274 <libota_write_fw_ah+0x274>
 21a:	e0000000 	bsr      	0x0	// 0 <spi_nor_open>
 21e:	9400      	ld.w      	r0, (r4, 0x0)
 220:	3304      	movi      	r3, 4
 222:	9023      	ld.w      	r1, (r0, 0xc)
 224:	1a03      	addi      	r2, r14, 12
 226:	9002      	ld.w      	r0, (r0, 0x8)
 228:	e0000000 	bsr      	0x0	// 0 <spi_nor_write>
 22c:	9460      	ld.w      	r3, (r4, 0x0)
 22e:	9302      	ld.w      	r0, (r3, 0x8)
 230:	e0000000 	bsr      	0x0	// 0 <spi_nor_close>
 234:	3300      	movi      	r3, 0
 236:	b861      	st.w      	r3, (r14, 0x4)
 238:	071b      	br      	0x6e	// 6e <libota_write_fw_ah+0x6e>
 23a:	3380      	movi      	r3, 128
 23c:	e4400023 	addi      	r2, r0, 36
 240:	6070      	addu      	r1, r12
 242:	4361      	lsli      	r3, r3, 1
 244:	9004      	ld.w      	r0, (r0, 0x10)
 246:	e0000000 	bsr      	0x0	// 0 <spi_nor_read>
 24a:	9460      	ld.w      	r3, (r4, 0x0)
 24c:	3280      	movi      	r2, 128
 24e:	e4030023 	addi      	r0, r3, 36
 252:	4241      	lsli      	r2, r2, 1
 254:	6c5b      	mov      	r1, r6
 256:	b860      	st.w      	r3, (r14, 0x0)
 258:	e0000000 	bsr      	0x0	// 0 <memcmp>
 25c:	9860      	ld.w      	r3, (r14, 0x0)
 25e:	e9000006 	bez      	r0, 0x26a	// 26a <libota_write_fw_ah+0x26a>
 262:	9304      	ld.w      	r0, (r3, 0x10)
 264:	e0000000 	bsr      	0x0	// 0 <spi_nor_close>
 268:	0703      	br      	0x6e	// 6e <libota_write_fw_ah+0x6e>
 26a:	e54a10ff 	subi      	r10, r10, 256
 26e:	76a9      	zexth      	r10, r10
 270:	26ff      	addi      	r6, 256
 272:	078d      	br      	0x18c	// 18c <libota_write_fw_ah+0x18c>
 274:	9300      	ld.w      	r0, (r3, 0x0)
 276:	e0000000 	bsr      	0x0	// 0 <spi_nor_open>
 27a:	9400      	ld.w      	r0, (r4, 0x0)
 27c:	3304      	movi      	r3, 4
 27e:	9021      	ld.w      	r1, (r0, 0x4)
 280:	1a03      	addi      	r2, r14, 12
 282:	9000      	ld.w      	r0, (r0, 0x0)
 284:	e0000000 	bsr      	0x0	// 0 <spi_nor_write>
 288:	9460      	ld.w      	r3, (r4, 0x0)
 28a:	9300      	ld.w      	r0, (r3, 0x0)
 28c:	07d2      	br      	0x230	// 230 <libota_write_fw_ah+0x230>
 28e:	9400      	ld.w      	r0, (r4, 0x0)
 290:	e0000000 	bsr      	0x0	// 0 <_os_free>
 294:	dd442000 	st.w      	r10, (r4, 0x0)
 298:	06eb      	br      	0x6e	// 6e <libota_write_fw_ah+0x6e>
	...
