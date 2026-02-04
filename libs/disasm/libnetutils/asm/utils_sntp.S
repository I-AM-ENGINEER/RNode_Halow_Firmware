
disasm/libnetutils/obj/utils_sntp.o:     file format elf32-csky-little


Disassembly of section .text.sntp_client_work:

00000000 <sntp_client_work>:
   0:	14d4      	push      	r4-r7, r15
   2:	1435      	subi      	r14, r14, 84
   4:	1281      	lrw      	r4, 0x0	// 108 <sntp_client_work+0x108>
   6:	3000      	movi      	r0, 0
   8:	e0000000 	bsr      	0x0	// 0 <dns_getserver>
   c:	846e      	ld.b      	r3, (r4, 0xe)
   e:	e4632001 	andi      	r3, r3, 1
  12:	e9230022 	bnez      	r3, 0x56	// 56 <sntp_client_work+0x56>
  16:	9442      	ld.w      	r2, (r4, 0x8)
  18:	2a00      	subi      	r2, 1
  1a:	2b02      	subi      	r3, 3
  1c:	648c      	cmphs      	r3, r2
  1e:	0822      	bt      	0x62	// 62 <sntp_client_work+0x62>
  20:	e9000070 	bez      	r0, 0x100	// 100 <sntp_client_work+0x100>
  24:	9060      	ld.w      	r3, (r0, 0x0)
  26:	e903006d 	bez      	r3, 0x100	// 100 <sntp_client_work+0x100>
  2a:	9401      	ld.w      	r0, (r4, 0x4)
  2c:	e900006a 	bez      	r0, 0x100	// 100 <sntp_client_work+0x100>
  30:	e0000000 	bsr      	0x0	// 0 <gethostbyname_async>
  34:	e9000011 	bez      	r0, 0x56	// 56 <sntp_client_work+0x56>
  38:	9064      	ld.w      	r3, (r0, 0x10)
  3a:	9360      	ld.w      	r3, (r3, 0x0)
  3c:	e903000d 	bez      	r3, 0x56	// 56 <sntp_client_work+0x56>
  40:	9360      	ld.w      	r3, (r3, 0x0)
  42:	5c1e      	addi      	r0, r4, 8
  44:	94a1      	ld.w      	r5, (r4, 0x4)
  46:	b462      	st.w      	r3, (r4, 0x8)
  48:	e0000000 	bsr      	0x0	// 0 <ip4addr_ntoa>
  4c:	6c83      	mov      	r2, r0
  4e:	6c57      	mov      	r1, r5
  50:	110f      	lrw      	r0, 0x0	// 10c <sntp_client_work+0x10c>
  52:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  56:	9442      	ld.w      	r2, (r4, 0x8)
  58:	3300      	movi      	r3, 0
  5a:	2a00      	subi      	r2, 1
  5c:	2b02      	subi      	r3, 3
  5e:	648c      	cmphs      	r3, r2
  60:	0c50      	bf      	0x100	// 100 <sntp_client_work+0x100>
  62:	84ae      	ld.b      	r5, (r4, 0xe)
  64:	e4a52001 	andi      	r5, r5, 1
  68:	e9250044 	bnez      	r5, 0xf0	// f0 <sntp_client_work+0xf0>
  6c:	1e05      	addi      	r6, r14, 20
  6e:	3710      	movi      	r7, 16
  70:	6c9f      	mov      	r2, r7
  72:	6c57      	mov      	r1, r5
  74:	6c1b      	mov      	r0, r6
  76:	e0000000 	bsr      	0x0	// 0 <memset>
  7a:	3302      	movi      	r3, 2
  7c:	8c01      	ld.h      	r0, (r4, 0x2)
  7e:	a661      	st.b      	r3, (r6, 0x1)
  80:	e0000000 	bsr      	0x0	// 0 <lwip_htons>
  84:	ae01      	st.h      	r0, (r6, 0x2)
  86:	9462      	ld.w      	r3, (r4, 0x8)
  88:	3230      	movi      	r2, 48
  8a:	6c57      	mov      	r1, r5
  8c:	1809      	addi      	r0, r14, 36
  8e:	b661      	st.w      	r3, (r6, 0x4)
  90:	e0000000 	bsr      	0x0	// 0 <memset>
  94:	3203      	movi      	r2, 3
  96:	d86e0024 	ld.b      	r3, (r14, 0x24)
  9a:	c4625c43 	ins      	r3, r2, 5, 3
  9e:	c4625c40 	ins      	r3, r2, 2, 0
  a2:	6c57      	mov      	r1, r5
  a4:	1802      	addi      	r0, r14, 8
  a6:	dc6e0024 	st.b      	r3, (r14, 0x24)
  aa:	e0000000 	bsr      	0x0	// 0 <gettimeofday>
  ae:	1079      	lrw      	r3, 0x83aa7e80	// 110 <sntp_client_work+0x110>
  b0:	9802      	ld.w      	r0, (r14, 0x8)
  b2:	600c      	addu      	r0, r3
  b4:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  b8:	b813      	st.w      	r0, (r14, 0x4c)
  ba:	9803      	ld.w      	r0, (r14, 0xc)
  bc:	9824      	ld.w      	r1, (r14, 0x10)
  be:	e0000000 	bsr      	0x0	// 0 <__floatundidf>
  c2:	3200      	movi      	r2, 0
  c4:	1074      	lrw      	r3, 0x412e8480	// 114 <sntp_client_work+0x114>
  c6:	e0000000 	bsr      	0x0	// 0 <__divdf3>
  ca:	3200      	movi      	r2, 0
  cc:	ea2341f0 	movih      	r3, 16880
  d0:	e0000000 	bsr      	0x0	// 0 <__muldf3>
  d4:	e0000000 	bsr      	0x0	// 0 <__fixunsdfdi>
  d8:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  dc:	b814      	st.w      	r0, (r14, 0x50)
  de:	b8e1      	st.w      	r7, (r14, 0x4)
  e0:	d8045000 	ld.hs      	r0, (r4, 0x0)
  e4:	b8c0      	st.w      	r6, (r14, 0x0)
  e6:	6cd7      	mov      	r3, r5
  e8:	3230      	movi      	r2, 48
  ea:	1909      	addi      	r1, r14, 36
  ec:	e0000000 	bsr      	0x0	// 0 <sendto>
  f0:	ea011388 	movi      	r1, 5000
  f4:	1009      	lrw      	r0, 0x0	// 118 <os_run_work_delay+0x118>
  f6:	e0000000 	bsr      	0x0	// 0 <os_run_work_delay>
  fa:	3000      	movi      	r0, 0
  fc:	1415      	addi      	r14, r14, 84
  fe:	1494      	pop      	r4-r7, r15
 100:	31fa      	movi      	r1, 250
 102:	4122      	lsli      	r1, r1, 2
 104:	07f8      	br      	0xf4	// f4 <sntp_client_work+0xf4>
	...
 10e:	0000      	.short	0x0000
 110:	83aa7e80 	.long	0x83aa7e80
 114:	412e8480 	.long	0x412e8480
 118:	00000000 	.long	0x00000000

Disassembly of section .text.sntp_skmonitor_cb:

00000000 <sntp_skmonitor_cb>:
   0:	14d8      	push      	r4-r11, r15
   2:	1438      	subi      	r14, r14, 96
   4:	e4212001 	andi      	r1, r1, 1
   8:	e90100fe 	bez      	r1, 0x204	// 204 <sntp_skmonitor_cb+0x204>
   c:	1b04      	addi      	r3, r14, 16
   e:	b861      	st.w      	r3, (r14, 0x4)
  10:	3230      	movi      	r2, 48
  12:	1b08      	addi      	r3, r14, 32
  14:	b860      	st.w      	r3, (r14, 0x0)
  16:	c44e0021 	addu      	r1, r14, r2
  1a:	3300      	movi      	r3, 0
  1c:	e0000000 	bsr      	0x0	// 0 <recvfrom>
  20:	e96000f2 	blsz      	r0, 0x204	// 204 <sntp_skmonitor_cb+0x204>
  24:	13b9      	lrw      	r5, 0x0	// 208 <sntp_skmonitor_cb+0x208>
  26:	858e      	ld.b      	r4, (r5, 0xe)
  28:	e4842001 	andi      	r4, r4, 1
  2c:	e92400ec 	bnez      	r4, 0x204	// 204 <sntp_skmonitor_cb+0x204>
  30:	6c53      	mov      	r1, r4
  32:	1805      	addi      	r0, r14, 20
  34:	e0000000 	bsr      	0x0	// 0 <gettimeofday>
  38:	9812      	ld.w      	r0, (r14, 0x48)
  3a:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  3e:	6e03      	mov      	r8, r0
  40:	9813      	ld.w      	r0, (r14, 0x4c)
  42:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  46:	e0000000 	bsr      	0x0	// 0 <__floatunsidf>
  4a:	3200      	movi      	r2, 0
  4c:	1370      	lrw      	r3, 0x412e8480	// 20c <sntp_skmonitor_cb+0x20c>
  4e:	e0000000 	bsr      	0x0	// 0 <__muldf3>
  52:	3200      	movi      	r2, 0
  54:	ea233df0 	movih      	r3, 15856
  58:	e0000000 	bsr      	0x0	// 0 <__muldf3>
  5c:	e0000000 	bsr      	0x0	// 0 <__fixunsdfsi>
  60:	e0000000 	bsr      	0x0	// 0 <__floatunsidf>
  64:	3200      	movi      	r2, 0
  66:	136a      	lrw      	r3, 0x412e8480	// 20c <sntp_skmonitor_cb+0x20c>
  68:	e0000000 	bsr      	0x0	// 0 <__divdf3>
  6c:	1369      	lrw      	r3, 0x7c558180	// 210 <sntp_skmonitor_cb+0x210>
  6e:	6dc3      	mov      	r7, r0
  70:	c4680020 	addu      	r0, r8, r3
  74:	6d87      	mov      	r6, r1
  76:	e0000000 	bsr      	0x0	// 0 <__floatunsidf>
  7a:	6c83      	mov      	r2, r0
  7c:	6cc7      	mov      	r3, r1
  7e:	6c1f      	mov      	r0, r7
  80:	6c5b      	mov      	r1, r6
  82:	e0000000 	bsr      	0x0	// 0 <__adddf3>
  86:	6ec3      	mov      	r11, r0
  88:	9814      	ld.w      	r0, (r14, 0x50)
  8a:	6e87      	mov      	r10, r1
  8c:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  90:	6e03      	mov      	r8, r0
  92:	9815      	ld.w      	r0, (r14, 0x54)
  94:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  98:	e0000000 	bsr      	0x0	// 0 <__floatunsidf>
  9c:	3200      	movi      	r2, 0
  9e:	127c      	lrw      	r3, 0x412e8480	// 20c <sntp_skmonitor_cb+0x20c>
  a0:	e0000000 	bsr      	0x0	// 0 <__muldf3>
  a4:	3200      	movi      	r2, 0
  a6:	ea233df0 	movih      	r3, 15856
  aa:	e0000000 	bsr      	0x0	// 0 <__muldf3>
  ae:	e0000000 	bsr      	0x0	// 0 <__fixunsdfsi>
  b2:	e0000000 	bsr      	0x0	// 0 <__floatunsidf>
  b6:	3200      	movi      	r2, 0
  b8:	1275      	lrw      	r3, 0x412e8480	// 20c <sntp_skmonitor_cb+0x20c>
  ba:	e0000000 	bsr      	0x0	// 0 <__divdf3>
  be:	1275      	lrw      	r3, 0x7c558180	// 210 <sntp_skmonitor_cb+0x210>
  c0:	6dc3      	mov      	r7, r0
  c2:	c4680020 	addu      	r0, r8, r3
  c6:	6d87      	mov      	r6, r1
  c8:	e0000000 	bsr      	0x0	// 0 <__floatunsidf>
  cc:	6c83      	mov      	r2, r0
  ce:	6cc7      	mov      	r3, r1
  d0:	6c1f      	mov      	r0, r7
  d2:	6c5b      	mov      	r1, r6
  d4:	e0000000 	bsr      	0x0	// 0 <__adddf3>
  d8:	6e43      	mov      	r9, r0
  da:	9816      	ld.w      	r0, (r14, 0x58)
  dc:	6e07      	mov      	r8, r1
  de:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  e2:	b802      	st.w      	r0, (r14, 0x8)
  e4:	9817      	ld.w      	r0, (r14, 0x5c)
  e6:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  ea:	e0000000 	bsr      	0x0	// 0 <__floatunsidf>
  ee:	3200      	movi      	r2, 0
  f0:	1267      	lrw      	r3, 0x412e8480	// 20c <sntp_skmonitor_cb+0x20c>
  f2:	e0000000 	bsr      	0x0	// 0 <__muldf3>
  f6:	3200      	movi      	r2, 0
  f8:	ea233df0 	movih      	r3, 15856
  fc:	e0000000 	bsr      	0x0	// 0 <__muldf3>
 100:	e0000000 	bsr      	0x0	// 0 <__fixunsdfsi>
 104:	e0000000 	bsr      	0x0	// 0 <__floatunsidf>
 108:	3200      	movi      	r2, 0
 10a:	1261      	lrw      	r3, 0x412e8480	// 20c <sntp_skmonitor_cb+0x20c>
 10c:	e0000000 	bsr      	0x0	// 0 <__divdf3>
 110:	d98e2002 	ld.w      	r12, (r14, 0x8)
 114:	117f      	lrw      	r3, 0x7c558180	// 210 <sntp_skmonitor_cb+0x210>
 116:	6dc3      	mov      	r7, r0
 118:	c46c0020 	addu      	r0, r12, r3
 11c:	6d87      	mov      	r6, r1
 11e:	e0000000 	bsr      	0x0	// 0 <__floatunsidf>
 122:	6c83      	mov      	r2, r0
 124:	6cc7      	mov      	r3, r1
 126:	6c1f      	mov      	r0, r7
 128:	6c5b      	mov      	r1, r6
 12a:	e0000000 	bsr      	0x0	// 0 <__adddf3>
 12e:	6dc3      	mov      	r7, r0
 130:	6d87      	mov      	r6, r1
 132:	9806      	ld.w      	r0, (r14, 0x18)
 134:	9827      	ld.w      	r1, (r14, 0x1c)
 136:	e0000000 	bsr      	0x0	// 0 <__floatundidf>
 13a:	3200      	movi      	r2, 0
 13c:	1174      	lrw      	r3, 0x412e8480	// 20c <sntp_skmonitor_cb+0x20c>
 13e:	e0000000 	bsr      	0x0	// 0 <__divdf3>
 142:	b803      	st.w      	r0, (r14, 0xc)
 144:	9805      	ld.w      	r0, (r14, 0x14)
 146:	b822      	st.w      	r1, (r14, 0x8)
 148:	e0000000 	bsr      	0x0	// 0 <__floatunsidf>
 14c:	d9ae2003 	ld.w      	r13, (r14, 0xc)
 150:	d98e2002 	ld.w      	r12, (r14, 0x8)
 154:	6c83      	mov      	r2, r0
 156:	6cc7      	mov      	r3, r1
 158:	6c37      	mov      	r0, r13
 15a:	6c73      	mov      	r1, r12
 15c:	e0000000 	bsr      	0x0	// 0 <__adddf3>
 160:	6c83      	mov      	r2, r0
 162:	6cc7      	mov      	r3, r1
 164:	6c1f      	mov      	r0, r7
 166:	6c5b      	mov      	r1, r6
 168:	e0000000 	bsr      	0x0	// 0 <__subdf3>
 16c:	6dc3      	mov      	r7, r0
 16e:	6d87      	mov      	r6, r1
 170:	6ceb      	mov      	r3, r10
 172:	6caf      	mov      	r2, r11
 174:	6c27      	mov      	r0, r9
 176:	6c63      	mov      	r1, r8
 178:	e0000000 	bsr      	0x0	// 0 <__subdf3>
 17c:	6c83      	mov      	r2, r0
 17e:	6cc7      	mov      	r3, r1
 180:	6c1f      	mov      	r0, r7
 182:	6c5b      	mov      	r1, r6
 184:	e0000000 	bsr      	0x0	// 0 <__adddf3>
 188:	3200      	movi      	r2, 0
 18a:	ea233fe0 	movih      	r3, 16352
 18e:	e0000000 	bsr      	0x0	// 0 <__muldf3>
 192:	6dc3      	mov      	r7, r0
 194:	6d87      	mov      	r6, r1
 196:	1805      	addi      	r0, r14, 20
 198:	6c53      	mov      	r1, r4
 19a:	e0000000 	bsr      	0x0	// 0 <gettimeofday>
 19e:	6c5b      	mov      	r1, r6
 1a0:	6c1f      	mov      	r0, r7
 1a2:	e0000000 	bsr      	0x0	// 0 <__fixdfsi>
 1a6:	9865      	ld.w      	r3, (r14, 0x14)
 1a8:	60c0      	addu      	r3, r0
 1aa:	6e03      	mov      	r8, r0
 1ac:	9806      	ld.w      	r0, (r14, 0x18)
 1ae:	9827      	ld.w      	r1, (r14, 0x1c)
 1b0:	b865      	st.w      	r3, (r14, 0x14)
 1b2:	e0000000 	bsr      	0x0	// 0 <__floatundidf>
 1b6:	6e83      	mov      	r10, r0
 1b8:	6c23      	mov      	r0, r8
 1ba:	6e47      	mov      	r9, r1
 1bc:	e0000000 	bsr      	0x0	// 0 <__floatsidf>
 1c0:	6c83      	mov      	r2, r0
 1c2:	6cc7      	mov      	r3, r1
 1c4:	6c1f      	mov      	r0, r7
 1c6:	6c5b      	mov      	r1, r6
 1c8:	e0000000 	bsr      	0x0	// 0 <__subdf3>
 1cc:	6c83      	mov      	r2, r0
 1ce:	6cc7      	mov      	r3, r1
 1d0:	6c2b      	mov      	r0, r10
 1d2:	6c67      	mov      	r1, r9
 1d4:	e0000000 	bsr      	0x0	// 0 <__adddf3>
 1d8:	e0000000 	bsr      	0x0	// 0 <__fixunsdfdi>
 1dc:	b806      	st.w      	r0, (r14, 0x18)
 1de:	b827      	st.w      	r1, (r14, 0x1c)
 1e0:	6c53      	mov      	r1, r4
 1e2:	1805      	addi      	r0, r14, 20
 1e4:	e0000000 	bsr      	0x0	// 0 <settimeofday>
 1e8:	9846      	ld.w      	r2, (r14, 0x18)
 1ea:	9867      	ld.w      	r3, (r14, 0x1c)
 1ec:	9825      	ld.w      	r1, (r14, 0x14)
 1ee:	100a      	lrw      	r0, 0x0	// 214 <sntp_skmonitor_cb+0x214>
 1f0:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 1f4:	33fa      	movi      	r3, 250
 1f6:	8d26      	ld.h      	r1, (r5, 0xc)
 1f8:	4362      	lsli      	r3, r3, 2
 1fa:	7c4c      	mult      	r1, r3
 1fc:	e405000f 	addi      	r0, r5, 16
 200:	e0000000 	bsr      	0x0	// 0 <os_run_work_delay>
 204:	1418      	addi      	r14, r14, 96
 206:	1498      	pop      	r4-r11, r15
 208:	00000000 	.long	0x00000000
 20c:	412e8480 	.long	0x412e8480
 210:	7c558180 	.long	0x7c558180
 214:	00000000 	.long	0x00000000

Disassembly of section .text.sntp_set_server:

00000000 <sntp_set_server>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9000015 	bez      	r0, 0x2e	// 2e <sntp_set_server+0x2e>
   8:	8060      	ld.b      	r3, (r0, 0x0)
   a:	e9030012 	bez      	r3, 0x2e	// 2e <sntp_set_server+0x2e>
   e:	1089      	lrw      	r4, 0x0	// 30 <sntp_set_server+0x30>
  10:	9401      	ld.w      	r0, (r4, 0x4)
  12:	e9000006 	bez      	r0, 0x1e	// 1e <sntp_set_server+0x1e>
  16:	e0000000 	bsr      	0x0	// 0 <_os_free>
  1a:	3300      	movi      	r3, 0
  1c:	b461      	st.w      	r3, (r4, 0x4)
  1e:	6c17      	mov      	r0, r5
  20:	e0000000 	bsr      	0x0	// 0 <os_strdup>
  24:	b401      	st.w      	r0, (r4, 0x4)
  26:	6c17      	mov      	r0, r5
  28:	e0000000 	bsr      	0x0	// 0 <ipaddr_addr>
  2c:	b402      	st.w      	r0, (r4, 0x8)
  2e:	1492      	pop      	r4-r5, r15
  30:	00000000 	.long	0x00000000

Disassembly of section .text.sntp_set_sport:

00000000 <sntp_set_sport>:
   0:	1062      	lrw      	r3, 0x0	// 8 <sntp_set_sport+0x8>
   2:	ab01      	st.h      	r0, (r3, 0x2)
   4:	783c      	jmp      	r15
   6:	0000      	.short	0x0000
   8:	0000      	.short	0x0000
	...

Disassembly of section .text.sntp_set_interval:

00000000 <sntp_set_interval>:
   0:	380a      	cmphsi      	r0, 11
   2:	0c03      	bf      	0x8	// 8 <sntp_set_interval+0x8>
   4:	1062      	lrw      	r3, 0x0	// c <sntp_set_interval+0xc>
   6:	ab06      	st.h      	r0, (r3, 0xc)
   8:	783c      	jmp      	r15
   a:	0000      	.short	0x0000
   c:	00000000 	.long	0x00000000

Disassembly of section .text.sntp_client_fresh:

00000000 <sntp_client_fresh>:
   0:	14d0      	push      	r15
   2:	1003      	lrw      	r0, 0x0	// c <sntp_client_fresh+0xc>
   4:	e0000000 	bsr      	0x0	// 0 <os_run_work>
   8:	1490      	pop      	r15
   a:	0000      	.short	0x0000
   c:	00000000 	.long	0x00000000

Disassembly of section .text.sntp_client_disable:

00000000 <sntp_client_disable>:
   0:	1063      	lrw      	r3, 0x0	// c <sntp_client_disable+0xc>
   2:	834e      	ld.b      	r2, (r3, 0xe)
   4:	c4405c00 	ins      	r2, r0, 0, 0
   8:	a34e      	st.b      	r2, (r3, 0xe)
   a:	783c      	jmp      	r15
   c:	00000000 	.long	0x00000000

Disassembly of section .text.sntp_client_init:

00000000 <sntp_client_init>:
   0:	14d5      	push      	r4-r8, r15
   2:	1424      	subi      	r14, r14, 16
   4:	6d87      	mov      	r6, r1
   6:	3102      	movi      	r1, 2
   8:	6e03      	mov      	r8, r0
   a:	3200      	movi      	r2, 0
   c:	6c07      	mov      	r0, r1
   e:	e0000000 	bsr      	0x0	// 0 <socket>
  12:	3700      	movi      	r7, 0
  14:	7503      	sexth      	r4, r0
  16:	2f00      	subi      	r7, 1
  18:	11a8      	lrw      	r5, 0x0	// b8 <sntp_client_init+0xb8>
  1a:	65d2      	cmpne      	r4, r7
  1c:	ad80      	st.h      	r4, (r5, 0x0)
  1e:	0807      	bt      	0x2c	// 2c <sntp_client_init+0x2c>
  20:	1107      	lrw      	r0, 0x0	// bc <sntp_client_init+0xbc>
  22:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  26:	6c13      	mov      	r0, r4
  28:	1404      	addi      	r14, r14, 16
  2a:	1495      	pop      	r4-r8, r15
  2c:	3280      	movi      	r2, 128
  2e:	4244      	lsli      	r2, r2, 4
  30:	3104      	movi      	r1, 4
  32:	6c13      	mov      	r0, r4
  34:	e0000000 	bsr      	0x0	// 0 <fcntl>
  38:	3210      	movi      	r2, 16
  3a:	3100      	movi      	r1, 0
  3c:	6c3b      	mov      	r0, r14
  3e:	e0000000 	bsr      	0x0	// 0 <memset>
  42:	3302      	movi      	r3, 2
  44:	3210      	movi      	r2, 16
  46:	6c7b      	mov      	r1, r14
  48:	d8055000 	ld.hs      	r0, (r5, 0x0)
  4c:	dc6e0001 	st.b      	r3, (r14, 0x1)
  50:	e0000000 	bsr      	0x0	// 0 <bind>
  54:	65c2      	cmpne      	r0, r7
  56:	6d03      	mov      	r4, r0
  58:	080a      	bt      	0x6c	// 6c <sntp_client_init+0x6c>
  5a:	101a      	lrw      	r0, 0x0	// c0 <sntp_client_init+0xc0>
  5c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  60:	d8055000 	ld.hs      	r0, (r5, 0x0)
  64:	e0000000 	bsr      	0x0	// 0 <closesocket>
  68:	ad80      	st.h      	r4, (r5, 0x0)
  6a:	07de      	br      	0x26	// 26 <sntp_client_init+0x26>
  6c:	337b      	movi      	r3, 123
  6e:	ad61      	st.h      	r3, (r5, 0x2)
  70:	33e1      	movi      	r3, 225
  72:	3e0a      	cmphsi      	r6, 11
  74:	4364      	lsli      	r3, r3, 4
  76:	c4c30c20 	incf      	r6, r3, 0
  7a:	6c23      	mov      	r0, r8
  7c:	adc6      	st.h      	r6, (r5, 0xc)
  7e:	e0000000 	bsr      	0x0	// 0 <os_strdup>
  82:	b501      	st.w      	r0, (r5, 0x4)
  84:	6c23      	mov      	r0, r8
  86:	e0000000 	bsr      	0x0	// 0 <ipaddr_addr>
  8a:	106f      	lrw      	r3, 0x0	// c4 <sntp_client_init+0xc4>
  8c:	3400      	movi      	r4, 0
  8e:	b56b      	st.w      	r3, (r5, 0x2c)
  90:	857c      	ld.b      	r3, (r5, 0x1c)
  92:	c4645c83 	ins      	r3, r4, 7, 3
  96:	b502      	st.w      	r0, (r5, 0x8)
  98:	e405000f 	addi      	r0, r5, 16
  9c:	a57c      	st.b      	r3, (r5, 0x1c)
  9e:	e0000000 	bsr      	0x0	// 0 <os_run_work>
  a2:	6cd7      	mov      	r3, r5
  a4:	1049      	lrw      	r2, 0x0	// c8 <sntp_client_init+0xc8>
  a6:	3101      	movi      	r1, 1
  a8:	8d00      	ld.h      	r0, (r5, 0x0)
  aa:	e0000000 	bsr      	0x0	// 0 <sock_monitor_add>
  ae:	6c63      	mov      	r1, r8
  b0:	1007      	lrw      	r0, 0x0	// cc <sntp_client_init+0xcc>
  b2:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  b6:	07b8      	br      	0x26	// 56 <sntp_client_init+0x56>
	...
