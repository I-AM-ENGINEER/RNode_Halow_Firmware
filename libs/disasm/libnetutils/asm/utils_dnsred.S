
disasm/libnetutils/obj/utils_dnsred.o:     file format elf32-csky-little


Disassembly of section .text.dns_redirect_pkthook.isra.1:

00000000 <dns_redirect_pkthook.isra.1>:
   0:	14d8      	push      	r4-r11, r15
   2:	1430      	subi      	r14, r14, 64
   4:	6d8b      	mov      	r6, r2
   6:	9240      	ld.w      	r2, (r2, 0x0)
   8:	6e03      	mov      	r8, r0
   a:	8277      	ld.b      	r3, (r2, 0x17)
   c:	3b51      	cmpnei      	r3, 17
   e:	6dc7      	mov      	r7, r1
  10:	0c04      	bf      	0x18	// 18 <dns_redirect_pkthook.isra.1+0x18>
  12:	3000      	movi      	r0, 0
  14:	1410      	addi      	r14, r14, 64
  16:	1498      	pop      	r4-r11, r15
  18:	d8620024 	ld.b      	r3, (r2, 0x24)
  1c:	4368      	lsli      	r3, r3, 8
  1e:	d8220025 	ld.b      	r1, (r2, 0x25)
  22:	6cc4      	or      	r3, r1
  24:	74cf      	sexth      	r3, r3
  26:	eb430035 	cmpnei      	r3, 53
  2a:	0bf4      	bt      	0x12	// 12 <dns_redirect_pkthook.isra.1+0x12>
  2c:	d802002c 	ld.b      	r0, (r2, 0x2c)
  30:	33f0      	movi      	r3, 240
  32:	4008      	lsli      	r0, r0, 8
  34:	4368      	lsli      	r3, r3, 8
  36:	680c      	and      	r0, r3
  38:	e920ffed 	bnez      	r0, 0x12	// 12 <dns_redirect_pkthook.isra.1+0x12>
  3c:	ea8a0071 	lrw      	r10, 0x0	// 200 <dns_redirect_pkthook.isra.1+0x200>
  40:	d88a2000 	ld.w      	r4, (r10, 0x0)
  44:	e0000000 	bsr      	0x0	// 0 <dns_getserver>
  48:	9060      	ld.w      	r3, (r0, 0x0)
  4a:	e9230009 	bnez      	r3, 0x5c	// 5c <dns_redirect_pkthook.isra.1+0x5c>
  4e:	136e      	lrw      	r3, 0x0	// 204 <dns_redirect_pkthook.isra.1+0x204>
  50:	d86300d2 	ld.b      	r3, (r3, 0xd2)
  54:	e4632001 	andi      	r3, r3, 1
  58:	e923001e 	bnez      	r3, 0x94	// 94 <dns_redirect_pkthook.isra.1+0x94>
  5c:	d9262000 	ld.w      	r9, (r6, 0x0)
  60:	e5290035 	addi      	r9, r9, 54
  64:	3400      	movi      	r4, 0
  66:	ea0b002e 	movi      	r11, 46
  6a:	d8a90000 	ld.b      	r5, (r9, 0x0)
  6e:	e9250024 	bnez      	r5, 0xb6	// b6 <dns_redirect_pkthook.isra.1+0xb6>
  72:	2c00      	subi      	r4, 1
  74:	3100      	movi      	r1, 0
  76:	7512      	sextb      	r4, r4
  78:	3300      	movi      	r3, 0
  7a:	2900      	subi      	r1, 1
  7c:	1303      	lrw      	r0, 0x0	// 208 <dns_redirect_pkthook.isra.1+0x208>
  7e:	d48e0023 	str.b      	r3, (r14, r4 << 0)
  82:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  86:	d88a2000 	ld.w      	r4, (r10, 0x0)
  8a:	e924002b 	bnez      	r4, 0xe0	// e0 <dns_redirect_pkthook.isra.1+0xe0>
  8e:	121f      	lrw      	r0, 0x0	// 208 <os_mutex_unlock+0x208>
  90:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  94:	e904ffbf 	bez      	r4, 0x12	// 12 <dns_redirect_pkthook.isra.1+0x12>
  98:	121d      	lrw      	r0, 0x0	// 20c <hgprintf+0x20c>
  9a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  9e:	9402      	ld.w      	r0, (r4, 0x8)
  a0:	e0000000 	bsr      	0x0	// 0 <lwip_netif_get_ip2>
  a4:	6e43      	mov      	r9, r0
  a6:	e9200025 	bnez      	r0, 0xf0	// f0 <dns_redirect_pkthook.isra.1+0xf0>
  aa:	9422      	ld.w      	r1, (r4, 0x8)
  ac:	1219      	lrw      	r0, 0x0	// 210 <dns_redirect_pkthook.isra.1+0x210>
  ae:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  b2:	3001      	movi      	r0, 1
  b4:	07b0      	br      	0x14	// 14 <dns_redirect_pkthook.isra.1+0x14>
  b6:	5c62      	addi      	r3, r4, 1
  b8:	60d4      	addu      	r3, r5
  ba:	3b3e      	cmplti      	r3, 31
  bc:	0fdb      	bf      	0x72	// 72 <dns_redirect_pkthook.isra.1+0x72>
  be:	6c97      	mov      	r2, r5
  c0:	e4290000 	addi      	r1, r9, 1
  c4:	c48e0020 	addu      	r0, r14, r4
  c8:	6114      	addu      	r4, r5
  ca:	e0000000 	bsr      	0x0	// 0 <memcpy>
  ce:	74d0      	zextb      	r3, r4
  d0:	5b82      	addi      	r4, r3, 1
  d2:	2500      	addi      	r5, 1
  d4:	74ce      	sextb      	r3, r3
  d6:	7512      	sextb      	r4, r4
  d8:	d46e002b 	str.b      	r11, (r14, r3 << 0)
  dc:	6254      	addu      	r9, r5
  de:	07c6      	br      	0x6a	// 6a <dns_redirect_pkthook.isra.1+0x6a>
  e0:	6c7b      	mov      	r1, r14
  e2:	9401      	ld.w      	r0, (r4, 0x4)
  e4:	e0000000 	bsr      	0x0	// 0 <strcmp>
  e8:	e900ffd3 	bez      	r0, 0x8e	// 8e <dns_redirect_pkthook.isra.1+0x8e>
  ec:	9480      	ld.w      	r4, (r4, 0x0)
  ee:	07ce      	br      	0x8a	// 8a <dns_redirect_pkthook.isra.1+0x8a>
  f0:	8e02      	ld.h      	r0, (r6, 0x4)
  f2:	200f      	addi      	r0, 16
  f4:	e0000000 	bsr      	0x0	// 0 <_os_malloc>
  f8:	6d03      	mov      	r4, r0
  fa:	e900ffdc 	bez      	r0, 0xb2	// b2 <dns_redirect_pkthook.isra.1+0xb2>
  fe:	9620      	ld.w      	r1, (r6, 0x0)
 100:	d8a1002c 	ld.b      	r5, (r1, 0x2c)
 104:	d861002d 	ld.b      	r3, (r1, 0x2d)
 108:	45a8      	lsli      	r5, r5, 8
 10a:	6d4c      	or      	r5, r3
 10c:	e4652100 	andi      	r3, r5, 256
 110:	e9230072 	bnez      	r3, 0x1f4	// 1f4 <dns_redirect_pkthook.isra.1+0x1f4>
 114:	eca58000 	ori      	r5, r5, 32768
 118:	8e42      	ld.h      	r2, (r6, 0x4)
 11a:	6c13      	mov      	r0, r4
 11c:	e0000000 	bsr      	0x0	// 0 <memcpy>
 120:	3200      	movi      	r2, 0
 122:	3101      	movi      	r1, 1
 124:	4d68      	lsri      	r3, r5, 8
 126:	dc440030 	st.b      	r2, (r4, 0x30)
 12a:	dc240031 	st.b      	r1, (r4, 0x31)
 12e:	dc64002c 	st.b      	r3, (r4, 0x2c)
 132:	dca4002d 	st.b      	r5, (r4, 0x2d)
 136:	8e62      	ld.h      	r3, (r6, 0x4)
 138:	60d0      	addu      	r3, r4
 13a:	3000      	movi      	r0, 0
 13c:	a342      	st.b      	r2, (r3, 0x2)
 13e:	a344      	st.b      	r2, (r3, 0x4)
 140:	a346      	st.b      	r2, (r3, 0x6)
 142:	a347      	st.b      	r2, (r3, 0x7)
 144:	a348      	st.b      	r2, (r3, 0x8)
 146:	a34a      	st.b      	r2, (r3, 0xa)
 148:	3204      	movi      	r2, 4
 14a:	a34b      	st.b      	r2, (r3, 0xb)
 14c:	283f      	subi      	r0, 64
 14e:	c6094842 	lsri      	r2, r9, 16
 152:	a300      	st.b      	r0, (r3, 0x0)
 154:	a323      	st.b      	r1, (r3, 0x3)
 156:	a325      	st.b      	r1, (r3, 0x5)
 158:	a34e      	st.b      	r2, (r3, 0xe)
 15a:	dd23000c 	st.b      	r9, (r3, 0xc)
 15e:	300c      	movi      	r0, 12
 160:	310a      	movi      	r1, 10
 162:	4a48      	lsri      	r2, r2, 8
 164:	c50955e9 	zext      	r9, r9, 15, 8
 168:	a301      	st.b      	r0, (r3, 0x1)
 16a:	a329      	st.b      	r1, (r3, 0x9)
 16c:	a34f      	st.b      	r2, (r3, 0xf)
 16e:	dd23000d 	st.b      	r9, (r3, 0xd)
 172:	9660      	ld.w      	r3, (r6, 0x0)
 174:	5b56      	addi      	r2, r3, 6
 176:	833b      	ld.b      	r1, (r3, 0x1b)
 178:	b848      	st.w      	r2, (r14, 0x20)
 17a:	835a      	ld.b      	r2, (r3, 0x1a)
 17c:	4130      	lsli      	r1, r1, 16
 17e:	4258      	lsli      	r2, r2, 24
 180:	6c84      	or      	r2, r1
 182:	833d      	ld.b      	r1, (r3, 0x1d)
 184:	6c84      	or      	r2, r1
 186:	833c      	ld.b      	r1, (r3, 0x1c)
 188:	4128      	lsli      	r1, r1, 8
 18a:	6c84      	or      	r2, r1
 18c:	b84a      	st.w      	r2, (r14, 0x28)
 18e:	833f      	ld.b      	r1, (r3, 0x1f)
 190:	835e      	ld.b      	r2, (r3, 0x1e)
 192:	4130      	lsli      	r1, r1, 16
 194:	4258      	lsli      	r2, r2, 24
 196:	6c84      	or      	r2, r1
 198:	d8230021 	ld.b      	r1, (r3, 0x21)
 19c:	b869      	st.w      	r3, (r14, 0x24)
 19e:	6c84      	or      	r2, r1
 1a0:	d8230020 	ld.b      	r1, (r3, 0x20)
 1a4:	4128      	lsli      	r1, r1, 8
 1a6:	6c84      	or      	r2, r1
 1a8:	b84c      	st.w      	r2, (r14, 0x30)
 1aa:	d8430022 	ld.b      	r2, (r3, 0x22)
 1ae:	d8230023 	ld.b      	r1, (r3, 0x23)
 1b2:	4248      	lsli      	r2, r2, 8
 1b4:	6c84      	or      	r2, r1
 1b6:	b84b      	st.w      	r2, (r14, 0x2c)
 1b8:	d8430024 	ld.b      	r2, (r3, 0x24)
 1bc:	4248      	lsli      	r2, r2, 8
 1be:	d8630025 	ld.b      	r3, (r3, 0x25)
 1c2:	6cc8      	or      	r3, r2
 1c4:	b86d      	st.w      	r3, (r14, 0x34)
 1c6:	e4640029 	addi      	r3, r4, 42
 1ca:	b86e      	st.w      	r3, (r14, 0x38)
 1cc:	8e62      	ld.h      	r3, (r6, 0x4)
 1ce:	2b19      	subi      	r3, 26
 1d0:	6c53      	mov      	r1, r4
 1d2:	1808      	addi      	r0, r14, 32
 1d4:	b86f      	st.w      	r3, (r14, 0x3c)
 1d6:	e0000000 	bsr      	0x0	// 0 <net_setup_udpdata>
 1da:	8e42      	ld.h      	r2, (r6, 0x4)
 1dc:	7489      	zexth      	r2, r2
 1de:	220f      	addi      	r2, 16
 1e0:	6c53      	mov      	r1, r4
 1e2:	6c1f      	mov      	r0, r7
 1e4:	e908000b 	bez      	r8, 0x1fa	// 1fa <dns_redirect_pkthook.isra.1+0x1fa>
 1e8:	e0000000 	bsr      	0x0	// 0 <ieee80211_input>
 1ec:	6c13      	mov      	r0, r4
 1ee:	e0000000 	bsr      	0x0	// 0 <_os_free>
 1f2:	0760      	br      	0xb2	// b2 <dns_redirect_pkthook.isra.1+0xb2>
 1f4:	eca58080 	ori      	r5, r5, 32896
 1f8:	0790      	br      	0x118	// 118 <ieee80211_tx+0x118>
 1fa:	e0000000 	bsr      	0x0	// 0 <ieee80211_tx>
 1fe:	07f7      	br      	0x1ec	// 1f8 <dns_redirect_pkthook.isra.1+0x1f8>
	...

Disassembly of section .text.dns_redirect_pkthook_rx:

00000000 <dns_redirect_pkthook_rx>:
   0:	14d0      	push      	r15
   2:	3000      	movi      	r0, 0
   4:	e0000000 	bsr      	0x0	// 0 <dns_redirect_pkthook_rx>
   8:	1490      	pop      	r15

Disassembly of section .text.dns_redirect_pkthook_tx:

00000000 <dns_redirect_pkthook_tx>:
   0:	14d0      	push      	r15
   2:	3001      	movi      	r0, 1
   4:	e0000000 	bsr      	0x0	// 0 <dns_redirect_pkthook_tx>
   8:	1490      	pop      	r15

Disassembly of section .text.dns_redirect_init:

00000000 <dns_redirect_init>:
   0:	14d1      	push      	r4, r15
   2:	1006      	lrw      	r0, 0x0	// 18 <dns_redirect_init+0x18>
   4:	3400      	movi      	r4, 0
   6:	b080      	st.w      	r4, (r0, 0x0)
   8:	2003      	addi      	r0, 4
   a:	e0000000 	bsr      	0x0	// 0 <os_mutex_init>
   e:	1004      	lrw      	r0, 0x0	// 1c <ieee80211_register_pkthook+0x1c>
  10:	e0000000 	bsr      	0x0	// 0 <ieee80211_register_pkthook>
  14:	6c13      	mov      	r0, r4
  16:	1491      	pop      	r4, r15
	...

Disassembly of section .text.dns_redirect_add:

00000000 <dns_redirect_add>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d83      	mov      	r6, r0
   4:	300c      	movi      	r0, 12
   6:	6d47      	mov      	r5, r1
   8:	e0000000 	bsr      	0x0	// 0 <_os_zalloc>
   c:	6d03      	mov      	r4, r0
   e:	e9000012 	bez      	r0, 0x32	// 32 <dns_redirect_add+0x32>
  12:	3100      	movi      	r1, 0
  14:	2900      	subi      	r1, 1
  16:	1009      	lrw      	r0, 0x0	// 38 <dns_redirect_add+0x38>
  18:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  1c:	1008      	lrw      	r0, 0x0	// 3c <dns_redirect_add+0x3c>
  1e:	b4c1      	st.w      	r6, (r4, 0x4)
  20:	9060      	ld.w      	r3, (r0, 0x0)
  22:	b460      	st.w      	r3, (r4, 0x0)
  24:	b4a2      	st.w      	r5, (r4, 0x8)
  26:	b080      	st.w      	r4, (r0, 0x0)
  28:	2003      	addi      	r0, 4
  2a:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  2e:	3000      	movi      	r0, 0
  30:	1493      	pop      	r4-r6, r15
  32:	3000      	movi      	r0, 0
  34:	2800      	subi      	r0, 1
  36:	07fd      	br      	0x30	// 30 <dns_redirect_add+0x30>
	...
