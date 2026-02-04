
disasm/libnetutils/obj/dhcpd_dhcpd.o:     file format elf32-csky-little


Disassembly of section .text.__put_unaligned_le32:

00000000 <__put_unaligned_le32>:
   0:	4870      	lsri      	r3, r0, 16
   2:	a162      	st.b      	r3, (r1, 0x2)
   4:	a100      	st.b      	r0, (r1, 0x0)
   6:	4b68      	lsri      	r3, r3, 8
   8:	c50055e0 	zext      	r0, r0, 15, 8
   c:	a163      	st.b      	r3, (r1, 0x3)
   e:	a101      	st.b      	r0, (r1, 0x1)
  10:	783c      	jmp      	r15

Disassembly of section .text.dhcpd_next_ip:

00000000 <dhcpd_next_ip>:
   0:	14d2      	push      	r4-r5, r15
   2:	1421      	subi      	r14, r14, 4
   4:	c4212483 	nor      	r3, r1, r1
   8:	c4032024 	and      	r4, r3, r0
   c:	10b4      	lrw      	r5, 0x0	// 5c <dhcpd_next_ip+0x5c>
   e:	2400      	addi      	r4, 1
  10:	690c      	and      	r4, r3
  12:	9560      	ld.w      	r3, (r5, 0x0)
  14:	6840      	and      	r1, r0
  16:	d803208d 	ld.w      	r0, (r3, 0x234)
  1a:	6104      	addu      	r4, r1
  1c:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  20:	6410      	cmphs      	r4, r0
  22:	0815      	bt      	0x4c	// 4c <dhcpd_next_ip+0x4c>
  24:	9560      	ld.w      	r3, (r5, 0x0)
  26:	d803208d 	ld.w      	r0, (r3, 0x234)
  2a:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  2e:	6d03      	mov      	r4, r0
  30:	e46420ff 	andi      	r3, r4, 255
  34:	b860      	st.w      	r3, (r14, 0x0)
  36:	c60456e2 	zext      	r2, r4, 23, 16
  3a:	c50455e3 	zext      	r3, r4, 15, 8
  3e:	4c38      	lsri      	r1, r4, 24
  40:	1008      	lrw      	r0, 0x0	// 60 <dhcpd_next_ip+0x60>
  42:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  46:	6c13      	mov      	r0, r4
  48:	1401      	addi      	r14, r14, 4
  4a:	1492      	pop      	r4-r5, r15
  4c:	9560      	ld.w      	r3, (r5, 0x0)
  4e:	d803208e 	ld.w      	r0, (r3, 0x238)
  52:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  56:	6500      	cmphs      	r0, r4
  58:	0fe6      	bf      	0x24	// 24 <dhcpd_next_ip+0x24>
  5a:	07eb      	br      	0x30	// 30 <dhcpd_next_ip+0x30>
	...

Disassembly of section .text.dhcpd_netcmp:

00000000 <dhcpd_netcmp>:
   0:	14d3      	push      	r4-r6, r15
   2:	10cc      	lrw      	r6, 0x0	// 30 <dhcpd_netcmp+0x30>
   4:	6d03      	mov      	r4, r0
   6:	9660      	ld.w      	r3, (r6, 0x0)
   8:	d803208f 	ld.w      	r0, (r3, 0x23c)
   c:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  10:	9660      	ld.w      	r3, (r6, 0x0)
  12:	6900      	and      	r4, r0
  14:	d803208d 	ld.w      	r0, (r3, 0x234)
  18:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  1c:	9660      	ld.w      	r3, (r6, 0x0)
  1e:	6d43      	mov      	r5, r0
  20:	d803208f 	ld.w      	r0, (r3, 0x23c)
  24:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  28:	6814      	and      	r0, r5
  2a:	6502      	cmpne      	r0, r4
  2c:	6403      	mvcv      	r0
  2e:	1493      	pop      	r4-r6, r15
  30:	00000000 	.long	0x00000000

Disassembly of section .text.dhcpd_find_ip:

00000000 <dhcpd_find_ip>:
   0:	14d4      	push      	r4-r7, r15
   2:	1074      	lrw      	r3, 0x0	// 50 <dhcpd_find_ip+0x50>
   4:	6d43      	mov      	r5, r0
   6:	9360      	ld.w      	r3, (r3, 0x0)
   8:	6d87      	mov      	r6, r1
   a:	e4e30253 	addi      	r7, r3, 596
   e:	e9200007 	bnez      	r0, 0x1c	// 1c <dhcpd_find_ip+0x1c>
  12:	e9210005 	bnez      	r1, 0x1c	// 1c <dhcpd_find_ip+0x1c>
  16:	3400      	movi      	r4, 0
  18:	6c13      	mov      	r0, r4
  1a:	1494      	pop      	r4-r7, r15
  1c:	d8832095 	ld.w      	r4, (r3, 0x254)
  20:	651e      	cmpne      	r7, r4
  22:	0ffa      	bf      	0x16	// 16 <dhcpd_find_ip+0x16>
  24:	e9250006 	bnez      	r5, 0x30	// 30 <dhcpd_find_ip+0x30>
  28:	e926000b 	bnez      	r6, 0x3e	// 3e <dhcpd_find_ip+0x3e>
  2c:	9480      	ld.w      	r4, (r4, 0x0)
  2e:	07f9      	br      	0x20	// 20 <dhcpd_find_ip+0x20>
  30:	6c17      	mov      	r0, r5
  32:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  36:	9462      	ld.w      	r3, (r4, 0x8)
  38:	64c2      	cmpne      	r0, r3
  3a:	0bf7      	bt      	0x28	// 28 <dhcpd_find_ip+0x28>
  3c:	07ee      	br      	0x18	// 18 <dhcpd_find_ip+0x18>
  3e:	3206      	movi      	r2, 6
  40:	e4240013 	addi      	r1, r4, 20
  44:	6c1b      	mov      	r0, r6
  46:	e0000000 	bsr      	0x0	// 0 <memcmp>
  4a:	e920fff1 	bnez      	r0, 0x2c	// 2c <dhcpd_find_ip+0x2c>
  4e:	07e5      	br      	0x18	// 18 <dhcpd_find_ip+0x18>
  50:	00000000 	.long	0x00000000

Disassembly of section .text.dhcpd_check_ip:

00000000 <dhcpd_check_ip>:
   0:	14d3      	push      	r4-r6, r15
   2:	1090      	lrw      	r4, 0x0	// 40 <dhcpd_check_ip+0x40>
   4:	6d87      	mov      	r6, r1
   6:	3100      	movi      	r1, 0
   8:	6d43      	mov      	r5, r0
   a:	2900      	subi      	r1, 1
   c:	9400      	ld.w      	r0, (r4, 0x0)
   e:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  12:	6c17      	mov      	r0, r5
  14:	3100      	movi      	r1, 0
  16:	e0000000 	bsr      	0x0	// 0 <dhcpd_check_ip>
  1a:	6d53      	mov      	r5, r4
  1c:	e900000f 	bez      	r0, 0x3a	// 3a <dhcpd_check_ip+0x3a>
  20:	3206      	movi      	r2, 6
  22:	6c5b      	mov      	r1, r6
  24:	2013      	addi      	r0, 20
  26:	e0000000 	bsr      	0x0	// 0 <memcmp>
  2a:	3840      	cmpnei      	r0, 0
  2c:	6503      	mvcv      	r4
  2e:	7510      	zextb      	r4, r4
  30:	9500      	ld.w      	r0, (r5, 0x0)
  32:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  36:	6c13      	mov      	r0, r4
  38:	1493      	pop      	r4-r6, r15
  3a:	3401      	movi      	r4, 1
  3c:	07fa      	br      	0x30	// 30 <dhcpd_check_ip+0x30>
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000
	...

Disassembly of section .text.dhcpd_socket_init:

00000000 <dhcpd_socket_init>:
   0:	14d4      	push      	r4-r7, r15
   2:	1428      	subi      	r14, r14, 32
   4:	12a1      	lrw      	r5, 0x0	// 108 <dhcpd_socket_init+0x108>
   6:	3301      	movi      	r3, 1
   8:	95c0      	ld.w      	r6, (r5, 0x0)
   a:	b861      	st.w      	r3, (r14, 0x4)
   c:	6dc3      	mov      	r7, r0
   e:	6d07      	mov      	r4, r1
  10:	e0000000 	bsr      	0x0	// 0 <netif_find>
  14:	dc062098 	st.w      	r0, (r6, 0x260)
  18:	95c0      	ld.w      	r6, (r5, 0x0)
  1a:	d8662098 	ld.w      	r3, (r6, 0x260)
  1e:	e923000b 	bnez      	r3, 0x34	// 34 <dhcpd_socket_init+0x34>
  22:	6c5f      	mov      	r1, r7
  24:	111a      	lrw      	r0, 0x0	// 10c <dhcpd_socket_init+0x10c>
  26:	3400      	movi      	r4, 0
  28:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  2c:	2c00      	subi      	r4, 1
  2e:	6c13      	mov      	r0, r4
  30:	1408      	addi      	r14, r14, 32
  32:	1494      	pop      	r4-r7, r15
  34:	e904000e 	bez      	r4, 0x50	// 50 <dhcpd_socket_init+0x50>
  38:	9401      	ld.w      	r0, (r4, 0x4)
  3a:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  3e:	dc062097 	st.w      	r0, (r6, 0x25c)
  42:	9500      	ld.w      	r0, (r5, 0x0)
  44:	321c      	movi      	r2, 28
  46:	6c53      	mov      	r1, r4
  48:	e400022f 	addi      	r0, r0, 560
  4c:	e0000000 	bsr      	0x0	// 0 <memcpy>
  50:	3102      	movi      	r1, 2
  52:	3200      	movi      	r2, 0
  54:	6c07      	mov      	r0, r1
  56:	3600      	movi      	r6, 0
  58:	e0000000 	bsr      	0x0	// 0 <socket>
  5c:	2e00      	subi      	r6, 1
  5e:	6582      	cmpne      	r0, r6
  60:	6d03      	mov      	r4, r0
  62:	0805      	bt      	0x6c	// 6c <dhcpd_socket_init+0x6c>
  64:	110b      	lrw      	r0, 0x0	// 110 <dhcpd_socket_init+0x110>
  66:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  6a:	07e2      	br      	0x2e	// 2e <dhcpd_socket_init+0x2e>
  6c:	3280      	movi      	r2, 128
  6e:	4244      	lsli      	r2, r2, 4
  70:	3104      	movi      	r1, 4
  72:	e0000000 	bsr      	0x0	// 0 <fcntl>
  76:	3304      	movi      	r3, 4
  78:	b860      	st.w      	r3, (r14, 0x0)
  7a:	3220      	movi      	r2, 32
  7c:	60f8      	addu      	r3, r14
  7e:	ea010fff 	movi      	r1, 4095
  82:	6c13      	mov      	r0, r4
  84:	e0000000 	bsr      	0x0	// 0 <setsockopt>
  88:	9560      	ld.w      	r3, (r5, 0x0)
  8a:	3202      	movi      	r2, 2
  8c:	d8232098 	ld.w      	r1, (r3, 0x260)
  90:	2131      	addi      	r1, 50
  92:	1802      	addi      	r0, r14, 8
  94:	e0000000 	bsr      	0x0	// 0 <strncpy>
  98:	3306      	movi      	r3, 6
  9a:	b860      	st.w      	r3, (r14, 0x0)
  9c:	ea02100b 	movi      	r2, 4107
  a0:	1b02      	addi      	r3, r14, 8
  a2:	ea010fff 	movi      	r1, 4095
  a6:	6c13      	mov      	r0, r4
  a8:	e0000000 	bsr      	0x0	// 0 <setsockopt>
  ac:	3210      	movi      	r2, 16
  ae:	3100      	movi      	r1, 0
  b0:	c44e0020 	addu      	r0, r14, r2
  b4:	e0000000 	bsr      	0x0	// 0 <memset>
  b8:	3302      	movi      	r3, 2
  ba:	3043      	movi      	r0, 67
  bc:	dc6e0011 	st.b      	r3, (r14, 0x11)
  c0:	e0000000 	bsr      	0x0	// 0 <lwip_htons>
  c4:	9560      	ld.w      	r3, (r5, 0x0)
  c6:	3210      	movi      	r2, 16
  c8:	d8632098 	ld.w      	r3, (r3, 0x260)
  cc:	dc0e1009 	st.h      	r0, (r14, 0x12)
  d0:	9361      	ld.w      	r3, (r3, 0x4)
  d2:	c44e0021 	addu      	r1, r14, r2
  d6:	6c13      	mov      	r0, r4
  d8:	b865      	st.w      	r3, (r14, 0x14)
  da:	e0000000 	bsr      	0x0	// 0 <bind>
  de:	6582      	cmpne      	r0, r6
  e0:	6dc3      	mov      	r7, r0
  e2:	0809      	bt      	0xf4	// f4 <dhcpd_socket_init+0xf4>
  e4:	100c      	lrw      	r0, 0x0	// 114 <dhcpd_socket_init+0x114>
  e6:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  ea:	6c13      	mov      	r0, r4
  ec:	e0000000 	bsr      	0x0	// 0 <closesocket>
  f0:	6d1f      	mov      	r4, r7
  f2:	079e      	br      	0x2e	// 2e <dhcpd_socket_init+0x2e>
  f4:	9560      	ld.w      	r3, (r5, 0x0)
  f6:	7411      	zexth      	r0, r4
  f8:	dc83208b 	st.w      	r4, (r3, 0x22c)
  fc:	3101      	movi      	r1, 1
  fe:	1047      	lrw      	r2, 0x0	// 118 <dhcpd_socket_init+0x118>
 100:	e0000000 	bsr      	0x0	// 0 <sock_monitor_add>
 104:	3400      	movi      	r4, 0
 106:	0794      	br      	0x2e	// 2e <dhcpd_socket_init+0x2e>
	...

Disassembly of section .text.dhcpd_send:

00000000 <dhcpd_send>:
   0:	14d6      	push      	r4-r9, r15
   2:	142a      	subi      	r14, r14, 40
   4:	6d8f      	mov      	r6, r3
   6:	6d43      	mov      	r5, r0
   8:	6e47      	mov      	r9, r1
   a:	6e0b      	mov      	r8, r2
   c:	103e      	lrw      	r1, 0x0	// 84 <dhcpd_send+0x84>
   e:	3206      	movi      	r2, 6
  10:	6c3b      	mov      	r0, r14
  12:	e0000000 	bsr      	0x0	// 0 <memcpy>
  16:	e426002d 	addi      	r1, r6, 46
  1a:	32c1      	movi      	r2, 193
  1c:	4241      	lsli      	r2, r2, 1
  1e:	7445      	zexth      	r1, r1
  20:	3000      	movi      	r0, 0
  22:	e0000000 	bsr      	0x0	// 0 <pbuf_alloc>
  26:	6dfb      	mov      	r7, r14
  28:	6d03      	mov      	r4, r0
  2a:	e900002b 	bez      	r0, 0x80	// 80 <dhcpd_send+0x80>
  2e:	3d40      	cmpnei      	r5, 0
  30:	c4ae0c20 	incf      	r5, r14, 0
  34:	b8a2      	st.w      	r5, (r14, 0x8)
  36:	6c27      	mov      	r0, r9
  38:	10b4      	lrw      	r5, 0x0	// 88 <dhcpd_send+0x88>
  3a:	9560      	ld.w      	r3, (r5, 0x0)
  3c:	d8632098 	ld.w      	r3, (r3, 0x260)
  40:	2329      	addi      	r3, 42
  42:	b863      	st.w      	r3, (r14, 0xc)
  44:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  48:	9560      	ld.w      	r3, (r5, 0x0)
  4a:	b804      	st.w      	r0, (r14, 0x10)
  4c:	d8632098 	ld.w      	r3, (r3, 0x260)
  50:	9301      	ld.w      	r0, (r3, 0x4)
  52:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  56:	3344      	movi      	r3, 68
  58:	b806      	st.w      	r0, (r14, 0x18)
  5a:	b865      	st.w      	r3, (r14, 0x14)
  5c:	9421      	ld.w      	r1, (r4, 0x4)
  5e:	3343      	movi      	r3, 67
  60:	1802      	addi      	r0, r14, 8
  62:	b867      	st.w      	r3, (r14, 0x1c)
  64:	dd0e2008 	st.w      	r8, (r14, 0x20)
  68:	b8c9      	st.w      	r6, (r14, 0x24)
  6a:	e0000000 	bsr      	0x0	// 0 <net_setup_udpdata>
  6e:	9560      	ld.w      	r3, (r5, 0x0)
  70:	6c53      	mov      	r1, r4
  72:	d8032098 	ld.w      	r0, (r3, 0x260)
  76:	9067      	ld.w      	r3, (r0, 0x1c)
  78:	7bcd      	jsr      	r3
  7a:	6c13      	mov      	r0, r4
  7c:	e0000000 	bsr      	0x0	// 0 <pbuf_free>
  80:	140a      	addi      	r14, r14, 40
  82:	1496      	pop      	r4-r9, r15
	...

Disassembly of section .text.dhcpd_send_nak:

00000000 <dhcpd_send_nak>:
   0:	14d2      	push      	r4-r5, r15
   2:	1423      	subi      	r14, r14, 12
   4:	80aa      	ld.b      	r5, (r0, 0xa)
   6:	806b      	ld.b      	r3, (r0, 0xb)
   8:	45a8      	lsli      	r5, r5, 8
   a:	6d4c      	or      	r5, r3
   c:	3302      	movi      	r3, 2
   e:	a060      	st.b      	r3, (r0, 0x0)
  10:	3335      	movi      	r3, 53
  12:	dc6000f0 	st.b      	r3, (r0, 0xf0)
  16:	3301      	movi      	r3, 1
  18:	dc6000f1 	st.b      	r3, (r0, 0xf1)
  1c:	3306      	movi      	r3, 6
  1e:	dc6000f2 	st.b      	r3, (r0, 0xf2)
  22:	3300      	movi      	r3, 0
  24:	6d03      	mov      	r4, r0
  26:	2b00      	subi      	r3, 1
  28:	dc6000f3 	st.b      	r3, (r0, 0xf3)
  2c:	805d      	ld.b      	r2, (r0, 0x1d)
  2e:	807e      	ld.b      	r3, (r0, 0x1e)
  30:	803c      	ld.b      	r1, (r0, 0x1c)
  32:	d8000021 	ld.b      	r0, (r0, 0x21)
  36:	b802      	st.w      	r0, (r14, 0x8)
  38:	d8040020 	ld.b      	r0, (r4, 0x20)
  3c:	7557      	sexth      	r5, r5
  3e:	b801      	st.w      	r0, (r14, 0x4)
  40:	841f      	ld.b      	r0, (r4, 0x1f)
  42:	b800      	st.w      	r0, (r14, 0x0)
  44:	1009      	lrw      	r0, 0x0	// 68 <dhcpd_send_nak+0x68>
  46:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  4a:	e985000c 	blz      	r5, 0x62	// 62 <dhcpd_send_nak+0x62>
  4e:	e404001b 	addi      	r0, r4, 28
  52:	3100      	movi      	r1, 0
  54:	33f4      	movi      	r3, 244
  56:	6c93      	mov      	r2, r4
  58:	2900      	subi      	r1, 1
  5a:	e0000000 	bsr      	0x0	// 0 <dhcpd_send_nak>
  5e:	1403      	addi      	r14, r14, 12
  60:	1492      	pop      	r4-r5, r15
  62:	3000      	movi      	r0, 0
  64:	07f7      	br      	0x52	// 52 <dhcpd_send_nak+0x52>
  66:	0000      	.short	0x0000
  68:	00000000 	.long	0x00000000

Disassembly of section .text.dhcpd_check_expired:

00000000 <dhcpd_check_expired>:
   0:	14d8      	push      	r4-r11, r15
   2:	1428      	subi      	r14, r14, 32
   4:	11b2      	lrw      	r5, 0x0	// cc <dhcpd_check_expired+0xcc>
   6:	6dc3      	mov      	r7, r0
   8:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
   c:	b804      	st.w      	r0, (r14, 0x10)
   e:	b825      	st.w      	r1, (r14, 0x14)
  10:	9580      	ld.w      	r4, (r5, 0x0)
  12:	3100      	movi      	r1, 0
  14:	6c13      	mov      	r0, r4
  16:	2900      	subi      	r1, 1
  18:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  1c:	e5440253 	addi      	r10, r4, 596
  20:	d8842095 	ld.w      	r4, (r4, 0x254)
  24:	ea0c00fa 	movi      	r12, 250
  28:	94c0      	ld.w      	r6, (r4, 0x0)
  2a:	ea0d0000 	movi      	r13, 0
  2e:	ea8b0029 	lrw      	r11, 0x0	// d0 <dhcpd_check_expired+0xd0>
  32:	c44c482c 	lsli      	r12, r12, 2
  36:	652a      	cmpne      	r10, r4
  38:	0806      	bt      	0x44	// 44 <dhcpd_check_expired+0x44>
  3a:	9500      	ld.w      	r0, (r5, 0x0)
  3c:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  40:	1408      	addi      	r14, r14, 32
  42:	1498      	pop      	r4-r11, r15
  44:	e9270018 	bnez      	r7, 0x74	// 74 <dhcpd_check_expired+0x74>
  48:	9560      	ld.w      	r3, (r5, 0x0)
  4a:	6e5f      	mov      	r9, r7
  4c:	d863208c 	ld.w      	r3, (r3, 0x230)
  50:	c5838428 	mult      	r8, r3, r12
  54:	9443      	ld.w      	r2, (r4, 0xc)
  56:	9464      	ld.w      	r3, (r4, 0x10)
  58:	6489      	cmplt      	r2, r2
  5a:	60a1      	addc      	r2, r8
  5c:	60e5      	addc      	r3, r9
  5e:	9804      	ld.w      	r0, (r14, 0x10)
  60:	9825      	ld.w      	r1, (r14, 0x14)
  62:	6400      	cmphs      	r0, r0
  64:	c4020100 	subc      	r0, r2, r0
  68:	c4230101 	subc      	r1, r3, r1
  6c:	6c83      	mov      	r2, r0
  6e:	6cc7      	mov      	r3, r1
  70:	e9a3002a 	bhsz      	r3, 0xc4	// c4 <dhcpd_check_expired+0xc4>
  74:	9461      	ld.w      	r3, (r4, 0x4)
  76:	9440      	ld.w      	r2, (r4, 0x0)
  78:	e9030006 	bez      	r3, 0x84	// 84 <dhcpd_check_expired+0x84>
  7c:	e9020004 	bez      	r2, 0x84	// 84 <dhcpd_check_expired+0x84>
  80:	b261      	st.w      	r3, (r2, 0x4)
  82:	b340      	st.w      	r2, (r3, 0x0)
  84:	dda42000 	st.w      	r13, (r4, 0x0)
  88:	dda42001 	st.w      	r13, (r4, 0x4)
  8c:	5c1e      	addi      	r0, r4, 8
  8e:	dd8e2007 	st.w      	r12, (r14, 0x1c)
  92:	ddae2006 	st.w      	r13, (r14, 0x18)
  96:	e0000000 	bsr      	0x0	// 0 <ip4addr_ntoa>
  9a:	8439      	ld.b      	r1, (r4, 0x19)
  9c:	8475      	ld.b      	r3, (r4, 0x15)
  9e:	8454      	ld.b      	r2, (r4, 0x14)
  a0:	b823      	st.w      	r1, (r14, 0xc)
  a2:	8438      	ld.b      	r1, (r4, 0x18)
  a4:	b822      	st.w      	r1, (r14, 0x8)
  a6:	8437      	ld.b      	r1, (r4, 0x17)
  a8:	b821      	st.w      	r1, (r14, 0x4)
  aa:	8436      	ld.b      	r1, (r4, 0x16)
  ac:	b820      	st.w      	r1, (r14, 0x0)
  ae:	6c43      	mov      	r1, r0
  b0:	6c2f      	mov      	r0, r11
  b2:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  b6:	6c13      	mov      	r0, r4
  b8:	e0000000 	bsr      	0x0	// 0 <_os_free>
  bc:	d98e2007 	ld.w      	r12, (r14, 0x1c)
  c0:	d9ae2006 	ld.w      	r13, (r14, 0x18)
  c4:	6d1b      	mov      	r4, r6
  c6:	96c0      	ld.w      	r6, (r6, 0x0)
  c8:	07b7      	br      	0x36	// 36 <dhcpd_check_expired+0x36>
	...

Disassembly of section .text.dhcpd_reply:

00000000 <dhcpd_reply>:
   0:	14d8      	push      	r4-r11, r15
   2:	142c      	subi      	r14, r14, 48
   4:	03e4      	lrw      	r7, 0x0	// 270 <dhcpd_reply+0x270>
   6:	6d03      	mov      	r4, r0
   8:	6e87      	mov      	r10, r1
   a:	9700      	ld.w      	r0, (r7, 0x0)
   c:	3100      	movi      	r1, 0
   e:	2900      	subi      	r1, 1
  10:	e504001b 	addi      	r8, r4, 28
  14:	d8c02093 	ld.w      	r6, (r0, 0x24c)
  18:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  1c:	6c63      	mov      	r1, r8
  1e:	3000      	movi      	r0, 0
  20:	e0000000 	bsr      	0x0	// 0 <dhcpd_reply>
  24:	6d43      	mov      	r5, r0
  26:	e9200072 	bnez      	r0, 0x10a	// 10a <dhcpd_reply+0x10a>
  2a:	e9260013 	bnez      	r6, 0x50	// 50 <dhcpd_reply+0x50>
  2e:	9760      	ld.w      	r3, (r7, 0x0)
  30:	d9232097 	ld.w      	r9, (r3, 0x25c)
  34:	9760      	ld.w      	r3, (r7, 0x0)
  36:	3100      	movi      	r1, 0
  38:	d8032097 	ld.w      	r0, (r3, 0x25c)
  3c:	e0000000 	bsr      	0x0	// 0 <dhcpd_reply>
  40:	97a0      	ld.w      	r5, (r7, 0x0)
  42:	e9200039 	bnez      	r0, 0xb4	// b4 <dhcpd_reply+0xb4>
  46:	d8652097 	ld.w      	r3, (r5, 0x25c)
  4a:	e9030046 	bez      	r3, 0xd6	// d6 <dhcpd_reply+0xd6>
  4e:	6d8f      	mov      	r6, r3
  50:	303c      	movi      	r0, 60
  52:	e0000000 	bsr      	0x0	// 0 <_os_zalloc>
  56:	6d43      	mov      	r5, r0
  58:	e9000069 	bez      	r0, 0x12a	// 12a <dhcpd_reply+0x12a>
  5c:	9760      	ld.w      	r3, (r7, 0x0)
  5e:	d8432095 	ld.w      	r2, (r3, 0x254)
  62:	b201      	st.w      	r0, (r2, 0x4)
  64:	b040      	st.w      	r2, (r0, 0x0)
  66:	e4430253 	addi      	r2, r3, 596
  6a:	b041      	st.w      	r2, (r0, 0x4)
  6c:	dc032095 	st.w      	r0, (r3, 0x254)
  70:	6c1b      	mov      	r0, r6
  72:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  76:	857a      	ld.b      	r3, (r5, 0x1a)
  78:	3201      	movi      	r2, 1
  7a:	c4625c00 	ins      	r3, r2, 0, 0
  7e:	a57a      	st.b      	r3, (r5, 0x1a)
  80:	3206      	movi      	r2, 6
  82:	b502      	st.w      	r0, (r5, 0x8)
  84:	6c63      	mov      	r1, r8
  86:	e4050013 	addi      	r0, r5, 20
  8a:	e0000000 	bsr      	0x0	// 0 <memcpy>
  8e:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
  92:	97c0      	ld.w      	r6, (r7, 0x0)
  94:	b503      	st.w      	r0, (r5, 0xc)
  96:	b524      	st.w      	r1, (r5, 0x10)
  98:	d806208f 	ld.w      	r0, (r6, 0x23c)
  9c:	d9262097 	ld.w      	r9, (r6, 0x25c)
  a0:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  a4:	6c43      	mov      	r1, r0
  a6:	6c27      	mov      	r0, r9
  a8:	e0000000 	bsr      	0x0	// 0 <dhcpd_reply>
  ac:	dc062097 	st.w      	r0, (r6, 0x25c)
  b0:	95c2      	ld.w      	r6, (r5, 0x8)
  b2:	0418      	br      	0xe2	// e2 <dhcpd_reply+0xe2>
  b4:	d805208f 	ld.w      	r0, (r5, 0x23c)
  b8:	d9652097 	ld.w      	r11, (r5, 0x25c)
  bc:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
  c0:	6c43      	mov      	r1, r0
  c2:	6c2f      	mov      	r0, r11
  c4:	e0000000 	bsr      	0x0	// 0 <dhcpd_reply>
  c8:	9760      	ld.w      	r3, (r7, 0x0)
  ca:	dc052097 	st.w      	r0, (r5, 0x25c)
  ce:	d8632097 	ld.w      	r3, (r3, 0x25c)
  d2:	64e6      	cmpne      	r9, r3
  d4:	0bb0      	bt      	0x34	// 34 <dhcpd_reply+0x34>
  d6:	3100      	movi      	r1, 0
  d8:	ea00ffff 	movi      	r0, 65535
  dc:	2008      	addi      	r0, 9
  de:	e0000000 	bsr      	0x0	// 0 <sys_event_new>
  e2:	9700      	ld.w      	r0, (r7, 0x0)
  e4:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  e8:	3200      	movi      	r2, 0
  ea:	846a      	ld.b      	r3, (r4, 0xa)
  ec:	842b      	ld.b      	r1, (r4, 0xb)
  ee:	a44e      	st.b      	r2, (r4, 0xe)
  f0:	a44f      	st.b      	r2, (r4, 0xf)
  f2:	a44c      	st.b      	r2, (r4, 0xc)
  f4:	a44d      	st.b      	r2, (r4, 0xd)
  f6:	e926001c 	bnez      	r6, 0x12e	// 12e <dhcpd_reply+0x12e>
  fa:	6c13      	mov      	r0, r4
  fc:	e0000000 	bsr      	0x0	// 0 <dhcpd_reply>
 100:	121d      	lrw      	r0, 0x0	// 274 <hgprintf+0x274>
 102:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 106:	140c      	addi      	r14, r14, 48
 108:	1498      	pop      	r4-r11, r15
 10a:	e9060006 	bez      	r6, 0x116	// 116 <dhcpd_reply+0x116>
 10e:	6c1b      	mov      	r0, r6
 110:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
 114:	b502      	st.w      	r0, (r5, 0x8)
 116:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
 11a:	857a      	ld.b      	r3, (r5, 0x1a)
 11c:	3201      	movi      	r2, 1
 11e:	c4625c00 	ins      	r3, r2, 0, 0
 122:	b503      	st.w      	r0, (r5, 0xc)
 124:	b524      	st.w      	r1, (r5, 0x10)
 126:	a57a      	st.b      	r3, (r5, 0x1a)
 128:	07c4      	br      	0xb0	// b0 <dhcpd_reply+0xb0>
 12a:	6d83      	mov      	r6, r0
 12c:	07db      	br      	0xe2	// e2 <dhcpd_reply+0xe2>
 12e:	9740      	ld.w      	r2, (r7, 0x0)
 130:	4368      	lsli      	r3, r3, 8
 132:	6cc4      	or      	r3, r1
 134:	d8422097 	ld.w      	r2, (r2, 0x25c)
 138:	764f      	sexth      	r9, r3
 13a:	b867      	st.w      	r3, (r14, 0x1c)
 13c:	d8640021 	ld.b      	r3, (r4, 0x21)
 140:	b866      	st.w      	r3, (r14, 0x18)
 142:	d8640020 	ld.b      	r3, (r4, 0x20)
 146:	b865      	st.w      	r3, (r14, 0x14)
 148:	847f      	ld.b      	r3, (r4, 0x1f)
 14a:	b864      	st.w      	r3, (r14, 0x10)
 14c:	847e      	ld.b      	r3, (r4, 0x1e)
 14e:	e42220ff 	andi      	r1, r2, 255
 152:	b863      	st.w      	r3, (r14, 0xc)
 154:	847d      	ld.b      	r3, (r4, 0x1d)
 156:	b82b      	st.w      	r1, (r14, 0x2c)
 158:	b862      	st.w      	r3, (r14, 0x8)
 15a:	c50255e1 	zext      	r1, r2, 15, 8
 15e:	847c      	ld.b      	r3, (r4, 0x1c)
 160:	b82a      	st.w      	r1, (r14, 0x28)
 162:	b861      	st.w      	r3, (r14, 0x4)
 164:	c60256e1 	zext      	r1, r2, 23, 16
 168:	4e78      	lsri      	r3, r6, 24
 16a:	4a58      	lsri      	r2, r2, 24
 16c:	b829      	st.w      	r1, (r14, 0x24)
 16e:	b848      	st.w      	r2, (r14, 0x20)
 170:	b860      	st.w      	r3, (r14, 0x0)
 172:	c50655e2 	zext      	r2, r6, 15, 8
 176:	c60656e3 	zext      	r3, r6, 23, 16
 17a:	7458      	zextb      	r1, r6
 17c:	111f      	lrw      	r0, 0x0	// 278 <dhcpd_reply+0x278>
 17e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 182:	3302      	movi      	r3, 2
 184:	a460      	st.b      	r3, (r4, 0x0)
 186:	e424000f 	addi      	r1, r4, 16
 18a:	6c1b      	mov      	r0, r6
 18c:	e0000000 	bsr      	0x0	// 0 <dhcpd_reply>
 190:	3335      	movi      	r3, 53
 192:	97e0      	ld.w      	r7, (r7, 0x0)
 194:	dc6400f0 	st.b      	r3, (r4, 0xf0)
 198:	3504      	movi      	r5, 4
 19a:	ea0b0001 	movi      	r11, 1
 19e:	3336      	movi      	r3, 54
 1a0:	dd6400f1 	st.b      	r11, (r4, 0xf1)
 1a4:	dd4400f2 	st.b      	r10, (r4, 0xf2)
 1a8:	dc6400f3 	st.b      	r3, (r4, 0xf3)
 1ac:	dca400f4 	st.b      	r5, (r4, 0xf4)
 1b0:	d8672098 	ld.w      	r3, (r7, 0x260)
 1b4:	e42400f4 	addi      	r1, r4, 245
 1b8:	9301      	ld.w      	r0, (r3, 0x4)
 1ba:	e0000000 	bsr      	0x0	// 0 <dhcpd_reply>
 1be:	3333      	movi      	r3, 51
 1c0:	dc6400f9 	st.b      	r3, (r4, 0xf9)
 1c4:	dca400fa 	st.b      	r5, (r4, 0xfa)
 1c8:	d867208c 	ld.w      	r3, (r7, 0x230)
 1cc:	4b50      	lsri      	r2, r3, 16
 1ce:	4a28      	lsri      	r1, r2, 8
 1d0:	dc4400fc 	st.b      	r2, (r4, 0xfc)
 1d4:	c50355e2 	zext      	r2, r3, 15, 8
 1d8:	dc2400fb 	st.b      	r1, (r4, 0xfb)
 1dc:	dc6400fe 	st.b      	r3, (r4, 0xfe)
 1e0:	dc4400fd 	st.b      	r2, (r4, 0xfd)
 1e4:	dd6400ff 	st.b      	r11, (r4, 0xff)
 1e8:	dca40100 	st.b      	r5, (r4, 0x100)
 1ec:	e4240100 	addi      	r1, r4, 257
 1f0:	d807208f 	ld.w      	r0, (r7, 0x23c)
 1f4:	e0000000 	bsr      	0x0	// 0 <dhcpd_reply>
 1f8:	d8672090 	ld.w      	r3, (r7, 0x240)
 1fc:	e923002b 	bnez      	r3, 0x252	// 252 <dhcpd_reply+0x252>
 200:	e4a40104 	addi      	r5, r4, 261
 204:	d8672091 	ld.w      	r3, (r7, 0x244)
 208:	e9030011 	bez      	r3, 0x22a	// 22a <dhcpd_reply+0x22a>
 20c:	3306      	movi      	r3, 6
 20e:	a560      	st.b      	r3, (r5, 0x0)
 210:	3308      	movi      	r3, 8
 212:	a561      	st.b      	r3, (r5, 0x1)
 214:	5d26      	addi      	r1, r5, 2
 216:	d8072091 	ld.w      	r0, (r7, 0x244)
 21a:	e0000000 	bsr      	0x0	// 0 <dhcpd_reply>
 21e:	5d36      	addi      	r1, r5, 6
 220:	d8072092 	ld.w      	r0, (r7, 0x248)
 224:	e0000000 	bsr      	0x0	// 0 <dhcpd_reply>
 228:	2509      	addi      	r5, 10
 22a:	c7e92880 	btsti      	r9, 31
 22e:	3200      	movi      	r2, 0
 230:	3000      	movi      	r0, 0
 232:	3100      	movi      	r1, 0
 234:	5d62      	addi      	r3, r5, 1
 236:	2a00      	subi      	r2, 1
 238:	c4080c20 	incf      	r0, r8, 0
 23c:	2900      	subi      	r1, 1
 23e:	c7e92880 	btsti      	r9, 31
 242:	a540      	st.b      	r2, (r5, 0x0)
 244:	60d2      	subu      	r3, r4
 246:	6c93      	mov      	r2, r4
 248:	c4260c20 	incf      	r1, r6, 0
 24c:	e0000000 	bsr      	0x0	// 0 <dhcpd_reply>
 250:	075b      	br      	0x106	// 106 <dhcpd_reply+0x106>
 252:	3303      	movi      	r3, 3
 254:	dca40106 	st.b      	r5, (r4, 0x106)
 258:	dc640105 	st.b      	r3, (r4, 0x105)
 25c:	e4240106 	addi      	r1, r4, 263
 260:	d8072090 	ld.w      	r0, (r7, 0x240)
 264:	e0000000 	bsr      	0x0	// 0 <dhcpd_reply>
 268:	e4a4010a 	addi      	r5, r4, 267
 26c:	07cc      	br      	0x204	// 204 <dhcpd_reply+0x204>
	...

Disassembly of section .text.dhcpd_work:

00000000 <dhcpd_work>:
   0:	14d6      	push      	r4-r9, r15
   2:	1427      	subi      	r14, r14, 28
   4:	13c5      	lrw      	r6, 0x0	// 198 <dhcpd_work+0x198>
   6:	1a02      	addi      	r2, r14, 8
   8:	9620      	ld.w      	r1, (r6, 0x0)
   a:	6dc3      	mov      	r7, r0
   c:	d801208b 	ld.w      	r0, (r1, 0x22c)
  10:	b841      	st.w      	r2, (r14, 0x4)
  12:	1a03      	addi      	r2, r14, 12
  14:	b840      	st.w      	r2, (r14, 0x0)
  16:	3280      	movi      	r2, 128
  18:	3300      	movi      	r3, 0
  1a:	4242      	lsli      	r2, r2, 2
  1c:	2128      	addi      	r1, 41
  1e:	b862      	st.w      	r3, (r14, 0x8)
  20:	e0000000 	bsr      	0x0	// 0 <recvfrom>
  24:	eb2000ef 	cmplti      	r0, 240
  28:	6e03      	mov      	r8, r0
  2a:	0845      	bt      	0xb4	// b4 <dhcpd_work+0xb4>
  2c:	9680      	ld.w      	r4, (r6, 0x0)
  2e:	d9240028 	ld.b      	r9, (r4, 0x28)
  32:	e5292001 	andi      	r9, r9, 1
  36:	e929003f 	bnez      	r9, 0xb4	// b4 <dhcpd_work+0xb4>
  3a:	d8640029 	ld.b      	r3, (r4, 0x29)
  3e:	3b41      	cmpnei      	r3, 1
  40:	e4a40028 	addi      	r5, r4, 41
  44:	0838      	bt      	0xb4	// b4 <dhcpd_work+0xb4>
  46:	d84500ed 	ld.b      	r2, (r5, 0xed)
  4a:	d86500ec 	ld.b      	r3, (r5, 0xec)
  4e:	4248      	lsli      	r2, r2, 8
  50:	6c8c      	or      	r2, r3
  52:	d86500ee 	ld.b      	r3, (r5, 0xee)
  56:	4370      	lsli      	r3, r3, 16
  58:	6c8c      	or      	r2, r3
  5a:	d86500ef 	ld.b      	r3, (r5, 0xef)
  5e:	4378      	lsli      	r3, r3, 24
  60:	6cc8      	or      	r3, r2
  62:	124f      	lrw      	r2, 0x63538263	// 19c <dhcpd_work+0x19c>
  64:	648e      	cmpne      	r3, r2
  66:	0827      	bt      	0xb4	// b4 <dhcpd_work+0xb4>
  68:	3208      	movi      	r2, 8
  6a:	6c67      	mov      	r1, r9
  6c:	e404024b 	addi      	r0, r4, 588
  70:	e0000000 	bsr      	0x0	// 0 <memset>
  74:	e50810ef 	subi      	r8, r8, 240
  78:	e4640118 	addi      	r3, r4, 281
  7c:	dd242093 	st.w      	r9, (r4, 0x24c)
  80:	dd240250 	st.b      	r9, (r4, 0x250)
  84:	620c      	addu      	r8, r3
  86:	660c      	cmphs      	r3, r8
  88:	0c21      	bf      	0xca	// ca <dhcpd_work+0xca>
  8a:	d8240250 	ld.b      	r1, (r4, 0x250)
  8e:	3941      	cmpnei      	r1, 1
  90:	0845      	bt      	0x11a	// 11a <dhcpd_work+0x11a>
  92:	d8042093 	ld.w      	r0, (r4, 0x24c)
  96:	e0000000 	bsr      	0x0	// 0 <dhcpd_work>
  9a:	e9200036 	bnez      	r0, 0x106	// 106 <dhcpd_work+0x106>
  9e:	9660      	ld.w      	r3, (r6, 0x0)
  a0:	3200      	movi      	r2, 0
  a2:	dc432093 	st.w      	r2, (r3, 0x24c)
  a6:	111f      	lrw      	r0, 0x0	// 1a0 <hgprintf+0x1a0>
  a8:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  ac:	3102      	movi      	r1, 2
  ae:	6c17      	mov      	r0, r5
  b0:	e0000000 	bsr      	0x0	// 0 <dhcpd_work>
  b4:	3000      	movi      	r0, 0
  b6:	e0000000 	bsr      	0x0	// 0 <dhcpd_work>
  ba:	31fa      	movi      	r1, 250
  bc:	4122      	lsli      	r1, r1, 2
  be:	6c1f      	mov      	r0, r7
  c0:	e0000000 	bsr      	0x0	// 0 <os_run_work_delay>
  c4:	3000      	movi      	r0, 0
  c6:	1407      	addi      	r14, r14, 28
  c8:	1496      	pop      	r4-r9, r15
  ca:	8340      	ld.b      	r2, (r3, 0x0)
  cc:	eb420035 	cmpnei      	r2, 53
  d0:	8301      	ld.b      	r0, (r3, 0x1)
  d2:	0c16      	bf      	0xfe	// fe <dhcpd_work+0xfe>
  d4:	eb4200ff 	cmpnei      	r2, 255
  d8:	0fd9      	bf      	0x8a	// 8a <dhcpd_work+0x8a>
  da:	eb420032 	cmpnei      	r2, 50
  de:	080d      	bt      	0xf8	// f8 <dhcpd_work+0xf8>
  e0:	8342      	ld.b      	r2, (r3, 0x2)
  e2:	8323      	ld.b      	r1, (r3, 0x3)
  e4:	4130      	lsli      	r1, r1, 16
  e6:	4258      	lsli      	r2, r2, 24
  e8:	6c84      	or      	r2, r1
  ea:	8325      	ld.b      	r1, (r3, 0x5)
  ec:	6c84      	or      	r2, r1
  ee:	8324      	ld.b      	r1, (r3, 0x4)
  f0:	4128      	lsli      	r1, r1, 8
  f2:	6c84      	or      	r2, r1
  f4:	dc442093 	st.w      	r2, (r4, 0x24c)
  f8:	2301      	addi      	r3, 2
  fa:	60c0      	addu      	r3, r0
  fc:	07c5      	br      	0x86	// 86 <dhcpd_work+0x86>
  fe:	8342      	ld.b      	r2, (r3, 0x2)
 100:	dc440250 	st.b      	r2, (r4, 0x250)
 104:	07fa      	br      	0xf8	// f8 <dhcpd_work+0xf8>
 106:	9660      	ld.w      	r3, (r6, 0x0)
 108:	e4240044 	addi      	r1, r4, 69
 10c:	d8032093 	ld.w      	r0, (r3, 0x24c)
 110:	e0000000 	bsr      	0x0	// 0 <dhcpd_work>
 114:	e900ffc5 	bez      	r0, 0x9e	// 9e <dhcpd_work+0x9e>
 118:	07c7      	br      	0xa6	// a6 <dhcpd_work+0xa6>
 11a:	3943      	cmpnei      	r1, 3
 11c:	0839      	bt      	0x18e	// 18e <dhcpd_work+0x18e>
 11e:	d8642093 	ld.w      	r3, (r4, 0x24c)
 122:	e9230010 	bnez      	r3, 0x142	// 142 <dhcpd_work+0x142>
 126:	850d      	ld.b      	r0, (r5, 0xd)
 128:	856c      	ld.b      	r3, (r5, 0xc)
 12a:	4008      	lsli      	r0, r0, 8
 12c:	6c0c      	or      	r0, r3
 12e:	856e      	ld.b      	r3, (r5, 0xe)
 130:	4370      	lsli      	r3, r3, 16
 132:	6cc0      	or      	r3, r0
 134:	850f      	ld.b      	r0, (r5, 0xf)
 136:	4018      	lsli      	r0, r0, 24
 138:	6c0c      	or      	r0, r3
 13a:	e0000000 	bsr      	0x0	// 0 <lwip_htonl>
 13e:	dc042093 	st.w      	r0, (r4, 0x24c)
 142:	9660      	ld.w      	r3, (r6, 0x0)
 144:	d8032093 	ld.w      	r0, (r3, 0x24c)
 148:	e900ffb6 	bez      	r0, 0xb4	// b4 <dhcpd_work+0xb4>
 14c:	e0000000 	bsr      	0x0	// 0 <dhcpd_work>
 150:	e900ffb2 	bez      	r0, 0xb4	// b4 <dhcpd_work+0xb4>
 154:	9660      	ld.w      	r3, (r6, 0x0)
 156:	e4240044 	addi      	r1, r4, 69
 15a:	d8032093 	ld.w      	r0, (r3, 0x24c)
 15e:	e0000000 	bsr      	0x0	// 0 <dhcpd_work>
 162:	e9200006 	bnez      	r0, 0x16e	// 16e <dhcpd_work+0x16e>
 166:	6c17      	mov      	r0, r5
 168:	e0000000 	bsr      	0x0	// 0 <dhcpd_work>
 16c:	07a4      	br      	0xb4	// b4 <dhcpd_work+0xb4>
 16e:	100e      	lrw      	r0, 0x0	// 1a4 <dhcpd_work+0x1a4>
 170:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 174:	6c17      	mov      	r0, r5
 176:	3105      	movi      	r1, 5
 178:	e0000000 	bsr      	0x0	// 0 <dhcpd_work>
 17c:	9660      	ld.w      	r3, (r6, 0x0)
 17e:	ea00ffff 	movi      	r0, 65535
 182:	2007      	addi      	r0, 8
 184:	d8232093 	ld.w      	r1, (r3, 0x24c)
 188:	e0000000 	bsr      	0x0	// 0 <sys_event_new>
 18c:	0794      	br      	0xb4	// b4 <dhcpd_work+0xb4>
 18e:	1007      	lrw      	r0, 0x0	// 1a8 <dhcpd_work+0x1a8>
 190:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 194:	0790      	br      	0xb4	// b4 <dhcpd_work+0xb4>
 196:	0000      	.short	0x0000
 198:	00000000 	.long	0x00000000
 19c:	63538263 	.long	0x63538263
	...

Disassembly of section .text.dhcpd_skmonitor_cb:

00000000 <dhcpd_skmonitor_cb>:
   0:	14d0      	push      	r15
   2:	e4212001 	andi      	r1, r1, 1
   6:	e9010007 	bez      	r1, 0x14	// 14 <dhcpd_skmonitor_cb+0x14>
   a:	1064      	lrw      	r3, 0x0	// 18 <dhcpd_skmonitor_cb+0x18>
   c:	9300      	ld.w      	r0, (r3, 0x0)
   e:	2007      	addi      	r0, 8
  10:	e0000000 	bsr      	0x0	// 0 <dhcpd_skmonitor_cb>
  14:	1490      	pop      	r15
  16:	0000      	.short	0x0000
  18:	00000000 	.long	0x00000000

Disassembly of section .text.dhcpd_dump_ippool:

00000000 <dhcpd_dump_ippool>:
   0:	14d4      	push      	r4-r7, r15
   2:	1424      	subi      	r14, r14, 16
   4:	1079      	lrw      	r3, 0x0	// 68 <dhcpd_dump_ippool+0x68>
   6:	6d8f      	mov      	r6, r3
   8:	93a0      	ld.w      	r5, (r3, 0x0)
   a:	e9050019 	bez      	r5, 0x3c	// 3c <dhcpd_dump_ippool+0x3c>
   e:	d8650028 	ld.b      	r3, (r5, 0x28)
  12:	e4632002 	andi      	r3, r3, 2
  16:	e9030013 	bez      	r3, 0x3c	// 3c <dhcpd_dump_ippool+0x3c>
  1a:	3100      	movi      	r1, 0
  1c:	2900      	subi      	r1, 1
  1e:	6c17      	mov      	r0, r5
  20:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  24:	1012      	lrw      	r0, 0x0	// 6c <hgprintf+0x6c>
  26:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  2a:	e4a50253 	addi      	r5, r5, 596
  2e:	9580      	ld.w      	r4, (r5, 0x0)
  30:	10f0      	lrw      	r7, 0x0	// 70 <dhcpd_dump_ippool+0x70>
  32:	6552      	cmpne      	r4, r5
  34:	0806      	bt      	0x40	// 40 <dhcpd_dump_ippool+0x40>
  36:	9600      	ld.w      	r0, (r6, 0x0)
  38:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  3c:	1404      	addi      	r14, r14, 16
  3e:	1494      	pop      	r4-r7, r15
  40:	5c1e      	addi      	r0, r4, 8
  42:	e0000000 	bsr      	0x0	// 0 <ip4addr_ntoa>
  46:	8439      	ld.b      	r1, (r4, 0x19)
  48:	8475      	ld.b      	r3, (r4, 0x15)
  4a:	8454      	ld.b      	r2, (r4, 0x14)
  4c:	b823      	st.w      	r1, (r14, 0xc)
  4e:	8438      	ld.b      	r1, (r4, 0x18)
  50:	b822      	st.w      	r1, (r14, 0x8)
  52:	8437      	ld.b      	r1, (r4, 0x17)
  54:	b821      	st.w      	r1, (r14, 0x4)
  56:	8436      	ld.b      	r1, (r4, 0x16)
  58:	b820      	st.w      	r1, (r14, 0x0)
  5a:	6c43      	mov      	r1, r0
  5c:	6c1f      	mov      	r0, r7
  5e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  62:	9480      	ld.w      	r4, (r4, 0x0)
  64:	07e7      	br      	0x32	// 32 <dhcpd_dump_ippool+0x32>
	...

Disassembly of section .text.dhcpd_get_lease_list:

00000000 <dhcpd_get_lease_list>:
   0:	14d7      	push      	r4-r10, r15
   2:	10fe      	lrw      	r7, 0x0	// 78 <dhcpd_get_lease_list+0x78>
   4:	6e43      	mov      	r9, r0
   6:	97a0      	ld.w      	r5, (r7, 0x0)
   8:	6e07      	mov      	r8, r1
   a:	e9050034 	bez      	r5, 0x72	// 72 <dhcpd_get_lease_list+0x72>
   e:	d8850028 	ld.b      	r4, (r5, 0x28)
  12:	e4842002 	andi      	r4, r4, 2
  16:	e9040017 	bez      	r4, 0x44	// 44 <dhcpd_get_lease_list+0x44>
  1a:	e900002c 	bez      	r0, 0x72	// 72 <dhcpd_get_lease_list+0x72>
  1e:	e961002a 	blsz      	r1, 0x72	// 72 <dhcpd_get_lease_list+0x72>
  22:	3100      	movi      	r1, 0
  24:	6c17      	mov      	r0, r5
  26:	2900      	subi      	r1, 1
  28:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  2c:	3400      	movi      	r4, 0
  2e:	d8c52095 	ld.w      	r6, (r5, 0x254)
  32:	ea0a000c 	movi      	r10, 12
  36:	e4a50253 	addi      	r5, r5, 596
  3a:	655a      	cmpne      	r6, r5
  3c:	0806      	bt      	0x48	// 48 <dhcpd_get_lease_list+0x48>
  3e:	9700      	ld.w      	r0, (r7, 0x0)
  40:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  44:	6c13      	mov      	r0, r4
  46:	1497      	pop      	r4-r10, r15
  48:	867a      	ld.b      	r3, (r6, 0x1a)
  4a:	e4632001 	andi      	r3, r3, 1
  4e:	e9030010 	bez      	r3, 0x6e	// 6e <dhcpd_get_lease_list+0x6e>
  52:	c5448420 	mult      	r0, r4, r10
  56:	6024      	addu      	r0, r9
  58:	9662      	ld.w      	r3, (r6, 0x8)
  5a:	b060      	st.w      	r3, (r0, 0x0)
  5c:	3206      	movi      	r2, 6
  5e:	e4260013 	addi      	r1, r6, 20
  62:	2003      	addi      	r0, 4
  64:	2400      	addi      	r4, 1
  66:	e0000000 	bsr      	0x0	// 0 <memcpy>
  6a:	6611      	cmplt      	r4, r8
  6c:	0fe9      	bf      	0x3e	// 3e <dhcpd_get_lease_list+0x3e>
  6e:	96c0      	ld.w      	r6, (r6, 0x0)
  70:	07e5      	br      	0x3a	// 3a <dhcpd_get_lease_list+0x3a>
  72:	3400      	movi      	r4, 0
  74:	07e8      	br      	0x44	// 44 <dhcpd_get_lease_list+0x44>
  76:	0000      	.short	0x0000
  78:	00000000 	.long	0x00000000

Disassembly of section .text.dhcpd_get_lease_ip:

00000000 <dhcpd_get_lease_ip>:
   0:	14d3      	push      	r4-r6, r15
   2:	1071      	lrw      	r3, 0x0	// 44 <dhcpd_get_lease_ip+0x44>
   4:	6d83      	mov      	r6, r0
   6:	9300      	ld.w      	r0, (r3, 0x0)
   8:	6d4f      	mov      	r5, r3
   a:	e900001a 	bez      	r0, 0x3e	// 3e <dhcpd_get_lease_ip+0x3e>
   e:	d8800028 	ld.b      	r4, (r0, 0x28)
  12:	e4842002 	andi      	r4, r4, 2
  16:	e9040010 	bez      	r4, 0x36	// 36 <dhcpd_get_lease_ip+0x36>
  1a:	3100      	movi      	r1, 0
  1c:	2900      	subi      	r1, 1
  1e:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  22:	6c5b      	mov      	r1, r6
  24:	3000      	movi      	r0, 0
  26:	e0000000 	bsr      	0x0	// 0 <dhcpd_get_lease_ip>
  2a:	e9000008 	bez      	r0, 0x3a	// 3a <dhcpd_get_lease_ip+0x3a>
  2e:	9082      	ld.w      	r4, (r0, 0x8)
  30:	9500      	ld.w      	r0, (r5, 0x0)
  32:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  36:	6c13      	mov      	r0, r4
  38:	1493      	pop      	r4-r6, r15
  3a:	6d03      	mov      	r4, r0
  3c:	07fa      	br      	0x30	// 30 <dhcpd_get_lease_ip+0x30>
  3e:	6d03      	mov      	r4, r0
  40:	07fb      	br      	0x36	// 36 <dhcpd_get_lease_ip+0x36>
  42:	0000      	.short	0x0000
  44:	00000000 	.long	0x00000000

Disassembly of section .text.dhcpd_ip_inactive:

00000000 <dhcpd_ip_inactive>:
   0:	14d2      	push      	r4-r5, r15
   2:	1070      	lrw      	r3, 0x0	// 40 <dhcpd_ip_inactive+0x40>
   4:	6d43      	mov      	r5, r0
   6:	9300      	ld.w      	r0, (r3, 0x0)
   8:	6d0f      	mov      	r4, r3
   a:	e900001a 	bez      	r0, 0x3e	// 3e <dhcpd_ip_inactive+0x3e>
   e:	d8600028 	ld.b      	r3, (r0, 0x28)
  12:	e4632002 	andi      	r3, r3, 2
  16:	e9030014 	bez      	r3, 0x3e	// 3e <dhcpd_ip_inactive+0x3e>
  1a:	3100      	movi      	r1, 0
  1c:	2900      	subi      	r1, 1
  1e:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  22:	6c57      	mov      	r1, r5
  24:	3000      	movi      	r0, 0
  26:	e0000000 	bsr      	0x0	// 0 <dhcpd_ip_inactive>
  2a:	e9000007 	bez      	r0, 0x38	// 38 <dhcpd_ip_inactive+0x38>
  2e:	807a      	ld.b      	r3, (r0, 0x1a)
  30:	3200      	movi      	r2, 0
  32:	c4625c00 	ins      	r3, r2, 0, 0
  36:	a07a      	st.b      	r3, (r0, 0x1a)
  38:	9400      	ld.w      	r0, (r4, 0x0)
  3a:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  3e:	1492      	pop      	r4-r5, r15
  40:	0000      	.short	0x0000
	...

Disassembly of section .text.dhcpd_start:

00000000 <dhcpd_start>:
   0:	14d4      	push      	r4-r7, r15
   2:	6d83      	mov      	r6, r0
   4:	6dc7      	mov      	r7, r1
   6:	e9200008 	bnez      	r0, 0x16	// 16 <dhcpd_start+0x16>
   a:	1104      	lrw      	r0, 0x0	// 98 <hgprintf+0x98>
   c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  10:	3000      	movi      	r0, 0
  12:	2800      	subi      	r0, 1
  14:	1494      	pop      	r4-r7, r15
  16:	11a2      	lrw      	r5, 0x0	// 9c <dhcpd_start+0x9c>
  18:	9540      	ld.w      	r2, (r5, 0x0)
  1a:	e9020012 	bez      	r2, 0x3e	// 3e <dhcpd_start+0x3e>
  1e:	d8620028 	ld.b      	r3, (r2, 0x28)
  22:	e5832003 	andi      	r12, r3, 3
  26:	eb4c0003 	cmpnei      	r12, 3
  2a:	080a      	bt      	0x3e	// 3e <dhcpd_start+0x3e>
  2c:	3400      	movi      	r4, 0
  2e:	c4645c00 	ins      	r3, r4, 0, 0
  32:	dc620028 	st.b      	r3, (r2, 0x28)
  36:	e0000000 	bsr      	0x0	// 0 <dhcpd_start>
  3a:	6c13      	mov      	r0, r4
  3c:	07ec      	br      	0x14	// 14 <dhcpd_start+0x14>
  3e:	e907ffe6 	bez      	r7, 0xa	// a <dhcpd_start+0xa>
  42:	3099      	movi      	r0, 153
  44:	4002      	lsli      	r0, r0, 2
  46:	e0000000 	bsr      	0x0	// 0 <_os_zalloc>
  4a:	b500      	st.w      	r0, (r5, 0x0)
  4c:	e9000023 	bez      	r0, 0x92	// 92 <dhcpd_start+0x92>
  50:	3200      	movi      	r2, 0
  52:	2a00      	subi      	r2, 1
  54:	dc40208b 	st.w      	r2, (r0, 0x22c)
  58:	e0000000 	bsr      	0x0	// 0 <os_mutex_init>
  5c:	9560      	ld.w      	r3, (r5, 0x0)
  5e:	e4430253 	addi      	r2, r3, 596
  62:	dc432095 	st.w      	r2, (r3, 0x254)
  66:	dc432096 	st.w      	r2, (r3, 0x258)
  6a:	3400      	movi      	r4, 0
  6c:	104d      	lrw      	r2, 0x0	// a0 <dhcpd_start+0xa0>
  6e:	6c5f      	mov      	r1, r7
  70:	b349      	st.w      	r2, (r3, 0x24)
  72:	8354      	ld.b      	r2, (r3, 0x14)
  74:	c4445c83 	ins      	r2, r4, 7, 3
  78:	a354      	st.b      	r2, (r3, 0x14)
  7a:	6c1b      	mov      	r0, r6
  7c:	e0000000 	bsr      	0x0	// 0 <dhcpd_start>
  80:	9560      	ld.w      	r3, (r5, 0x0)
  82:	3101      	movi      	r1, 1
  84:	d8430028 	ld.b      	r2, (r3, 0x28)
  88:	c4415c01 	ins      	r2, r1, 1, 1
  8c:	dc430028 	st.b      	r2, (r3, 0x28)
  90:	07d5      	br      	0x3a	// 3a <dhcpd_start+0x3a>
  92:	3000      	movi      	r0, 0
  94:	280b      	subi      	r0, 12
  96:	07bf      	br      	0x14	// 14 <dhcpd_start+0x14>
	...

Disassembly of section .text.dhcpd_stop:

00000000 <dhcpd_stop>:
   0:	14d1      	push      	r4, r15
   2:	1093      	lrw      	r4, 0x0	// 4c <dhcpd_stop+0x4c>
   4:	9460      	ld.w      	r3, (r4, 0x0)
   6:	e9030021 	bez      	r3, 0x48	// 48 <dhcpd_stop+0x48>
   a:	d8430028 	ld.b      	r2, (r3, 0x28)
   e:	e4422002 	andi      	r2, r2, 2
  12:	e902001b 	bez      	r2, 0x48	// 48 <dhcpd_stop+0x48>
  16:	3101      	movi      	r1, 1
  18:	d8031116 	ld.h      	r0, (r3, 0x22c)
  1c:	e0000000 	bsr      	0x0	// 0 <sock_monitor_disable>
  20:	3001      	movi      	r0, 1
  22:	e0000000 	bsr      	0x0	// 0 <dhcpd_stop>
  26:	9460      	ld.w      	r3, (r4, 0x0)
  28:	d803208b 	ld.w      	r0, (r3, 0x22c)
  2c:	e0000000 	bsr      	0x0	// 0 <closesocket>
  30:	9460      	ld.w      	r3, (r4, 0x0)
  32:	3200      	movi      	r2, 0
  34:	2a00      	subi      	r2, 1
  36:	dc43208b 	st.w      	r2, (r3, 0x22c)
  3a:	3101      	movi      	r1, 1
  3c:	d8430028 	ld.b      	r2, (r3, 0x28)
  40:	c4415c00 	ins      	r2, r1, 0, 0
  44:	dc430028 	st.b      	r2, (r3, 0x28)
  48:	1491      	pop      	r4, r15
  4a:	0000      	.short	0x0000
  4c:	0000      	.short	0x0000
	...

Disassembly of section .text.dhcpd_set_dns:

00000000 <dhcpd_set_dns>:
   0:	14d0      	push      	r15
   2:	1425      	subi      	r14, r14, 20
   4:	1073      	lrw      	r3, 0x0	// 50 <dhcpd_set_dns+0x50>
   6:	9360      	ld.w      	r3, (r3, 0x0)
   8:	e9030021 	bez      	r3, 0x4a	// 4a <dhcpd_set_dns+0x4a>
   c:	d8430028 	ld.b      	r2, (r3, 0x28)
  10:	e4422002 	andi      	r2, r2, 2
  14:	e902001b 	bez      	r2, 0x4a	// 4a <dhcpd_set_dns+0x4a>
  18:	dc032091 	st.w      	r0, (r3, 0x244)
  1c:	dc232092 	st.w      	r1, (r3, 0x248)
  20:	4978      	lsri      	r3, r1, 24
  22:	b864      	st.w      	r3, (r14, 0x10)
  24:	c60156e3 	zext      	r3, r1, 23, 16
  28:	b863      	st.w      	r3, (r14, 0xc)
  2a:	c50155e3 	zext      	r3, r1, 15, 8
  2e:	b862      	st.w      	r3, (r14, 0x8)
  30:	e42120ff 	andi      	r1, r1, 255
  34:	4878      	lsri      	r3, r0, 24
  36:	b821      	st.w      	r1, (r14, 0x4)
  38:	b860      	st.w      	r3, (r14, 0x0)
  3a:	c50055e2 	zext      	r2, r0, 15, 8
  3e:	c60056e3 	zext      	r3, r0, 23, 16
  42:	7440      	zextb      	r1, r0
  44:	1004      	lrw      	r0, 0x0	// 54 <dhcpd_set_dns+0x54>
  46:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  4a:	1405      	addi      	r14, r14, 20
  4c:	1490      	pop      	r15
	...
