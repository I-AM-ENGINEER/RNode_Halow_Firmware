
disasm/libnetutils/obj/utils_wnbota.o:     file format elf32-csky-little


Disassembly of section .text.wnb_ota_pkthook_rx:

00000000 <wnb_ota_pkthook_rx>:
   0:	14d5      	push      	r4-r8, r15
   2:	1422      	subi      	r14, r14, 8
   4:	6d4b      	mov      	r5, r2
   6:	9240      	ld.w      	r2, (r2, 0x0)
   8:	6d87      	mov      	r6, r1
   a:	826c      	ld.b      	r3, (r2, 0xc)
   c:	4368      	lsli      	r3, r3, 8
   e:	824d      	ld.b      	r2, (r2, 0xd)
  10:	6cc8      	or      	r3, r2
  12:	74cf      	sexth      	r3, r3
  14:	eb434847 	cmpnei      	r3, 18503
  18:	0843      	bt      	0x9e	// 9e <wnb_ota_pkthook_rx+0x9e>
  1a:	6c7b      	mov      	r1, r14
  1c:	6c1b      	mov      	r0, r6
  1e:	e0000000 	bsr      	0x0	// 0 <ieee80211_conf_get_mac>
  22:	9500      	ld.w      	r0, (r5, 0x0)
  24:	8080      	ld.b      	r4, (r0, 0x0)
  26:	e4842001 	andi      	r4, r4, 1
  2a:	e9240008 	bnez      	r4, 0x3a	// 3a <wnb_ota_pkthook_rx+0x3a>
  2e:	3206      	movi      	r2, 6
  30:	6c7b      	mov      	r1, r14
  32:	e0000000 	bsr      	0x0	// 0 <memcmp>
  36:	e9200034 	bnez      	r0, 0x9e	// 9e <wnb_ota_pkthook_rx+0x9e>
  3a:	8d02      	ld.h      	r0, (r5, 0x4)
  3c:	e0000000 	bsr      	0x0	// 0 <alloc_skb>
  40:	6dc3      	mov      	r7, r0
  42:	e9000027 	bez      	r0, 0x90	// 90 <wnb_ota_pkthook_rx+0x90>
  46:	8d42      	ld.h      	r2, (r5, 0x4)
  48:	9520      	ld.w      	r1, (r5, 0x0)
  4a:	9007      	ld.w      	r0, (r0, 0x1c)
  4c:	e0000000 	bsr      	0x0	// 0 <hw_memcpy>
  50:	6c5f      	mov      	r1, r7
  52:	6c1b      	mov      	r0, r6
  54:	e0000000 	bsr      	0x0	// 0 <libota_proc>
  58:	6d03      	mov      	r4, r0
  5a:	e9000018 	bez      	r0, 0x8a	// 8a <wnb_ota_pkthook_rx+0x8a>
  5e:	9007      	ld.w      	r0, (r0, 0x1c)
  60:	e5000005 	addi      	r8, r0, 6
  64:	3206      	movi      	r2, 6
  66:	6c63      	mov      	r1, r8
  68:	e0000000 	bsr      	0x0	// 0 <memcpy>
  6c:	3206      	movi      	r2, 6
  6e:	6c7b      	mov      	r1, r14
  70:	6c23      	mov      	r0, r8
  72:	e0000000 	bsr      	0x0	// 0 <memcpy>
  76:	8c54      	ld.h      	r2, (r4, 0x28)
  78:	9427      	ld.w      	r1, (r4, 0x1c)
  7a:	6c1b      	mov      	r0, r6
  7c:	e0000000 	bsr      	0x0	// 0 <ieee80211_tx>
  80:	651e      	cmpne      	r7, r4
  82:	0c04      	bf      	0x8a	// 8a <wnb_ota_pkthook_rx+0x8a>
  84:	6c13      	mov      	r0, r4
  86:	e0000000 	bsr      	0x0	// 0 <kfree_skb>
  8a:	6c1f      	mov      	r0, r7
  8c:	e0000000 	bsr      	0x0	// 0 <kfree_skb>
  90:	9560      	ld.w      	r3, (r5, 0x0)
  92:	8300      	ld.b      	r0, (r3, 0x0)
  94:	6c02      	nor      	r0, r0
  96:	e4002001 	andi      	r0, r0, 1
  9a:	1402      	addi      	r14, r14, 8
  9c:	1495      	pop      	r4-r8, r15
  9e:	3000      	movi      	r0, 0
  a0:	07fd      	br      	0x9a	// 9a <wnb_ota_pkthook_rx+0x9a>

Disassembly of section .text.wnb_ota_pkthook_tx:

00000000 <wnb_ota_pkthook_tx>:
   0:	14d5      	push      	r4-r8, r15
   2:	1422      	subi      	r14, r14, 8
   4:	6d4b      	mov      	r5, r2
   6:	9240      	ld.w      	r2, (r2, 0x0)
   8:	6d87      	mov      	r6, r1
   a:	826c      	ld.b      	r3, (r2, 0xc)
   c:	4368      	lsli      	r3, r3, 8
   e:	824d      	ld.b      	r2, (r2, 0xd)
  10:	6cc8      	or      	r3, r2
  12:	74cf      	sexth      	r3, r3
  14:	eb434847 	cmpnei      	r3, 18503
  18:	0843      	bt      	0x9e	// 9e <wnb_ota_pkthook_tx+0x9e>
  1a:	6c7b      	mov      	r1, r14
  1c:	6c1b      	mov      	r0, r6
  1e:	e0000000 	bsr      	0x0	// 0 <ieee80211_conf_get_mac>
  22:	9500      	ld.w      	r0, (r5, 0x0)
  24:	8080      	ld.b      	r4, (r0, 0x0)
  26:	e4842001 	andi      	r4, r4, 1
  2a:	e9240008 	bnez      	r4, 0x3a	// 3a <wnb_ota_pkthook_tx+0x3a>
  2e:	3206      	movi      	r2, 6
  30:	6c7b      	mov      	r1, r14
  32:	e0000000 	bsr      	0x0	// 0 <memcmp>
  36:	e9200034 	bnez      	r0, 0x9e	// 9e <wnb_ota_pkthook_tx+0x9e>
  3a:	8d02      	ld.h      	r0, (r5, 0x4)
  3c:	e0000000 	bsr      	0x0	// 0 <alloc_skb>
  40:	6dc3      	mov      	r7, r0
  42:	e9000027 	bez      	r0, 0x90	// 90 <wnb_ota_pkthook_tx+0x90>
  46:	8d42      	ld.h      	r2, (r5, 0x4)
  48:	9520      	ld.w      	r1, (r5, 0x0)
  4a:	9007      	ld.w      	r0, (r0, 0x1c)
  4c:	e0000000 	bsr      	0x0	// 0 <hw_memcpy>
  50:	6c5f      	mov      	r1, r7
  52:	6c1b      	mov      	r0, r6
  54:	e0000000 	bsr      	0x0	// 0 <libota_proc>
  58:	6d03      	mov      	r4, r0
  5a:	e9000018 	bez      	r0, 0x8a	// 8a <wnb_ota_pkthook_tx+0x8a>
  5e:	9007      	ld.w      	r0, (r0, 0x1c)
  60:	e5000005 	addi      	r8, r0, 6
  64:	3206      	movi      	r2, 6
  66:	6c63      	mov      	r1, r8
  68:	e0000000 	bsr      	0x0	// 0 <memcpy>
  6c:	3206      	movi      	r2, 6
  6e:	6c7b      	mov      	r1, r14
  70:	6c23      	mov      	r0, r8
  72:	e0000000 	bsr      	0x0	// 0 <memcpy>
  76:	8c54      	ld.h      	r2, (r4, 0x28)
  78:	9427      	ld.w      	r1, (r4, 0x1c)
  7a:	6c1b      	mov      	r0, r6
  7c:	e0000000 	bsr      	0x0	// 0 <ieee80211_input>
  80:	651e      	cmpne      	r7, r4
  82:	0c04      	bf      	0x8a	// 8a <wnb_ota_pkthook_tx+0x8a>
  84:	6c13      	mov      	r0, r4
  86:	e0000000 	bsr      	0x0	// 0 <kfree_skb>
  8a:	6c1f      	mov      	r0, r7
  8c:	e0000000 	bsr      	0x0	// 0 <kfree_skb>
  90:	9560      	ld.w      	r3, (r5, 0x0)
  92:	8300      	ld.b      	r0, (r3, 0x0)
  94:	6c02      	nor      	r0, r0
  96:	e4002001 	andi      	r0, r0, 1
  9a:	1402      	addi      	r14, r14, 8
  9c:	1495      	pop      	r4-r8, r15
  9e:	3000      	movi      	r0, 0
  a0:	07fd      	br      	0x9a	// 9a <wnb_ota_pkthook_tx+0x9a>

Disassembly of section .text.wnb_ota_init:

00000000 <wnb_ota_init>:
   0:	14d0      	push      	r15
   2:	1003      	lrw      	r0, 0x0	// c <wnb_ota_init+0xc>
   4:	e0000000 	bsr      	0x0	// 0 <ieee80211_register_pkthook>
   8:	1490      	pop      	r15
   a:	0000      	.short	0x0000
   c:	00000000 	.long	0x00000000
