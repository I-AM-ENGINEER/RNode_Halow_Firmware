
disasm/libnetutils/obj/utils_chksum.o:     file format elf32-csky-little


Disassembly of section .text.net_checksum:

00000000 <net_checksum>:
   0:	14c2      	push      	r4-r5
   2:	e4822001 	andi      	r4, r2, 1
   6:	6f47      	mov      	r13, r1
   8:	3a80      	bclri      	r2, 0
   a:	ea0c0000 	movi      	r12, 0
   e:	64b1      	cmplt      	r12, r2
  10:	080c      	bt      	0x28	// 28 <net_checksum+0x28>
  12:	e9040006 	bez      	r4, 0x1e	// 1e <net_checksum+0x1e>
  16:	d1810023 	ldr.b      	r3, (r1, r12 << 0)
  1a:	4368      	lsli      	r3, r3, 8
  1c:	600c      	addu      	r0, r3
  1e:	4870      	lsri      	r3, r0, 16
  20:	e9230010 	bnez      	r3, 0x40	// 40 <net_checksum+0x40>
  24:	7401      	zexth      	r0, r0
  26:	1482      	pop      	r4-r5
  28:	d86d0000 	ld.b      	r3, (r13, 0x0)
  2c:	d8ad0001 	ld.b      	r5, (r13, 0x1)
  30:	4368      	lsli      	r3, r3, 8
  32:	60d4      	addu      	r3, r5
  34:	600c      	addu      	r0, r3
  36:	e58c0001 	addi      	r12, r12, 2
  3a:	e5ad0001 	addi      	r13, r13, 2
  3e:	07e8      	br      	0xe	// e <net_checksum+0xe>
  40:	c40055e0 	zext      	r0, r0, 15, 0
  44:	07ec      	br      	0x1c	// 1c <net_checksum+0x1c>

Disassembly of section .text.net_pseudo_checksum:

00000000 <net_pseudo_checksum>:
   0:	14d4      	push      	r4-r7, r15
   2:	1424      	subi      	r14, r14, 16
   4:	6d0b      	mov      	r4, r2
   6:	3504      	movi      	r5, 4
   8:	9849      	ld.w      	r2, (r14, 0x24)
   a:	6dc3      	mov      	r7, r0
   c:	6d87      	mov      	r6, r1
   e:	b840      	st.w      	r2, (r14, 0x0)
  10:	6c4f      	mov      	r1, r3
  12:	6c97      	mov      	r2, r5
  14:	c4ae0020 	addu      	r0, r14, r5
  18:	e0000000 	bsr      	0x0	// 0 <memcpy>
  1c:	6c97      	mov      	r2, r5
  1e:	9820      	ld.w      	r1, (r14, 0x0)
  20:	1802      	addi      	r0, r14, 8
  22:	e0000000 	bsr      	0x0	// 0 <memcpy>
  26:	3300      	movi      	r3, 0
  28:	dc6e000c 	st.b      	r3, (r14, 0xc)
  2c:	c4ae0021 	addu      	r1, r14, r5
  30:	4c68      	lsri      	r3, r4, 8
  32:	320c      	movi      	r2, 12
  34:	3000      	movi      	r0, 0
  36:	dc6e000e 	st.b      	r3, (r14, 0xe)
  3a:	dcee000d 	st.b      	r7, (r14, 0xd)
  3e:	dc8e000f 	st.b      	r4, (r14, 0xf)
  42:	e0000000 	bsr      	0x0	// 0 <net_pseudo_checksum>
  46:	6c93      	mov      	r2, r4
  48:	6c5b      	mov      	r1, r6
  4a:	e0000000 	bsr      	0x0	// 0 <net_pseudo_checksum>
  4e:	6c02      	nor      	r0, r0
  50:	7401      	zexth      	r0, r0
  52:	1404      	addi      	r14, r14, 16
  54:	1494      	pop      	r4-r7, r15
