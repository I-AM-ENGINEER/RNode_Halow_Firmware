
disasm/libcommon/obj/ota_fwinfo.o:     file format elf32-csky-little


Disassembly of section .text.fwinfo_crc16:

00000000 <fwinfo_crc16>:
   0:	6040      	addu      	r1, r0
   2:	ea03ffff 	movi      	r3, 65535
   6:	6442      	cmpne      	r0, r1
   8:	0803      	bt      	0xe	// e <fwinfo_crc16+0xe>
   a:	6c0f      	mov      	r0, r3
   c:	783c      	jmp      	r15
   e:	8040      	ld.b      	r2, (r0, 0x0)
  10:	6cc9      	xor      	r3, r2
  12:	3208      	movi      	r2, 8
  14:	e5832001 	andi      	r12, r3, 1
  18:	4b61      	lsri      	r3, r3, 1
  1a:	74cd      	zexth      	r3, r3
  1c:	e90c0005 	bez      	r12, 0x26	// 26 <fwinfo_crc16+0x26>
  20:	ea0ca001 	movi      	r12, 40961
  24:	6cf1      	xor      	r3, r12
  26:	2a00      	subi      	r2, 1
  28:	7488      	zextb      	r2, r2
  2a:	e922fff5 	bnez      	r2, 0x14	// 14 <fwinfo_crc16+0x14>
  2e:	2000      	addi      	r0, 1
  30:	07eb      	br      	0x6	// 6 <fwinfo_crc16+0x6>

Disassembly of section .text.fwinfo_crc32:

00000000 <fwinfo_crc32>:
   0:	14c1      	push      	r4
   2:	3300      	movi      	r3, 0
   4:	6040      	addu      	r1, r0
   6:	2b00      	subi      	r3, 1
   8:	ea8c000c 	lrw      	r12, 0xedb88320	// 38 <fwinfo_crc32+0x38>
   c:	6442      	cmpne      	r0, r1
   e:	0804      	bt      	0x16	// 16 <fwinfo_crc32+0x16>
  10:	c4632480 	nor      	r0, r3, r3
  14:	1481      	pop      	r4
  16:	8040      	ld.b      	r2, (r0, 0x0)
  18:	6cc9      	xor      	r3, r2
  1a:	3208      	movi      	r2, 8
  1c:	2a00      	subi      	r2, 1
  1e:	e4832001 	andi      	r4, r3, 1
  22:	7488      	zextb      	r2, r2
  24:	4b61      	lsri      	r3, r3, 1
  26:	6f4f      	mov      	r13, r3
  28:	3c40      	cmpnei      	r4, 0
  2a:	6cf1      	xor      	r3, r12
  2c:	c46d0c20 	incf      	r3, r13, 0
  30:	e922fff6 	bnez      	r2, 0x1c	// 1c <fwinfo_crc32+0x1c>
  34:	2000      	addi      	r0, 1
  36:	07eb      	br      	0xc	// c <fwinfo_crc32+0xc>
  38:	edb88320 	.long	0xedb88320

Disassembly of section .text.fwinfo_check_fwinfo_hdr:

00000000 <fwinfo_check_fwinfo_hdr>:
   0:	14d0      	push      	r15
   2:	e9200008 	bnez      	r0, 0x12	// 12 <fwinfo_check_fwinfo_hdr+0x12>
   6:	100f      	lrw      	r0, 0x0	// 40 <hgprintf+0x40>
   8:	e0000000 	bsr      	0x0	// 0 <hgprintf>
   c:	3000      	movi      	r0, 0
   e:	2815      	subi      	r0, 22
  10:	1490      	pop      	r15
  12:	8061      	ld.b      	r3, (r0, 0x1)
  14:	8040      	ld.b      	r2, (r0, 0x0)
  16:	4368      	lsli      	r3, r3, 8
  18:	6cc8      	or      	r3, r2
  1a:	eb435a69 	cmpnei      	r3, 23145
  1e:	0c03      	bf      	0x24	// 24 <fwinfo_check_fwinfo_hdr+0x24>
  20:	1009      	lrw      	r0, 0x0	// 44 <fwinfo_check_fwinfo_hdr+0x44>
  22:	07f3      	br      	0x8	// 8 <fwinfo_check_fwinfo_hdr+0x8>
  24:	d860006a 	ld.b      	r3, (r0, 0x6a)
  28:	3b42      	cmpnei      	r3, 2
  2a:	0c03      	bf      	0x30	// 30 <fwinfo_check_fwinfo_hdr+0x30>
  2c:	1007      	lrw      	r0, 0x0	// 48 <fwinfo_check_fwinfo_hdr+0x48>
  2e:	07ed      	br      	0x8	// 8 <fwinfo_check_fwinfo_hdr+0x8>
  30:	d8600020 	ld.b      	r3, (r0, 0x20)
  34:	3b41      	cmpnei      	r3, 1
  36:	0c03      	bf      	0x3c	// 3c <fwinfo_check_fwinfo_hdr+0x3c>
  38:	1005      	lrw      	r0, 0x0	// 4c <fwinfo_check_fwinfo_hdr+0x4c>
  3a:	07e7      	br      	0x8	// 8 <fwinfo_check_fwinfo_hdr+0x8>
  3c:	3000      	movi      	r0, 0
  3e:	07e9      	br      	0x10	// 10 <fwinfo_check_fwinfo_hdr+0x10>
	...

Disassembly of section .text.fwinfo_get_fw_aes_en:

00000000 <fwinfo_get_fw_aes_en>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d83      	mov      	r6, r0
   4:	6d47      	mov      	r5, r1
   6:	e0000000 	bsr      	0x0	// 0 <fwinfo_get_fw_aes_en>
   a:	6d03      	mov      	r4, r0
   c:	e9000009 	bez      	r0, 0x1e	// 1e <fwinfo_get_fw_aes_en+0x1e>
  10:	1006      	lrw      	r0, 0x0	// 28 <hgprintf+0x28>
  12:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  16:	b580      	st.w      	r4, (r5, 0x0)
  18:	ea00ffff 	movi      	r0, 65535
  1c:	1493      	pop      	r4-r6, r15
  1e:	b500      	st.w      	r0, (r5, 0x0)
  20:	861b      	ld.b      	r0, (r6, 0x1b)
  22:	c4405440 	zext      	r0, r0, 2, 2
  26:	07fb      	br      	0x1c	// 1c <fwinfo_get_fw_aes_en+0x1c>
  28:	00000000 	.long	0x00000000

Disassembly of section .text.fwinfo_get_fw_crc_en:

00000000 <fwinfo_get_fw_crc_en>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d83      	mov      	r6, r0
   4:	6d47      	mov      	r5, r1
   6:	e0000000 	bsr      	0x0	// 0 <fwinfo_get_fw_crc_en>
   a:	6d03      	mov      	r4, r0
   c:	e9000009 	bez      	r0, 0x1e	// 1e <fwinfo_get_fw_crc_en+0x1e>
  10:	1006      	lrw      	r0, 0x0	// 28 <hgprintf+0x28>
  12:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  16:	b580      	st.w      	r4, (r5, 0x0)
  18:	ea00ffff 	movi      	r0, 65535
  1c:	1493      	pop      	r4-r6, r15
  1e:	b500      	st.w      	r0, (r5, 0x0)
  20:	861b      	ld.b      	r0, (r6, 0x1b)
  22:	c4605460 	zext      	r0, r0, 3, 3
  26:	07fb      	br      	0x1c	// 1c <fwinfo_get_fw_crc_en+0x1c>
  28:	00000000 	.long	0x00000000

Disassembly of section .text.fwinfo_get_fw_dl_addr:

00000000 <fwinfo_get_fw_dl_addr>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d03      	mov      	r4, r0
   4:	6d87      	mov      	r6, r1
   6:	e0000000 	bsr      	0x0	// 0 <fwinfo_get_fw_dl_addr>
   a:	6d43      	mov      	r5, r0
   c:	e9000009 	bez      	r0, 0x1e	// 1e <fwinfo_get_fw_dl_addr+0x1e>
  10:	100a      	lrw      	r0, 0x0	// 38 <hgprintf+0x38>
  12:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  16:	3000      	movi      	r0, 0
  18:	b6a0      	st.w      	r5, (r6, 0x0)
  1a:	2800      	subi      	r0, 1
  1c:	1493      	pop      	r4-r6, r15
  1e:	b600      	st.w      	r0, (r6, 0x0)
  20:	8465      	ld.b      	r3, (r4, 0x5)
  22:	8404      	ld.b      	r0, (r4, 0x4)
  24:	4368      	lsli      	r3, r3, 8
  26:	6cc0      	or      	r3, r0
  28:	8406      	ld.b      	r0, (r4, 0x6)
  2a:	4010      	lsli      	r0, r0, 16
  2c:	6cc0      	or      	r3, r0
  2e:	8407      	ld.b      	r0, (r4, 0x7)
  30:	4018      	lsli      	r0, r0, 24
  32:	6c0c      	or      	r0, r3
  34:	07f4      	br      	0x1c	// 1c <fwinfo_get_fw_dl_addr+0x1c>
  36:	0000      	.short	0x0000
  38:	00000000 	.long	0x00000000

Disassembly of section .text.fwinfo_get_fw_run_addr:

00000000 <fwinfo_get_fw_run_addr>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d03      	mov      	r4, r0
   4:	6d87      	mov      	r6, r1
   6:	e0000000 	bsr      	0x0	// 0 <fwinfo_get_fw_run_addr>
   a:	6d43      	mov      	r5, r0
   c:	e9000009 	bez      	r0, 0x1e	// 1e <fwinfo_get_fw_run_addr+0x1e>
  10:	100a      	lrw      	r0, 0x0	// 38 <hgprintf+0x38>
  12:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  16:	3000      	movi      	r0, 0
  18:	b6a0      	st.w      	r5, (r6, 0x0)
  1a:	2800      	subi      	r0, 1
  1c:	1493      	pop      	r4-r6, r15
  1e:	b600      	st.w      	r0, (r6, 0x0)
  20:	8469      	ld.b      	r3, (r4, 0x9)
  22:	8408      	ld.b      	r0, (r4, 0x8)
  24:	4368      	lsli      	r3, r3, 8
  26:	6cc0      	or      	r3, r0
  28:	840a      	ld.b      	r0, (r4, 0xa)
  2a:	4010      	lsli      	r0, r0, 16
  2c:	6cc0      	or      	r3, r0
  2e:	840b      	ld.b      	r0, (r4, 0xb)
  30:	4018      	lsli      	r0, r0, 24
  32:	6c0c      	or      	r0, r3
  34:	07f4      	br      	0x1c	// 1c <fwinfo_get_fw_run_addr+0x1c>
  36:	0000      	.short	0x0000
  38:	00000000 	.long	0x00000000

Disassembly of section .text.fwinfo_get_fw_code_offset:

00000000 <fwinfo_get_fw_code_offset>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d03      	mov      	r4, r0
   4:	6d87      	mov      	r6, r1
   6:	e0000000 	bsr      	0x0	// 0 <fwinfo_get_fw_code_offset>
   a:	6d43      	mov      	r5, r0
   c:	e9000009 	bez      	r0, 0x1e	// 1e <fwinfo_get_fw_code_offset+0x1e>
  10:	100a      	lrw      	r0, 0x0	// 38 <hgprintf+0x38>
  12:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  16:	3000      	movi      	r0, 0
  18:	b6a0      	st.w      	r5, (r6, 0x0)
  1a:	2800      	subi      	r0, 1
  1c:	1493      	pop      	r4-r6, r15
  1e:	b600      	st.w      	r0, (r6, 0x0)
  20:	846d      	ld.b      	r3, (r4, 0xd)
  22:	840c      	ld.b      	r0, (r4, 0xc)
  24:	4368      	lsli      	r3, r3, 8
  26:	6cc0      	or      	r3, r0
  28:	840e      	ld.b      	r0, (r4, 0xe)
  2a:	4010      	lsli      	r0, r0, 16
  2c:	6cc0      	or      	r3, r0
  2e:	840f      	ld.b      	r0, (r4, 0xf)
  30:	4018      	lsli      	r0, r0, 24
  32:	6c0c      	or      	r0, r3
  34:	07f4      	br      	0x1c	// 1c <fwinfo_get_fw_code_offset+0x1c>
  36:	0000      	.short	0x0000
  38:	00000000 	.long	0x00000000

Disassembly of section .text.fwinfo_get_fw_local_crc32:

00000000 <fwinfo_get_fw_local_crc32>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d03      	mov      	r4, r0
   4:	6d87      	mov      	r6, r1
   6:	e0000000 	bsr      	0x0	// 0 <fwinfo_get_fw_local_crc32>
   a:	6d43      	mov      	r5, r0
   c:	e9000009 	bez      	r0, 0x1e	// 1e <fwinfo_get_fw_local_crc32+0x1e>
  10:	100c      	lrw      	r0, 0x0	// 40 <hgprintf+0x40>
  12:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  16:	3000      	movi      	r0, 0
  18:	b6a0      	st.w      	r5, (r6, 0x0)
  1a:	2800      	subi      	r0, 1
  1c:	1493      	pop      	r4-r6, r15
  1e:	b600      	st.w      	r0, (r6, 0x0)
  20:	d864007c 	ld.b      	r3, (r4, 0x7c)
  24:	d804007b 	ld.b      	r0, (r4, 0x7b)
  28:	4368      	lsli      	r3, r3, 8
  2a:	6cc0      	or      	r3, r0
  2c:	d804007d 	ld.b      	r0, (r4, 0x7d)
  30:	4010      	lsli      	r0, r0, 16
  32:	6cc0      	or      	r3, r0
  34:	d804007e 	ld.b      	r0, (r4, 0x7e)
  38:	4018      	lsli      	r0, r0, 24
  3a:	6c0c      	or      	r0, r3
  3c:	07f0      	br      	0x1c	// 1c <fwinfo_get_fw_local_crc32+0x1c>
  3e:	0000      	.short	0x0000
  40:	00000000 	.long	0x00000000

Disassembly of section .text.fwinfo_get_fw_sdk_version:

00000000 <fwinfo_get_fw_sdk_version>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d03      	mov      	r4, r0
   4:	6d87      	mov      	r6, r1
   6:	e0000000 	bsr      	0x0	// 0 <fwinfo_get_fw_sdk_version>
   a:	6d43      	mov      	r5, r0
   c:	e9000009 	bez      	r0, 0x1e	// 1e <fwinfo_get_fw_sdk_version+0x1e>
  10:	100c      	lrw      	r0, 0x0	// 40 <hgprintf+0x40>
  12:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  16:	3000      	movi      	r0, 0
  18:	b6a0      	st.w      	r5, (r6, 0x0)
  1a:	2800      	subi      	r0, 1
  1c:	1493      	pop      	r4-r6, r15
  1e:	b600      	st.w      	r0, (r6, 0x0)
  20:	d864006d 	ld.b      	r3, (r4, 0x6d)
  24:	d804006c 	ld.b      	r0, (r4, 0x6c)
  28:	4368      	lsli      	r3, r3, 8
  2a:	6cc0      	or      	r3, r0
  2c:	d804006e 	ld.b      	r0, (r4, 0x6e)
  30:	4010      	lsli      	r0, r0, 16
  32:	6cc0      	or      	r3, r0
  34:	d804006f 	ld.b      	r0, (r4, 0x6f)
  38:	4018      	lsli      	r0, r0, 24
  3a:	6c0c      	or      	r0, r3
  3c:	07f0      	br      	0x1c	// 1c <fwinfo_get_fw_sdk_version+0x1c>
  3e:	0000      	.short	0x0000
  40:	00000000 	.long	0x00000000

Disassembly of section .text.fwinfo_get_fw_svn_version:

00000000 <fwinfo_get_fw_svn_version>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d03      	mov      	r4, r0
   4:	6d87      	mov      	r6, r1
   6:	e0000000 	bsr      	0x0	// 0 <fwinfo_get_fw_svn_version>
   a:	6d43      	mov      	r5, r0
   c:	e9000009 	bez      	r0, 0x1e	// 1e <fwinfo_get_fw_svn_version+0x1e>
  10:	100c      	lrw      	r0, 0x0	// 40 <hgprintf+0x40>
  12:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  16:	3000      	movi      	r0, 0
  18:	b6a0      	st.w      	r5, (r6, 0x0)
  1a:	2800      	subi      	r0, 1
  1c:	1493      	pop      	r4-r6, r15
  1e:	b600      	st.w      	r0, (r6, 0x0)
  20:	d8640071 	ld.b      	r3, (r4, 0x71)
  24:	d8040070 	ld.b      	r0, (r4, 0x70)
  28:	4368      	lsli      	r3, r3, 8
  2a:	6cc0      	or      	r3, r0
  2c:	d8040072 	ld.b      	r0, (r4, 0x72)
  30:	4010      	lsli      	r0, r0, 16
  32:	6cc0      	or      	r3, r0
  34:	d8040073 	ld.b      	r0, (r4, 0x73)
  38:	4018      	lsli      	r0, r0, 24
  3a:	6c0c      	or      	r0, r3
  3c:	07f0      	br      	0x1c	// 1c <fwinfo_get_fw_svn_version+0x1c>
  3e:	0000      	.short	0x0000
  40:	00000000 	.long	0x00000000

Disassembly of section .text.fwinfo_get_fw_chipid:

00000000 <fwinfo_get_fw_chipid>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d43      	mov      	r5, r0
   4:	6d87      	mov      	r6, r1
   6:	e0000000 	bsr      	0x0	// 0 <fwinfo_get_fw_chipid>
   a:	6d03      	mov      	r4, r0
   c:	e9000009 	bez      	r0, 0x1e	// 1e <fwinfo_get_fw_chipid+0x1e>
  10:	1008      	lrw      	r0, 0x0	// 30 <hgprintf+0x30>
  12:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  16:	b680      	st.w      	r4, (r6, 0x0)
  18:	ea00ffff 	movi      	r0, 65535
  1c:	1493      	pop      	r4-r6, r15
  1e:	b600      	st.w      	r0, (r6, 0x0)
  20:	d8050079 	ld.b      	r0, (r5, 0x79)
  24:	d8650078 	ld.b      	r3, (r5, 0x78)
  28:	4008      	lsli      	r0, r0, 8
  2a:	6c0c      	or      	r0, r3
  2c:	07f8      	br      	0x1c	// 1c <fwinfo_get_fw_chipid+0x1c>
  2e:	0000      	.short	0x0000
  30:	00000000 	.long	0x00000000

Disassembly of section .text.fwinfo_get_fw_cpuid:

00000000 <fwinfo_get_fw_cpuid>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d83      	mov      	r6, r0
   4:	6d47      	mov      	r5, r1
   6:	e0000000 	bsr      	0x0	// 0 <fwinfo_get_fw_cpuid>
   a:	6d03      	mov      	r4, r0
   c:	e9000008 	bez      	r0, 0x1c	// 1c <fwinfo_get_fw_cpuid+0x1c>
  10:	1005      	lrw      	r0, 0x0	// 24 <hgprintf+0x24>
  12:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  16:	b580      	st.w      	r4, (r5, 0x0)
  18:	30ff      	movi      	r0, 255
  1a:	1493      	pop      	r4-r6, r15
  1c:	b500      	st.w      	r0, (r5, 0x0)
  1e:	d806007a 	ld.b      	r0, (r6, 0x7a)
  22:	07fc      	br      	0x1a	// 1a <fwinfo_get_fw_cpuid+0x1a>
  24:	00000000 	.long	0x00000000

Disassembly of section .text.fwinfo_get_fw_lenght:

00000000 <fwinfo_get_fw_lenght>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d03      	mov      	r4, r0
   4:	6d87      	mov      	r6, r1
   6:	e0000000 	bsr      	0x0	// 0 <fwinfo_get_fw_lenght>
   a:	6d43      	mov      	r5, r0
   c:	e9000009 	bez      	r0, 0x1e	// 1e <fwinfo_get_fw_lenght+0x1e>
  10:	100f      	lrw      	r0, 0x0	// 4c <hgprintf+0x4c>
  12:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  16:	3000      	movi      	r0, 0
  18:	b6a0      	st.w      	r5, (r6, 0x0)
  1a:	2800      	subi      	r0, 1
  1c:	1493      	pop      	r4-r6, r15
  1e:	b600      	st.w      	r0, (r6, 0x0)
  20:	8471      	ld.b      	r3, (r4, 0x11)
  22:	8410      	ld.b      	r0, (r4, 0x10)
  24:	4368      	lsli      	r3, r3, 8
  26:	6cc0      	or      	r3, r0
  28:	8412      	ld.b      	r0, (r4, 0x12)
  2a:	4010      	lsli      	r0, r0, 16
  2c:	6cc0      	or      	r3, r0
  2e:	8413      	ld.b      	r0, (r4, 0x13)
  30:	4018      	lsli      	r0, r0, 24
  32:	844d      	ld.b      	r2, (r4, 0xd)
  34:	6c0c      	or      	r0, r3
  36:	4248      	lsli      	r2, r2, 8
  38:	846c      	ld.b      	r3, (r4, 0xc)
  3a:	6c8c      	or      	r2, r3
  3c:	846e      	ld.b      	r3, (r4, 0xe)
  3e:	4370      	lsli      	r3, r3, 16
  40:	6c8c      	or      	r2, r3
  42:	846f      	ld.b      	r3, (r4, 0xf)
  44:	4378      	lsli      	r3, r3, 24
  46:	6cc8      	or      	r3, r2
  48:	600c      	addu      	r0, r3
  4a:	07e9      	br      	0x1c	// 1c <fwinfo_get_fw_lenght+0x1c>
  4c:	00000000 	.long	0x00000000

Disassembly of section .text.fwinfo_get_fw_code_checksum:

00000000 <fwinfo_get_fw_code_checksum>:
   0:	14d4      	push      	r4-r7, r15
   2:	1421      	subi      	r14, r14, 4
   4:	6d87      	mov      	r6, r1
   6:	3300      	movi      	r3, 0
   8:	6c7b      	mov      	r1, r14
   a:	b860      	st.w      	r3, (r14, 0x0)
   c:	6d43      	mov      	r5, r0
   e:	e0000000 	bsr      	0x0	// 0 <fwinfo_get_fw_code_checksum>
  12:	9860      	ld.w      	r3, (r14, 0x0)
  14:	6dc3      	mov      	r7, r0
  16:	e9030009 	bez      	r3, 0x28	// 28 <fwinfo_get_fw_code_checksum+0x28>
  1a:	1016      	lrw      	r0, 0x0	// 70 <hgprintf+0x70>
  1c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  20:	9880      	ld.w      	r4, (r14, 0x0)
  22:	6c13      	mov      	r0, r4
  24:	1401      	addi      	r14, r14, 4
  26:	1494      	pop      	r4-r7, r15
  28:	6c7b      	mov      	r1, r14
  2a:	6c17      	mov      	r0, r5
  2c:	e0000000 	bsr      	0x0	// 0 <fwinfo_get_fw_code_checksum>
  30:	9880      	ld.w      	r4, (r14, 0x0)
  32:	e9040004 	bez      	r4, 0x3a	// 3a <fwinfo_get_fw_code_checksum+0x3a>
  36:	1010      	lrw      	r0, 0x0	// 74 <fwinfo_get_fw_code_checksum+0x74>
  38:	07f2      	br      	0x1c	// 1c <fwinfo_get_fw_code_checksum+0x1c>
  3a:	5e21      	subu      	r1, r6, r0
  3c:	6140      	addu      	r5, r0
  3e:	e9a10008 	bhsz      	r1, 0x4e	// 4e <fwinfo_get_fw_code_checksum+0x4e>
  42:	100e      	lrw      	r0, 0x0	// 78 <fwinfo_get_fw_code_checksum+0x78>
  44:	3400      	movi      	r4, 0
  46:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  4a:	2c15      	subi      	r4, 22
  4c:	07eb      	br      	0x22	// 22 <fwinfo_get_fw_code_checksum+0x22>
  4e:	6c17      	mov      	r0, r5
  50:	e0000000 	bsr      	0x0	// 0 <fwinfo_get_fw_code_checksum>
  54:	641e      	cmpne      	r7, r0
  56:	6c83      	mov      	r2, r0
  58:	0fe5      	bf      	0x22	// 22 <fwinfo_get_fw_code_checksum+0x22>
  5a:	c4002483 	nor      	r3, r0, r0
  5e:	64de      	cmpne      	r7, r3
  60:	0fe1      	bf      	0x22	// 22 <fwinfo_get_fw_code_checksum+0x22>
  62:	6c5f      	mov      	r1, r7
  64:	1006      	lrw      	r0, 0x0	// 7c <fwinfo_get_fw_code_checksum+0x7c>
  66:	3400      	movi      	r4, 0
  68:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  6c:	2c0d      	subi      	r4, 14
  6e:	07da      	br      	0x22	// 22 <fwinfo_get_fw_code_checksum+0x22>
	...

Disassembly of section .text.fwinfo_check_customer_id:

00000000 <fwinfo_check_customer_id>:
   0:	14d4      	push      	r4-r7, r15
   2:	1425      	subi      	r14, r14, 20
   4:	6d43      	mov      	r5, r0
   6:	e0000000 	bsr      	0x0	// 0 <fwinfo_check_customer_id>
   a:	6d03      	mov      	r4, r0
   c:	e9000007 	bez      	r0, 0x1a	// 1a <fwinfo_check_customer_id+0x1a>
  10:	6c43      	mov      	r1, r0
  12:	1203      	lrw      	r0, 0x0	// 11c <fwinfo_check_customer_id+0x11c>
  14:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  18:	041d      	br      	0x52	// 52 <fwinfo_check_customer_id+0x52>
  1a:	e4e500ff 	addi      	r7, r5, 256
  1e:	6c1f      	mov      	r0, r7
  20:	e0000000 	bsr      	0x0	// 0 <fwinfo_check_customer_id>
  24:	e9000006 	bez      	r0, 0x30	// 30 <fwinfo_check_customer_id+0x30>
  28:	111e      	lrw      	r0, 0x0	// 120 <hgprintf+0x120>
  2a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  2e:	6dd7      	mov      	r7, r5
  30:	877b      	ld.b      	r3, (r7, 0x1b)
  32:	e4632004 	andi      	r3, r3, 4
  36:	e9230005 	bnez      	r3, 0x40	// 40 <fwinfo_check_customer_id+0x40>
  3a:	113b      	lrw      	r1, 0x0	// 124 <fwinfo_check_customer_id+0x124>
  3c:	111b      	lrw      	r0, 0x0	// 128 <fwinfo_check_customer_id+0x128>
  3e:	07eb      	br      	0x14	// 14 <fwinfo_check_customer_id+0x14>
  40:	d8670083 	ld.b      	r3, (r7, 0x83)
  44:	3b43      	cmpnei      	r3, 3
  46:	0c09      	bf      	0x58	// 58 <fwinfo_check_customer_id+0x58>
  48:	1119      	lrw      	r0, 0x0	// 12c <fwinfo_check_customer_id+0x12c>
  4a:	3400      	movi      	r4, 0
  4c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  50:	2c15      	subi      	r4, 22
  52:	6c13      	mov      	r0, r4
  54:	1405      	addi      	r14, r14, 20
  56:	1494      	pop      	r4-r7, r15
  58:	3600      	movi      	r6, 0
  5a:	b8c1      	st.w      	r6, (r14, 0x4)
  5c:	dcce1004 	st.h      	r6, (r14, 0x8)
  60:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_customer_id>
  64:	6d43      	mov      	r5, r0
  66:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_customer_id>
  6a:	5008      	asri      	r0, r0, 8
  6c:	4528      	lsli      	r1, r5, 8
  6e:	6c40      	or      	r1, r0
  70:	7445      	zexth      	r1, r1
  72:	5963      	subi      	r3, r1, 1
  74:	74cd      	zexth      	r3, r3
  76:	e4ae0001 	addi      	r5, r14, 2
  7a:	eb03fffd 	cmphsi      	r3, 65534
  7e:	ad20      	st.h      	r1, (r5, 0x0)
  80:	0c08      	bf      	0x90	// 90 <fwinfo_check_customer_id+0x90>
  82:	110c      	lrw      	r0, 0x0	// 130 <fwinfo_check_customer_id+0x130>
  84:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  88:	340d      	movi      	r4, 13
  8a:	6c53      	mov      	r1, r4
  8c:	110a      	lrw      	r0, 0x0	// 134 <fwinfo_check_customer_id+0x134>
  8e:	07c3      	br      	0x14	// 14 <fwinfo_check_customer_id+0x14>
  90:	d8670083 	ld.b      	r3, (r7, 0x83)
  94:	3b43      	cmpnei      	r3, 3
  96:	e4270082 	addi      	r1, r7, 131
  9a:	0c07      	bf      	0xa8	// a8 <fwinfo_check_customer_id+0xa8>
  9c:	6c4f      	mov      	r1, r3
  9e:	1107      	lrw      	r0, 0x0	// 138 <fwinfo_check_customer_id+0x138>
  a0:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  a4:	3416      	movi      	r4, 22
  a6:	07f2      	br      	0x8a	// 8a <fwinfo_check_customer_id+0x8a>
  a8:	3206      	movi      	r2, 6
  aa:	1803      	addi      	r0, r14, 12
  ac:	e0000000 	bsr      	0x0	// 0 <memcpy>
  b0:	6cdb      	mov      	r3, r6
  b2:	6c5b      	mov      	r1, r6
  b4:	1a03      	addi      	r2, r14, 12
  b6:	5a04      	addu      	r0, r2, r1
  b8:	2100      	addi      	r1, 1
  ba:	d0650022 	ldr.b      	r2, (r5, r3 << 0)
  be:	d9800002 	ld.b      	r12, (r0, 0x2)
  c2:	3944      	cmpnei      	r1, 4
  c4:	6cb1      	xor      	r2, r12
  c6:	a042      	st.b      	r2, (r0, 0x2)
  c8:	e4634001 	xori      	r3, r3, 1
  cc:	0bf4      	bt      	0xb4	// b4 <fwinfo_check_customer_id+0xb4>
  ce:	9863      	ld.w      	r3, (r14, 0xc)
  d0:	d8ae1008 	ld.h      	r5, (r14, 0x10)
  d4:	1801      	addi      	r0, r14, 4
  d6:	b861      	st.w      	r3, (r14, 0x4)
  d8:	dcae1004 	st.h      	r5, (r14, 0x8)
  dc:	e0000000 	bsr      	0x0	// 0 <fwinfo_check_customer_id>
  e0:	7495      	zexth      	r2, r5
  e2:	6482      	cmpne      	r0, r2
  e4:	6c43      	mov      	r1, r0
  e6:	0c09      	bf      	0xf8	// f8 <fwinfo_check_customer_id+0xf8>
  e8:	c4422483 	nor      	r3, r2, r2
  ec:	74cd      	zexth      	r3, r3
  ee:	1014      	lrw      	r0, 0x0	// 13c <fwinfo_check_customer_id+0x13c>
  f0:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  f4:	3473      	movi      	r4, 115
  f6:	07ae      	br      	0x52	// 52 <fwinfo_check_customer_id+0x52>
  f8:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_customer_id>
  fc:	6d43      	mov      	r5, r0
  fe:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_customer_id>
 102:	5008      	asri      	r0, r0, 8
 104:	4568      	lsli      	r3, r5, 8
 106:	6cc0      	or      	r3, r0
 108:	d84e1003 	ld.h      	r2, (r14, 0x6)
 10c:	74cd      	zexth      	r3, r3
 10e:	64ca      	cmpne      	r2, r3
 110:	0fa1      	bf      	0x52	// 52 <fwinfo_check_customer_id+0x52>
 112:	100c      	lrw      	r0, 0x0	// 140 <fwinfo_check_customer_id+0x140>
 114:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 118:	340d      	movi      	r4, 13
 11a:	079c      	br      	0x52	// 52 <fwinfo_check_customer_id+0x52>
	...
