
disasm/libcommon/obj/common_sysevt.o:     file format elf32-csky-little


Disassembly of section .text.sys_evt_work:

00000000 <sys_evt_work>:
   0:	14d8      	push      	r4-r11, r15
   2:	1421      	subi      	r14, r14, 4
   4:	1187      	lrw      	r4, 0x0	// a0 <sys_evt_work+0xa0>
   6:	6dd3      	mov      	r7, r4
   8:	e5040003 	addi      	r8, r4, 4
   c:	946c      	ld.w      	r3, (r4, 0x30)
   e:	944d      	ld.w      	r2, (r4, 0x34)
  10:	64ca      	cmpne      	r2, r3
  12:	0804      	bt      	0x1a	// 1a <sys_evt_work+0x1a>
  14:	3000      	movi      	r0, 0
  16:	1401      	addi      	r14, r14, 4
  18:	1498      	pop      	r4-r11, r15
  1a:	4323      	lsli      	r1, r3, 3
  1c:	944f      	ld.w      	r2, (r4, 0x3c)
  1e:	6084      	addu      	r2, r1
  20:	2300      	addi      	r3, 1
  22:	92c0      	ld.w      	r6, (r2, 0x0)
  24:	d9222001 	ld.w      	r9, (r2, 0x4)
  28:	944e      	ld.w      	r2, (r4, 0x38)
  2a:	5b29      	subu      	r1, r3, r2
  2c:	648d      	cmplt      	r3, r2
  2e:	c4610c20 	incf      	r3, r1, 0
  32:	3100      	movi      	r1, 0
  34:	2900      	subi      	r1, 1
  36:	6c23      	mov      	r0, r8
  38:	b76c      	st.w      	r3, (r7, 0x30)
  3a:	3500      	movi      	r5, 0
  3c:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  40:	ea23ffff 	movih      	r3, 65535
  44:	d9472000 	ld.w      	r10, (r7, 0x0)
  48:	e5651000 	subi      	r11, r5, 1
  4c:	c466202c 	and      	r12, r6, r3
  50:	e92a000c 	bnez      	r10, 0x68	// 68 <sys_evt_work+0x68>
  54:	6c23      	mov      	r0, r8
  56:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  5a:	e925ffd9 	bnez      	r5, 0xc	// c <sys_evt_work+0xc>
  5e:	6c5b      	mov      	r1, r6
  60:	1011      	lrw      	r0, 0x0	// a4 <sys_evt_work+0xa4>
  62:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  66:	07d3      	br      	0xc	// c <sys_evt_work+0xc>
  68:	d86a2001 	ld.w      	r3, (r10, 0x4)
  6c:	66ce      	cmpne      	r3, r11
  6e:	0c05      	bf      	0x78	// 78 <sys_evt_work+0x78>
  70:	658e      	cmpne      	r3, r6
  72:	0c03      	bf      	0x78	// 78 <sys_evt_work+0x78>
  74:	670e      	cmpne      	r3, r12
  76:	080f      	bt      	0x94	// 94 <sys_evt_work+0x94>
  78:	d86a2003 	ld.w      	r3, (r10, 0xc)
  7c:	d84a2002 	ld.w      	r2, (r10, 0x8)
  80:	6c67      	mov      	r1, r9
  82:	6c1b      	mov      	r0, r6
  84:	dd8e2000 	st.w      	r12, (r14, 0x0)
  88:	7bcd      	jsr      	r3
  8a:	3841      	cmpnei      	r0, 1
  8c:	0c07      	bf      	0x9a	// 9a <sys_evt_work+0x9a>
  8e:	3501      	movi      	r5, 1
  90:	d98e2000 	ld.w      	r12, (r14, 0x0)
  94:	d94a2000 	ld.w      	r10, (r10, 0x0)
  98:	07dc      	br      	0x50	// 50 <sys_evt_work+0x50>
  9a:	6d43      	mov      	r5, r0
  9c:	07dc      	br      	0x54	// 54 <sys_evt_work+0x54>
	...

Disassembly of section .text.sys_event_init:

00000000 <sys_event_init>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d03      	mov      	r4, r0
   4:	2000      	addi      	r0, 1
   6:	4003      	lsli      	r0, r0, 3
   8:	e0000000 	bsr      	0x0	// 0 <_os_malloc>
   c:	6d43      	mov      	r5, r0
   e:	e9200009 	bnez      	r0, 0x20	// 20 <sys_event_init+0x20>
  12:	1010      	lrw      	r0, 0x0	// 50 <sys_event_init+0x50>
  14:	6c53      	mov      	r1, r4
  16:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  1a:	3000      	movi      	r0, 0
  1c:	2800      	subi      	r0, 1
  1e:	1492      	pop      	r4-r5, r15
  20:	100d      	lrw      	r0, 0x0	// 54 <sys_event_init+0x54>
  22:	e0000000 	bsr      	0x0	// 0 <os_mutex_init>
  26:	106d      	lrw      	r3, 0x0	// 58 <sys_event_init+0x58>
  28:	104d      	lrw      	r2, 0x0	// 5c <sys_event_init+0x5c>
  2a:	3000      	movi      	r0, 0
  2c:	b34a      	st.w      	r2, (r3, 0x28)
  2e:	8358      	ld.b      	r2, (r3, 0x18)
  30:	c4405c83 	ins      	r2, r0, 7, 3
  34:	a358      	st.b      	r2, (r3, 0x18)
  36:	3101      	movi      	r1, 1
  38:	d843002e 	ld.b      	r2, (r3, 0x2e)
  3c:	c4415c00 	ins      	r2, r1, 0, 0
  40:	b38e      	st.w      	r4, (r3, 0x38)
  42:	b30c      	st.w      	r0, (r3, 0x30)
  44:	b30d      	st.w      	r0, (r3, 0x34)
  46:	b3af      	st.w      	r5, (r3, 0x3c)
  48:	ab96      	st.h      	r4, (r3, 0x2c)
  4a:	dc43002e 	st.b      	r2, (r3, 0x2e)
  4e:	07e8      	br      	0x1e	// 1e <sys_event_init+0x1e>
	...

Disassembly of section .text.sys_event_new:

00000000 <sys_event_new>:
   0:	14d1      	push      	r4, r15
   2:	1077      	lrw      	r3, 0x0	// 5c <sys_event_new+0x5c>
   4:	d843002e 	ld.b      	r2, (r3, 0x2e)
   8:	e4422001 	andi      	r2, r2, 1
   c:	e9220008 	bnez      	r2, 0x1c	// 1c <sys_event_new+0x1c>
  10:	1014      	lrw      	r0, 0x0	// 60 <hgprintf+0x60>
  12:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  16:	3000      	movi      	r0, 0
  18:	2800      	subi      	r0, 1
  1a:	041f      	br      	0x58	// 58 <sys_event_new+0x58>
  1c:	d983200d 	ld.w      	r12, (r3, 0x34)
  20:	e44c0000 	addi      	r2, r12, 1
  24:	d9a3200e 	ld.w      	r13, (r3, 0x38)
  28:	6749      	cmplt      	r2, r13
  2a:	c5a20084 	subu      	r4, r2, r13
  2e:	c4440c20 	incf      	r2, r4, 0
  32:	d9a3200c 	ld.w      	r13, (r3, 0x30)
  36:	674a      	cmpne      	r2, r13
  38:	0fef      	bf      	0x16	// 16 <sys_event_new+0x16>
  3a:	c46c482d 	lsli      	r13, r12, 3
  3e:	d983200f 	ld.w      	r12, (r3, 0x3c)
  42:	6334      	addu      	r12, r13
  44:	dc0c2000 	st.w      	r0, (r12, 0x0)
  48:	dc2c2001 	st.w      	r1, (r12, 0x4)
  4c:	e403000b 	addi      	r0, r3, 12
  50:	b34d      	st.w      	r2, (r3, 0x34)
  52:	e0000000 	bsr      	0x0	// 0 <os_run_work>
  56:	3000      	movi      	r0, 0
  58:	1491      	pop      	r4, r15
	...

Disassembly of section .text.sys_event_take:

00000000 <sys_event_take>:
   0:	14d5      	push      	r4-r8, r15
   2:	11a0      	lrw      	r5, 0x0	// 80 <sys_event_take+0x80>
   4:	6d83      	mov      	r6, r0
   6:	d865002e 	ld.b      	r3, (r5, 0x2e)
   a:	e4632001 	andi      	r3, r3, 1
   e:	6dc7      	mov      	r7, r1
  10:	6e0b      	mov      	r8, r2
  12:	e9230009 	bnez      	r3, 0x24	// 24 <sys_event_take+0x24>
  16:	101c      	lrw      	r0, 0x0	// 84 <sys_event_take+0x84>
  18:	3400      	movi      	r4, 0
  1a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  1e:	2c00      	subi      	r4, 1
  20:	6c13      	mov      	r0, r4
  22:	1495      	pop      	r4-r8, r15
  24:	e901002b 	bez      	r1, 0x7a	// 7a <sys_event_take+0x7a>
  28:	e9000029 	bez      	r0, 0x7a	// 7a <sys_event_take+0x7a>
  2c:	3100      	movi      	r1, 0
  2e:	2900      	subi      	r1, 1
  30:	5d0e      	addi      	r0, r5, 4
  32:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  36:	9580      	ld.w      	r4, (r5, 0x0)
  38:	e924000a 	bnez      	r4, 0x4c	// 4c <sys_event_take+0x4c>
  3c:	3010      	movi      	r0, 16
  3e:	e0000000 	bsr      	0x0	// 0 <_os_zalloc>
  42:	e9200014 	bnez      	r0, 0x6a	// 6a <sys_event_take+0x6a>
  46:	3400      	movi      	r4, 0
  48:	2c00      	subi      	r4, 1
  4a:	040a      	br      	0x5e	// 5e <sys_event_take+0x5e>
  4c:	9461      	ld.w      	r3, (r4, 0x4)
  4e:	64da      	cmpne      	r6, r3
  50:	080b      	bt      	0x66	// 66 <sys_event_take+0x66>
  52:	9463      	ld.w      	r3, (r4, 0xc)
  54:	64de      	cmpne      	r7, r3
  56:	0808      	bt      	0x66	// 66 <sys_event_take+0x66>
  58:	dd042002 	st.w      	r8, (r4, 0x8)
  5c:	3400      	movi      	r4, 0
  5e:	100b      	lrw      	r0, 0x0	// 88 <sys_event_take+0x88>
  60:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  64:	07de      	br      	0x20	// 20 <sys_event_take+0x20>
  66:	9480      	ld.w      	r4, (r4, 0x0)
  68:	07e8      	br      	0x38	// 38 <sys_event_take+0x38>
  6a:	9560      	ld.w      	r3, (r5, 0x0)
  6c:	b060      	st.w      	r3, (r0, 0x0)
  6e:	b0e3      	st.w      	r7, (r0, 0xc)
  70:	b0c1      	st.w      	r6, (r0, 0x4)
  72:	dd002002 	st.w      	r8, (r0, 0x8)
  76:	b500      	st.w      	r0, (r5, 0x0)
  78:	07f3      	br      	0x5e	// 5e <sys_event_take+0x5e>
  7a:	3400      	movi      	r4, 0
  7c:	2c15      	subi      	r4, 22
  7e:	07d1      	br      	0x20	// 20 <sys_event_take+0x20>
	...

Disassembly of section .text.sys_event_untake:

00000000 <sys_event_untake>:
   0:	14d3      	push      	r4-r6, r15
   2:	1096      	lrw      	r4, 0x0	// 58 <sys_event_untake+0x58>
   4:	6d43      	mov      	r5, r0
   6:	d864002e 	ld.b      	r3, (r4, 0x2e)
   a:	e4632001 	andi      	r3, r3, 1
   e:	6d87      	mov      	r6, r1
  10:	e9230006 	bnez      	r3, 0x1c	// 1c <sys_event_untake+0x1c>
  14:	1012      	lrw      	r0, 0x0	// 5c <hgprintf+0x5c>
  16:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  1a:	1493      	pop      	r4-r6, r15
  1c:	3100      	movi      	r1, 0
  1e:	2900      	subi      	r1, 1
  20:	5c0e      	addi      	r0, r4, 4
  22:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  26:	9400      	ld.w      	r0, (r4, 0x0)
  28:	3300      	movi      	r3, 0
  2a:	e900000e 	bez      	r0, 0x46	// 46 <sys_event_untake+0x46>
  2e:	9041      	ld.w      	r2, (r0, 0x4)
  30:	654a      	cmpne      	r2, r5
  32:	9040      	ld.w      	r2, (r0, 0x0)
  34:	080f      	bt      	0x52	// 52 <sys_event_untake+0x52>
  36:	9023      	ld.w      	r1, (r0, 0xc)
  38:	6586      	cmpne      	r1, r6
  3a:	080c      	bt      	0x52	// 52 <sys_event_untake+0x52>
  3c:	e9030009 	bez      	r3, 0x4e	// 4e <sys_event_untake+0x4e>
  40:	b340      	st.w      	r2, (r3, 0x0)
  42:	e0000000 	bsr      	0x0	// 0 <_os_free>
  46:	1007      	lrw      	r0, 0x0	// 60 <os_mutex_unlock+0x60>
  48:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  4c:	07e7      	br      	0x1a	// 1a <sys_event_untake+0x1a>
  4e:	b440      	st.w      	r2, (r4, 0x0)
  50:	07f9      	br      	0x42	// 42 <sys_event_untake+0x42>
  52:	6cc3      	mov      	r3, r0
  54:	6c0b      	mov      	r0, r2
  56:	07ea      	br      	0x2a	// 2a <sys_event_untake+0x2a>
	...
