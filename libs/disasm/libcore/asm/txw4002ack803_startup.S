
disasm/libcore/obj/txw4002ack803_startup.o:     file format elf32-csky-little


Disassembly of section .text:

00000000 <Reset_Handler>:
   0:	c1807020 	psrclr      	ee, ie
   4:	101b      	lrw      	r0, 0x80000200	// 70 <._load_loop_done+0x4>
   6:	c0006420 	mtcr      	r0, cr<0, 0>
   a:	c01f6020 	mfcr      	r0, cr<31, 0>
   e:	3883      	bclri      	r0, 3
  10:	c000643f 	mtcr      	r0, cr<31, 0>
  14:	1018      	lrw      	r0, 0x0	// 74 <._load_loop_done+0x8>
  16:	6f83      	mov      	r14, r0
  18:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
  1c:	e0000000 	bsr      	0x0	// 0 <cpu_clk_sel_hosc>
  20:	e0000000 	bsr      	0x0	// 0 <boot_reload>
  24:	1035      	lrw      	r1, 0x0	// 78 <._load_loop_done+0xc>
  26:	1056      	lrw      	r2, 0x0	// 7c <._load_loop_done+0x10>
  28:	1076      	lrw      	r3, 0x0	// 80 <._load_loop_done+0x14>
  2a:	e0000000 	bsr      	0x0	// 54 <load_data_section>
  2e:	1036      	lrw      	r1, 0x0	// 84 <._load_loop_done+0x18>
  30:	1056      	lrw      	r2, 0x0	// 88 <._load_loop_done+0x1c>
  32:	e0000000 	bsr      	0x0	// 40 <clear_bss_section>
  36:	e0000000 	bsr      	0x0	// 0 <SystemInit>
  3a:	e0000000 	bsr      	0x0	// 0 <pre_main>

0000003e <__exit>:
  3e:	0400      	br      	0x3e	// 3e <__exit>

00000040 <clear_bss_section>:
  40:	3000      	movi      	r0, 0
  42:	6086      	subu      	r2, r1
  44:	3a40      	cmpnei      	r2, 0
  46:	0c06      	bf      	0x52	// 52 <._clear_loop_done>

00000048 <._clear_loop>:
  48:	b100      	st.w      	r0, (r1, 0x0)
  4a:	2103      	addi      	r1, 4
  4c:	2a03      	subi      	r2, 4
  4e:	3a40      	cmpnei      	r2, 0
  50:	0bfc      	bt      	0x48	// 48 <._clear_loop>

00000052 <._clear_loop_done>:
  52:	783c      	jmp      	r15

00000054 <load_data_section>:
  54:	6486      	cmpne      	r1, r2
  56:	0c0b      	bf      	0x6c	// 6c <._load_loop_done>
  58:	60ca      	subu      	r3, r2
  5a:	3b40      	cmpnei      	r3, 0
  5c:	0c08      	bf      	0x6c	// 6c <._load_loop_done>

0000005e <._load_loop>:
  5e:	9100      	ld.w      	r0, (r1, 0x0)
  60:	b200      	st.w      	r0, (r2, 0x0)
  62:	2103      	addi      	r1, 4
  64:	2203      	addi      	r2, 4
  66:	2b03      	subi      	r3, 4
  68:	3b40      	cmpnei      	r3, 0
  6a:	0bfa      	bt      	0x5e	// 5e <._load_loop>

0000006c <._load_loop_done>:
  6c:	783c      	jmp      	r15
  6e:	0000      	.short	0x0000
  70:	80000200 	.long	0x80000200
	...
