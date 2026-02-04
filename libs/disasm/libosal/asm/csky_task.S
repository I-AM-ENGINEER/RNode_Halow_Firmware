
disasm/libosal/obj/csky_task.o:     file format elf32-csky-little


Disassembly of section .text.os_task_entry:

00000000 <os_task_entry>:
   0:	14d0      	push      	r15
   2:	9061      	ld.w      	r3, (r0, 0x4)
   4:	9003      	ld.w      	r0, (r0, 0xc)
   6:	7bcd      	jsr      	r3
   8:	1490      	pop      	r15

Disassembly of section .text.os_task_init:

00000000 <os_task_init>:
   0:	14d4      	push      	r4-r7, r15
   2:	6d07      	mov      	r4, r1
   4:	6d43      	mov      	r5, r0
   6:	6d8b      	mov      	r6, r2
   8:	3100      	movi      	r1, 0
   a:	3214      	movi      	r2, 20
   c:	6c13      	mov      	r0, r4
   e:	6dcf      	mov      	r7, r3
  10:	e0000000 	bsr      	0x0	// 0 <memset>
  14:	3000      	movi      	r0, 0
  16:	b4e3      	st.w      	r7, (r4, 0xc)
  18:	b4c1      	st.w      	r6, (r4, 0x4)
  1a:	b4a2      	st.w      	r5, (r4, 0x8)
  1c:	1494      	pop      	r4-r7, r15

Disassembly of section .text.os_task_priority:

00000000 <os_task_priority>:
   0:	8808      	ld.h      	r0, (r0, 0x10)
   2:	e40023ff 	andi      	r0, r0, 1023
   6:	783c      	jmp      	r15

Disassembly of section .text.os_task_stacksize:

00000000 <os_task_stacksize>:
   0:	9004      	ld.w      	r0, (r0, 0x10)
   2:	480a      	lsri      	r0, r0, 10
   4:	783c      	jmp      	r15

Disassembly of section .text._os_task_set_priority:

00000000 <_os_task_set_priority>:
   0:	14d0      	push      	r15
   2:	390f      	cmphsi      	r1, 16
   4:	0c41      	bf      	0x86	// 86 <_os_task_set_priority+0x86>
   6:	391f      	cmphsi      	r1, 32
   8:	0811      	bt      	0x2a	// 2a <_os_task_set_priority+0x2a>
   a:	290e      	subi      	r1, 15
   c:	3928      	cmplti      	r1, 9
   e:	3308      	movi      	r3, 8
  10:	c4230c20 	incf      	r1, r3, 0
  14:	8868      	ld.h      	r3, (r0, 0x10)
  16:	c4615d20 	ins      	r3, r1, 9, 0
  1a:	a868      	st.h      	r3, (r0, 0x10)
  1c:	9000      	ld.w      	r0, (r0, 0x0)
  1e:	e9000004 	bez      	r0, 0x26	// 26 <_os_task_set_priority+0x26>
  22:	e0000000 	bsr      	0x0	// 0 <csi_kernel_task_set_prio>
  26:	3000      	movi      	r0, 0
  28:	1490      	pop      	r15
  2a:	e461101f 	subi      	r3, r1, 32
  2e:	74cc      	zextb      	r3, r3
  30:	3b0f      	cmphsi      	r3, 16
  32:	0805      	bt      	0x3c	// 3c <_os_task_set_priority+0x3c>
  34:	2916      	subi      	r1, 23
  36:	3930      	cmplti      	r1, 17
  38:	3310      	movi      	r3, 16
  3a:	07eb      	br      	0x10	// 10 <_os_task_set_priority+0x10>
  3c:	e461102f 	subi      	r3, r1, 48
  40:	74cc      	zextb      	r3, r3
  42:	3b0f      	cmphsi      	r3, 16
  44:	0805      	bt      	0x4e	// 4e <_os_task_set_priority+0x4e>
  46:	291e      	subi      	r1, 31
  48:	3938      	cmplti      	r1, 25
  4a:	3318      	movi      	r3, 24
  4c:	07e2      	br      	0x10	// 10 <_os_task_set_priority+0x10>
  4e:	e461103f 	subi      	r3, r1, 64
  52:	74cc      	zextb      	r3, r3
  54:	3b0f      	cmphsi      	r3, 16
  56:	0806      	bt      	0x62	// 62 <_os_task_set_priority+0x62>
  58:	2926      	subi      	r1, 39
  5a:	eb210020 	cmplti      	r1, 33
  5e:	3320      	movi      	r3, 32
  60:	07d8      	br      	0x10	// 10 <_os_task_set_priority+0x10>
  62:	e461104f 	subi      	r3, r1, 80
  66:	74cc      	zextb      	r3, r3
  68:	3b0f      	cmphsi      	r3, 16
  6a:	0806      	bt      	0x76	// 76 <_os_task_set_priority+0x76>
  6c:	292e      	subi      	r1, 47
  6e:	eb210028 	cmplti      	r1, 41
  72:	3328      	movi      	r3, 40
  74:	07ce      	br      	0x10	// 10 <_os_task_set_priority+0x10>
  76:	eb4100ff 	cmpnei      	r1, 255
  7a:	0c08      	bf      	0x8a	// 8a <_os_task_set_priority+0x8a>
  7c:	2936      	subi      	r1, 55
  7e:	eb210030 	cmplti      	r1, 49
  82:	3330      	movi      	r3, 48
  84:	07c6      	br      	0x10	// 10 <_os_task_set_priority+0x10>
  86:	3101      	movi      	r1, 1
  88:	07c6      	br      	0x14	// 14 <_os_task_set_priority+0x14>
  8a:	3131      	movi      	r1, 49
  8c:	07c4      	br      	0x14	// 14 <_os_task_set_priority+0x14>

Disassembly of section .text.os_task_set_priority:

00000000 <os_task_set_priority>:
   0:	14d1      	push      	r4, r15
   2:	eb01004f 	cmphsi      	r1, 80
   6:	6d03      	mov      	r4, r0
   8:	0c05      	bf      	0x12	// 12 <os_task_set_priority+0x12>
   a:	1005      	lrw      	r0, 0x0	// 1c <os_task_set_priority+0x1c>
   c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  10:	314f      	movi      	r1, 79
  12:	6c13      	mov      	r0, r4
  14:	e0000000 	bsr      	0x0	// 0 <os_task_set_priority>
  18:	1491      	pop      	r4, r15
  1a:	0000      	.short	0x0000
  1c:	00000000 	.long	0x00000000

Disassembly of section .text.os_task_set_stacksize:

00000000 <os_task_set_stacksize>:
   0:	9064      	ld.w      	r3, (r0, 0x10)
   2:	c4615eaa 	ins      	r3, r1, 31, 10
   6:	b064      	st.w      	r3, (r0, 0x10)
   8:	3000      	movi      	r0, 0
   a:	783c      	jmp      	r15

Disassembly of section .text.os_task_run:

00000000 <os_task_run>:
   0:	14d0      	push      	r15
   2:	1424      	subi      	r14, r14, 16
   4:	8868      	ld.h      	r3, (r0, 0x10)
   6:	9022      	ld.w      	r1, (r0, 0x8)
   8:	b803      	st.w      	r0, (r14, 0xc)
   a:	6c83      	mov      	r2, r0
   c:	9004      	ld.w      	r0, (r0, 0x10)
   e:	c54057e0 	zext      	r0, r0, 31, 10
  12:	b802      	st.w      	r0, (r14, 0x8)
  14:	3000      	movi      	r0, 0
  16:	b801      	st.w      	r0, (r14, 0x4)
  18:	b800      	st.w      	r0, (r14, 0x0)
  1a:	e46323ff 	andi      	r3, r3, 1023
  1e:	1003      	lrw      	r0, 0x0	// 28 <csi_kernel_task_new+0x28>
  20:	e0000000 	bsr      	0x0	// 0 <csi_kernel_task_new>
  24:	1404      	addi      	r14, r14, 16
  26:	1490      	pop      	r15
  28:	00000000 	.long	0x00000000

Disassembly of section .text.os_task_stop:

00000000 <os_task_stop>:
   0:	3000      	movi      	r0, 0
   2:	783c      	jmp      	r15

Disassembly of section .text.os_task_del:

00000000 <os_task_del>:
   0:	14d1      	push      	r4, r15
   2:	9060      	ld.w      	r3, (r0, 0x0)
   4:	6d03      	mov      	r4, r0
   6:	e9230007 	bnez      	r3, 0x14	// 14 <os_task_del+0x14>
   a:	1046      	lrw      	r2, 0x0	// 20 <os_task_del+0x20>
   c:	3171      	movi      	r1, 113
   e:	1006      	lrw      	r0, 0x0	// 24 <os_task_del+0x24>
  10:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  14:	9400      	ld.w      	r0, (r4, 0x0)
  16:	e0000000 	bsr      	0x0	// 0 <csi_kernel_task_del>
  1a:	3300      	movi      	r3, 0
  1c:	b460      	st.w      	r3, (r4, 0x0)
  1e:	1491      	pop      	r4, r15
	...

Disassembly of section .text.os_task_runtime:

00000000 <os_task_runtime>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <csi_kernel_task_runtime>
   6:	1490      	pop      	r15

Disassembly of section .text.os_task_current:

00000000 <os_task_current>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <csi_kernel_task_get_cur>
   6:	901d      	ld.w      	r0, (r0, 0x74)
   8:	1490      	pop      	r15

Disassembly of section .text.os_task_suspend:

00000000 <os_task_suspend>:
   0:	14d0      	push      	r15
   2:	9000      	ld.w      	r0, (r0, 0x0)
   4:	e0000000 	bsr      	0x0	// 0 <csi_kernel_task_suspend>
   8:	1490      	pop      	r15

Disassembly of section .text.os_task_resume:

00000000 <os_task_resume>:
   0:	14d0      	push      	r15
   2:	9000      	ld.w      	r0, (r0, 0x0)
   4:	e0000000 	bsr      	0x0	// 0 <csi_kernel_task_resume>
   8:	1490      	pop      	r15

Disassembly of section .text.os_task_dump:

00000000 <os_task_dump>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <csi_kernel_task_dump>
   6:	1490      	pop      	r15

Disassembly of section .text.os_task_yield:

00000000 <os_task_yield>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <csi_kernel_task_yield>
   6:	1490      	pop      	r15

Disassembly of section .text.os_sched_disable:

00000000 <os_sched_disable>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <krhino_sched_disable>
   6:	3000      	movi      	r0, 0
   8:	1490      	pop      	r15

Disassembly of section .text.os_sched_enbale:

00000000 <os_sched_enbale>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <krhino_sched_enable>
   6:	3000      	movi      	r0, 0
   8:	1490      	pop      	r15
