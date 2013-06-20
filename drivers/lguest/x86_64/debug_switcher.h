#ifndef __DEBUG_SWITCHER_H
#define __DEBUG_SWITCHER_H

#define PRINT_L(L)				\
        PRINT_OUT($L)

#define PRINT_N(n)				\
        PRINT_OUT($'0' + $n)

#define PRINT_HEX(n)				\
	mov     n, %cl;				\
	and     $0xf, %cl;			\
	cmp     $0xa, %cl;			\
	jge     11f;				\
	add     $'0', %cl;			\
	jmp     12f;				\
11:	add     $('a' - 10), %cl;               \
12:	PRINT_OUT(%cl);

#define PRINT_NUM_BX			\
/*    pushq   %rax;               \
    pushq   %rcx;               \
    pushq   %r10;               \
*/    xorq    %rax, %rax;         \
    mov     $0x10, %rcx;        \
8:                              \
    shl     $4, %rax;           \
    mov     %rbx, %r10;         \
    and     $0xf, %r10;         \
    or      %r10, %rax;         \
    shr     $4, %rbx;           \
    loop    8b;                 \
    mov     %rax, %rbx;         \
    mov     $0x10, %r10;        \
9:	PRINT_HEX(%bl);				\
	shr     $4, %rbx;			\
    sub     $0x01, %r10;        \
    cmp     $0x0, %r10;         \
    jne     9b;   /*              \
    popq    %r10;               \
    popq    %rcx;               \
    popq    %rax;*/

#define PRINT_NUM(n)				\
	movl    $n, %ebx;			\
	PRINT_NUM_BX;				\
	PRINT_L('\n');				\
	PRINT_L('\r')

#define PRINT_LONG(n)				\
	movl    n, %ebx;			\
	PRINT_NUM_BX;				\
	PRINT_L('\n');				\
	PRINT_L('\r')

#define PRINT_QUAD(n)				\
	movq    n, %rbx;			\
	PRINT_NUM_BX;				\
	PRINT_L('\n');				\
	PRINT_L('\r')

#define PRINT_X					\
	PRINT_L('x')

#define PRINT_OUT(x)				\
	mov $0x3f8, %esi;			\
21:	lea  0x5(%esi), %edx;			\
	movzwl %dx, %edx;			\
	in  (%dx), %al;				\
	test $0x20,%al;				\
	jne 22f;				\
	pause;					\
	jmp 21b;				\
22:						\
	movl    %esi, %edx;			\
	movzwl  %dx, %edx;			\
	mov     x, %al;				\
	out     %al, (%dx);			\
31:						\
	lea  0x5(%esi), %edx;			\
	movzwl %dx, %edx;			\
	in  (%dx), %al;				\
	test $0x20,%al;				\
	jne 32f;				\
	pause;					\
	jmp 31b;				\
32:						\

#define PUSH_NUM				\
	pushq %rcx;				\
	pushq %rbx;

#define POP_NUM					\
	popq %rbx;				\
	popq %rcx;

#define PUSH_PRINT				\
	pushq %rax;				\
	pushq %rsi;				\
	pushq %rdx;				\

#define POP_PRINT				\
	popq %rdx;				\
	popq %rsi;				\
	popq %rax;				\

#define S_PRINT_NUM(_n)				\
	PUSH_PRINT;				\
	PUSH_NUM;				\
	PRINT_NUM(_n);				\
	POP_NUM;				\
	POP_PRINT;

#define S_PRINT_L(x)				\
	PUSH_PRINT;				\
	PRINT_L(x);				\
	POP_PRINT;

#define S_PRINT_QUAD(_n)			\
	PUSH_PRINT;				\
	PUSH_NUM;				\
	PRINT_QUAD(_n);				\
	POP_NUM;				\
	POP_PRINT;

#define PRINT_STR_2(a,b)			\
	PRINT_L(a); PRINT_L(b)

#define PRINT_STR_3(a,b,c)			\
	PRINT_L(a);PRINT_L(b);PRINT_L(c)

#define	PRINT_STR_4(a,b,c,d)			\
	PRINT_STR_2(a,b);PRINT_STR_2(c,d)

#define	PRINT_STR_5(a,b,c,d,e)			\
	PRINT_STR_3(a,b,c);PRINT_STR_2(d,e)

#define	PRINT_STR_6(a,b,c,d,e,f)		\
	PRINT_STR_3(a,b,c);PRINT_STR_3(d,e,f)

#define	PRINT_STR_7(a,b,c,d,e,f,g)		\
	PRINT_STR_4(a,b,c,d);PRINT_STR_3(e,f,g)

#define	PRINT_STR_8(a,b,c,d,e,f,g,h)		\
	PRINT_STR_4(a,b,c,d);PRINT_STR_4(e,f,g,h)

#define	PRINT_STR_9(a,b,c,d,e,f,g,h,i)		\
	PRINT_STR_5(a,b,c,d,e);PRINT_STR_4(f,g,h,i)

#define	PRINT_STR_10(a,b,c,d,e,f,g,h,i,j)		\
	PRINT_STR_5(a,b,c,d,e);PRINT_STR_5(f,g,h,i,j)

#define	PRINT_STR_11(a,b,c,d,e,f,g,h,i,j,k)		\
	PRINT_STR_6(a,b,c,d,e,f);PRINT_STR_5(g,h,i,j,k)

#define PRINT_STR_STACK				\
	PRINT_STR_6('S','t','a','c','k',':')

#define PRINT_STR_SYSCALL			\
	PRINT_STR_9('S','Y','S','C','A','L','L',':',' ')

#define PRINT_STR_VADDR				\
	PRINT_STR_6('V','a','d','d','r',':')

#define PRINT_STR_CR(n)				\
	PRINT_STR_4('C','R',n,':')

#define PRINT_STR_PGD				\
	PRINT_STR_3('P','G','D')

#define PRINT_STR_PUD				\
	PRINT_STR_3('P','U','D')

#define PRINT_STR_PMD				\
	PRINT_STR_3('P','M','D')

#define PRINT_STR_PTE				\
	PRINT_STR_3('P','T','E')

#define PRINT_NL				\
	PRINT_STR_2('\n','\r')

#endif
