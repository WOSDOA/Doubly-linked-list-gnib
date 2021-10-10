// panama.cpp - written and placed in the public domain by Wei Dai

// use "cl /EP /P /DCRYPTOPP_GENERATE_X64_MASM panama.cpp" to generate MASM code

#include "pch.h"

#ifndef CRYPTOPP_GENERATE_X64_MASM

#include "panama.h"
#include "misc.h"
#include "cpu.h"

NAMESPACE_BEGIN(CryptoPP)

template <class B>
void Panama<B>::Reset()
{
	memset(m_state, 0, m_state.SizeInBytes());
#if CRYPTOPP_BOOL_SSSE3_ASM_AVAILABLE
	m_state[17] = HasSSSE3();
#endif
}

#endif	// #ifndef CRYPTOPP_GENERATE_X64_MASM

#ifdef CRYPTOPP_X64_MASM_AVAILABLE
extern "C" {
void Panama_SSE2_Pull(size_t count, word32 *state, word32 *z, const word32 *y);
}
#elif CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE

#ifdef CRYPTOPP_GENERATE_X64_MASM
	Panama_SSE2_Pull	PROC FRAME
	rex_push_reg rdi
	alloc_stack(2*16)
	save_xmm128 xmm6, 0h
	save_xmm128 xmm7, 10h
	.endprolog
#else
#pragma warning(disable: 4731)	// frame pointer register 'ebp' modified by inline assembly code
void CRYPTOPP_NOINLINE Panama_SSE2_Pull(size_t count, word32 *state, word32 *z, const word32 *y)
{
#ifdef CRYPTOPP_GNU_STYLE_INLINE_ASSEMBLY
	asm __volatile__
	(
		".intel_syntax noprefix;"
		AS_PUSH_IF86(	bx)
#else
	AS2(	mov		AS_REG_1, count)
	AS2(	mov		AS_REG_2, state)
	AS2(	mov		AS_REG_3, z)
	AS2(	mov		AS_REG_4, y)
#endif
#endif	// #ifdef CRYPTOPP_GENERATE_X64_MASM

#if CRYPTOPP_BOOL_X86
	#define REG_loopEnd			[esp]
#elif defined(CRYPTOPP_GENERATE_X64_MASM)
	#define REG_loopEnd			rdi
#else
	#define REG_loopEnd			r8
#endif

	AS2(	shl		AS_REG_1, 5)
	ASJ(	jz,		5, f)
	AS2(	mov		AS_REG_6d, [AS_REG_2+4*17])
	AS2(	add		AS_REG_1, AS_REG_6)

	#if CRYPTOPP_BOOL_X64
		AS2(	mov		REG_loopEnd, AS_REG_1)
	#else
		AS1(	push	ebp)
		AS1(	push	AS_REG_1)
	#endif

	AS2(	movdqa	xmm0, XMMWORD_PTR [AS_REG_2+0*16])
	AS2(	movdqa	xmm1, XMMWORD_PTR [AS_REG_2+1*16])
	AS2(	movdqa	xmm2, XMMWORD_PTR [AS_REG_2+2*16])
	AS2(	movdqa	xmm3, XMMWORD_PTR [AS_REG_2+3*16])
	AS2(	mov		eax, dword ptr [AS_REG_2+4*16])

	ASL(4)
	// gamma and pi
#if CRYPTOPP_BOOL_SSSE3_ASM_AVAILABLE
	AS2(	test	AS_REG_6, 1)
	ASJ(	jnz,	6, f)
#endif
	AS2(	movdqa	xmm6, xmm2)
	AS2(	movss	xmm6, xmm3)
	ASS(	pshufd	xmm5, xmm6, 0, 3, 2, 1)
	AS2(	movd	xmm6, eax)
	AS2(	movdqa	xmm7, xmm3)
	AS2(	movss	xmm7, xmm6)
	ASS(	pshufd	xmm6, xmm7, 0, 3, 2, 1)
#if CRYPTOPP_BOOL_SSSE3_ASM_AVAILABLE
	ASJ(	jmp,	7, f)
	ASL(6)
	AS2(	movdqa	xmm5, xmm3)
	AS3(	palignr	xmm5, xmm2, 4)
	AS2(	movd	xmm6, eax)
	AS3(	palignr	xmm6, xmm3, 4)
	ASL(7)
#endif

	AS2(	movd	AS_REG_1d, xmm2)
	AS1(	not		AS_REG_1d)
	AS2(	movd	AS_REG_7d, xmm3)
	AS2(	or		AS_REG_1d, AS_REG_7d)
	AS2(	xor		eax, AS_REG_1d)

#define SSE2_Index(i) ASM_MOD(((i)*13+16), 17)

#define pi(i)	\
	AS2(	movd	AS_REG_1d, xmm7)\
	AS2(	rol		AS_REG_1d, ASM_MOD((ASM_MOD(5*i,17)*(ASM_MOD(5*i,17)+1)/2), 32))\
	AS2(	mov		[AS_REG_2+SSE2_Index(ASM_MOD(5*(i), 17))*4], AS_REG_1d)

#define pi4(x, y, z, a, b, c, d)	\
	AS2(	pcmpeqb	xmm7, xmm7)\
	AS2(	pxor	xmm7, x)\
	AS2(	por		xmm7, y)\
	AS2(	pxor	xmm7, z)\
	pi(a)\
	ASS(	pshuflw	xmm7, xmm7, 1, 0, 3, 2)\
	pi(b)\
	AS2(	punpckhqdq	xmm7, xmm7)\
	pi(c)\
	ASS(	pshuflw	xmm7, xmm7, 1, 0, 3, 2)\
	pi(d)

	pi4(xmm1, xmm2, xmm3, 1, 5, 9, 13)
	pi4(xmm0, xmm1, xmm2, 2, 6, 10, 14)
	pi4(xmm6, xmm0, xmm1, 3, 7, 11, 15)
	pi4(xmm5, xmm6, xmm0, 4, 8, 12, 16)

	// output keystream and update buffer here to hide partial memory stalls between pi and theta
	AS2(	movdqa	xmm4, xmm3)
	AS2(	punpcklqdq	xmm3, xmm2)		// 1 5 2 6
	AS2(	punpckhdq	xmm4, xmm2)		// 9 10 13 14
	AS2(	movdqa	xmm2, xmm1)
	AS2(	punpcklqdq	xmm1, xmm0)		// 3 7 4 8
	AS2(	punpckhdq	xmm2, xmm0)		// 11 12 15 16

	// keystream
	AS2(	test	AS_REG_3, AS_REG_3)
	ASJ(	jz,		0, f)
	AS2(	movdqa	xmm6, xmm4)
	AS2(	punpcklqdq	xmm4, xmm2)
	AS2(	punpckhqdq	xmm6, xmm2)
	AS2(	test	AS_REG_4, 15)
	ASJ(	jnz,	2, f)
	AS2(	test	AS_REG_4, AS_REG_4)
	ASJ(	jz,		1, f)
	AS2(	pxor	xmm4, [AS_REG_4])
	AS2(	pxor	xmm6, [AS_REG_4+16])
	AS2(	add		AS_REG_4, 32)
	ASJ(	jmp,	1, f)
	ASL(2)
	AS2(	movdqu	xmm0, [AS_REG_4])
	AS2(	movdqu	xmm2, [AS_REG_4+16])
	AS2(	pxor	xmm4, xmm0)
	AS2(	pxor	xmm6, xmm2)
	AS2(	add		AS_REG_4, 32)
	ASL(1)
	AS2(	test	AS_REG_3, 15)
	ASJ(	jnz,	3, f)
	AS2(	movdqa	XMMWORD_PTR [AS_REG_3], xmm4)
	AS2(	movdqa	XMMWORD_PTR [AS_REG_3+16], xmm6)
	AS2(	add		AS_REG_3, 32)
	ASJ(	jmp,	0, f)
	ASL(3)
	AS2(	movdqu	XMMWORD_PTR [AS_REG_3], xmm4)
	AS2(	movdqu	XMMWORD_PTR [AS_REG_3+16], xmm6)
	AS2(	add		AS_REG_3, 32)
	ASL(0)

	// buffer update
	AS2(	lea		AS_REG_1, [AS_REG_6 + 32])
	AS2(	and		AS_REG_1, 31*32)
	AS2(	lea		AS_REG_7, [AS_REG_6 + (32-24)*32])
	A