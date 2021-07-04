// camellia.cpp - by Kevin Springle, 2003
// This code is hereby placed in the public domain.

/*
Optimisations and defense against timing attacks added in Jan 2007 by Wei Dai.

The first 2 rounds and the last round seem especially vulnerable to timing
attacks. The protection is similar to what was implemented for Rijndael.
See comments at top of rijndael.cpp for more details.
*/

#include "pch.h"

#include "camellia.h"
#include "misc.h"
#include "cpu.h"

NAMESPACE_BEGIN(CryptoPP)

// round implementation that uses a small table for protection against timing attacks
#define SLOW_ROUND(lh, ll, rh, rl, kh, kl)	{							\
	word32 zr = ll ^ kl;												\
	word32 zl = lh ^ kh;												\
	zr=	rotlFixed(s1[GETBYTE(zr, 3)], 1) |								\
		(rotrFixed(s1[GETBYTE(zr, 2)], 1) << 24) |						\
		(s1[rotlFixed(CRYPTOPP_GET_BYTE_AS_BYTE(zr, 1),1)] << 16) |		\
		(s1[GETBYTE(zr, 0)] << 8);										\
	zl=	(s1[GETBYTE(zl, 3)] << 24) |									\
		(rotlFixed(s1[GETBYTE(zl, 2)], 1) << 16) |						\
		(rotrFixed(s1[GETBYTE(zl, 1)], 1) << 8) |						\
		s1[rotlFixed(CRYPTOPP_GET_BYTE_AS_BYTE(zl, 0), 1)];				\
	zl ^= zr;															\
	zr = zl ^ rotlFixed(zr, 8);											\
	zl = zr ^ rotrFixed(zl, 8);											\
	rh ^= rotlFixed(zr, 16);											\
	rh ^= zl;															\
	rl ^= rotlFixed(zl, 8);												\
	}

// normal round - same output as above but using larger tables for faster speed
#define ROUND(lh, ll, rh, rl, kh, kl)	{	\
	word32 th = lh ^ kh;					\
	word32 tl = ll ^ kl;					\
	word32 d = SP[0][GETBYTE(tl,0)] ^ SP[1][GETBYTE(tl,3)] ^ SP[2][GETBYTE(tl,2)] ^ SP[3][GETBYTE(tl,1)];	\
	word32 u = SP[0][GETBYTE(th,3)] ^ SP[1][GETBYTE(th,2)] ^ SP[2][GETBYTE(th,1)] ^ SP[3][GETBYTE(th,0)];	\
	d ^= u;									\
	rh ^= d;								\
	rl ^= d;								\
	rl ^= rotrFixed(u, 8);}

#define DOUBLE_ROUND(lh, ll, rh, rl, k0, k1, k2, k3)	\
	ROUND(lh, ll, rh, rl, k0, k1)						\
	ROUND(rh, rl, lh, ll, k2, k3)

#ifdef IS_LITTLE_ENDIAN
#define EFI(i) (1-(i))
#else
#define EFI(i) (i)
#endif

void Camellia::Base::UncheckedSetKey(const byte *key, unsigned int keylen, const NameValuePairs &)
{
	m_rounds = (keylen >= 24) ? 4 : 3;
	unsigned int kslen = (8 * m_rounds + 2);
	m_key.New(kslen*2);
	word32 *ks32 = m_key.data();
	int m=0, a=0;
	if (!IsForwardTransformation())
		m = -1, a = kslen-1;

	word32 kl0, kl1, kl2, kl3;
	GetBlock<word32, BigEndian> getBlock(key);
	getBlock(kl0)(kl1)(kl2)(kl3);
	word32 k0=kl0, k1=kl1, k2=kl2, k3=kl3;

#define CALC_ADDR2(base, i, j)	((byte *)(base)+8*(i)+4*(j)+((-16*(i))&m))
#define CALC_ADDR(base, i)	CALC_ADDR2(base, i, 0)

#if 1
	word64 kwl, kwr;
	ks32 += 2*a;
#define PREPARE_KS_ROUNDS			\
	kwl = (word64(k0) << 32) | k1;	\
	kwr = (word64(k2) << 32) | k3
#define KS_ROUND_0(i)							\
	*(word64*)CALC_ADDR(ks32, i+EFI(0)) = kwl;	\
	*(word64*)CALC_ADDR(ks32, i+EFI(1)) = kwr
#define KS_ROUND(i, r, which)																						\
	if (which & (1<<int(r<64))) *(word64*)CALC_ADDR(ks32, i+EFI(r<64)) = (kwr << (r%64)) | (kwl >> (64 - (r%64)));	\
	if (which & (1<<int(r>64))) *(word64*)CALC_ADDR(ks32, i+EFI(r>64)) = (kwl << (r%64)) | (kwr >> (64 - (r%64)))
#else
	// SSE2 version is 30% faster on Intel Core 2. Doesn't seem worth the hassle of maintenance, but left here
	// #if'd out in case someone needs it.
	__m128i kw, kw2;
	__m128i *ks128 = (__m128i *)ks32+a/2;
	ks32 += 2*a;
#define PREPARE_KS_ROUNDS													\
	kw = _mm_set_epi32(k0, k1, k2, k3);										\
	if (m) kw2 = kw, kw = _mm_shuffle_epi32(kw, _MM_SHUFFLE(1, 0, 3, 2));	\
	else kw2 = _mm_shuffle_epi32(kw, _MM_SHUFFLE(1, 0, 3, 2))
#define KS_ROUND_0(i)										\
	_mm_store_si128((__m128i *)CALC_ADDR(ks128, i), kw)
#define KS_ROUND(i, r, which)	{																				\
	__m128i temp;																								\
	if (r<64 && (which!=1 || m)) temp = _mm_or_si128(_mm_slli_epi64(kw, r%64), _mm_srli_epi64(kw2, 64-r%64));	\
	else temp = _mm_or_si128(_mm_slli_epi64(kw2, r%64), _mm_srli_epi64(kw, 64-r%64));							\
	if (which & 2) _mm_store_si128((__m128i *)CALC_ADDR(ks128, i), temp);										\
	else _mm_storel_epi64((__m128i*)CALC_ADDR(ks32, i+EFI(0)), temp);											\
	}
#endif

	if (keylen == 16)
	{
		// KL
		PREPARE_KS_ROUNDS;
		KS_ROUND_0(0);
		KS_ROUND(4, 15, 3);
		KS_ROUND(10, 45, 3);
		KS_ROUND(12, 60, 2);
		KS_ROUND(16, 77, 3);
		KS_ROUND(18, 94, 3);
		KS_ROUND(22, 111, 3);

		// KA
		k0=kl0, k1=kl1, k2=kl2, k3=kl3;
		DOUBLE_ROUND(k0, k1, k2, k3, 0xA09E667Ful, 0x3BCC908Bul, 0xB67AE858ul, 0x4CAA73B2ul);
		k0^=kl0, k1^=kl1, k2^=kl2, k3^=kl3;
		DOUBLE_ROUND(k0, k1, k2, k3, 0xC6EF372Ful, 0xE94F82BEul, 0x54FF53A5ul, 0xF1D36F1Cul);

		PREPARE_KS_ROUNDS;
		KS_ROUND_0(2);
		KS_ROUND(6, 15, 3);
		KS_ROUND(8, 30, 3);
		KS_ROUND(12, 45, 1);
		KS_ROUND(14, 60, 3);
		KS_ROUND(20, 94, 3);
		KS_ROUND(24, 47, 3);
	}
	else
	{
		// KL
		PREPARE_KS_ROUNDS;
		KS_ROUND_0(0);
		KS_ROUND(12, 45, 3);
		KS_ROUND(16, 60, 3);
		KS_ROUND(22, 77, 3);
		KS_ROUND(30, 111, 3);

		// KR
		word32 kr0, kr1, kr2, kr3;
		GetBlock<word32, BigEndian>(key+16)(kr0)(kr1);
		if (keylen == 24)
			kr2 = ~kr0, kr3 = ~kr1;
		else
			GetBlock<word32, BigEndian>(key+24)(kr2)(kr3);
		k0=kr0, k1=kr1, k2=kr2, k3=kr3;

		PREPARE_KS_ROUNDS;
		KS_ROUND(4, 15, 3);
		KS_ROUND(8, 30, 3);
		KS_ROUND(18, 60, 3);
		KS_ROUND(26, 94, 3);

		// KA
		k0^=kl0, k1^=kl1, k2^=kl2, k3^=kl3;
		DOUBLE_ROUND(k0, k1, k2, k3, 0xA09E667Ful, 0x3BCC908Bul, 0xB67AE858ul, 0x4CAA73B2ul);
		k0^=kl0, k1^=kl1, k2^=kl2, k3^=kl3;
		DOUBLE_ROUND(k0, k1, k2, k3, 0xC6EF372Ful, 0xE94F82BEul, 0x54FF53A5ul, 0xF1D36F1Cul);

		PREPARE_KS_ROUNDS;
		KS_ROUND(6, 15, 3);
		KS_ROUND(14, 45, 3);
		KS_ROUND(24, 77, 3);
		KS_ROUND(28, 94, 3);

		// KB
		k0^=kr0, k1^=kr1, k2^=kr2, k3^=kr3;
		DOUBLE_ROUND(k0, k1, k2, k3, 0x10E527FAul, 0xDE682D1Dul, 0xB05688C2ul, 0xB3E6C1FDul);

		PREPARE_KS_ROUNDS;
		KS_ROUND_0(2);
		KS_ROUND(10, 30, 3);
		KS_ROUND(20, 60, 3);
		KS_ROUND(32, 47, 3);
	}
}

void Camellia::Base::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
#define KS(i, j) ks[i*4 + EFI(j/2)*2 + EFI(j%2)]

#define FL(klh, kll, krh, krl)		\
	ll ^= rotlFixed(lh & klh, 1);	\
	lh ^= (ll | kll);				\
	rh ^= (rl | krl);				\
	rl ^= rotlFixed(rh & krh, 1);

	word32 lh, ll, rh, rl;
	typedef BlockGetAndPut<word32, BigEndian> Block;
	Block::Get(inBlock)(lh)(ll)(rh)(rl);
	const word32 *ks = m_key.data();
	lh ^= KS(0,0);
	ll ^= KS(0,1);
	rh ^= KS(0,2);
	rl ^= KS(0,3);

	// timing attack countermeasure. see comments at top for more details
	const int cacheLineSize = GetCacheLineSize();
	unsigned int i;
	word32 u = 0;
	for (i=0; i<256; i+=cacheLineSize)
		u &= *(const word32 *)(s1+i);
	u &= *(const word32 *)(s1+252);
	lh |= u; ll |= u;

	SLOW_ROUND(lh, ll, rh, rl, KS(1,0), KS(1,1))
	SLOW_ROUND(rh, rl, lh, ll, KS(1,2), KS(1,3))
	for (i = m_rounds-1; i > 0; --i)
	{
		DOUBLE_ROUND(lh, ll, rh, rl, K