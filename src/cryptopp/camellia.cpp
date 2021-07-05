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
		DOUBLE_ROUND(lh, ll, rh, rl, KS(2,0), KS(2,1), KS(2,2), KS(2,3))
		DOUBLE_ROUND(lh, ll, rh, rl, KS(3,0), KS(3,1), KS(3,2), KS(3,3))
		FL(KS(4,0), KS(4,1), KS(4,2), KS(4,3));
		DOUBLE_ROUND(lh, ll, rh, rl, KS(5,0), KS(5,1), KS(5,2), KS(5,3))
		ks += 16;
	}
	DOUBLE_ROUND(lh, ll, rh, rl, KS(2,0), KS(2,1), KS(2,2), KS(2,3))
	ROUND(lh, ll, rh, rl, KS(3,0), KS(3,1))
	SLOW_ROUND(rh, rl, lh, ll, KS(3,2), KS(3,3))
	lh ^= KS(4,0);
	ll ^= KS(4,1);
	rh ^= KS(4,2);
	rl ^= KS(4,3);
	Block::Put(xorBlock, outBlock)(rh)(rl)(lh)(ll);
}

// The Camellia s-boxes

const byte Camellia::Base::s1[256] =
{
	112,130,44,236,179,39,192,229,228,133,87,53,234,12,174,65,
	35,239,107,147,69,25,165,33,237,14,79,78,29,101,146,189,
	134,184,175,143,124,235,31,206,62,48,220,95,94,197,11,26,
	166,225,57,202,213,71,93,61,217,1,90,214,81,86,108,77,
	139,13,154,102,251,204,176,45,116,18,43,32,240,177,132,153,
	223,76,203,194,52,126,118,5,109,183,169,49,209,23,4,215,
	20,88,58,97,222,27,17,28,50,15,156,22,83,24,242,34,
	254,68,207,178,195,181,122,145,36,8,232,168,96,252,105,80,
	170,208,160,125,161,137,98,151,84,91,30,149,224,255,100,210,
	16,196,0,72,163,247,117,219,138,3,230,218,9,63,221,148,
	135,92,131,2,205,74,144,51,115,103,246,243,157,127,191,226,
	82,155,216,38,200,55,198,59,129,150,111,75,19,190,99,46,
	233,121,167,140,159,110,188,142,41,245,249,182,47,253,180,89,
	120,152,6,106,231,70,113,186,212,37,171,66,136,162,141,250,
	114,7,185,85,248,238,172,10,54,73,42,104,60,56,241,164,
	64,40,211,123,187,201,67,193,21,227,173,244,119,199,128,158
};

const word32 Camellia::Base::SP[4][256] = {
	{
	0x70707000, 0x82828200, 0x2c2c2c00, 0xececec00,
	0xb3b3b300, 0x27272700, 0xc0c0c000, 0xe5e5e500,
	0xe4e4e400, 0x85858500, 0x57575700, 0x35353500,
	0xeaeaea00, 0x0c0c0c00, 0xaeaeae00, 0x41414100,
	0x23232300, 0xefefef00, 0x6b6b6b00, 0x93939300,
	0x45454500, 0x19191900, 0xa5a5a500, 0x21212100,
	0xededed00, 0x0e0e0e00, 0x4f4f4f00, 0x4e4e4e00,
	0x1d1d1d00, 0x65656500, 0x92929200, 0xbdbdbd00,
	0x86868600, 0xb8b8b800, 0xafafaf00, 0x8f8f8f00,
	0x7c7c7c00, 0xebebeb00, 0x1f1f1f00, 0xcecece00,
	0x3e3e3e00, 0x30303000, 0xdcdcdc00, 0x5f5f5f00,
	0x5e5e5e00, 0xc5c5c500, 0x0b0b0b00, 0x1a1a1a00,
	0xa6a6a600, 0xe1e1e100, 0x39393900, 0xcacaca00,
	0xd5d5d500, 0x47474700, 0x5d5d5d00, 0x3d3d3d00,
	0xd9d9d900, 0x01010100, 0x5a5a5a00, 0xd6d6d600,
	0x51515100, 0x56565600, 0x6c6c6c00, 0x4d4d4d00,
	0x8b8b8b00, 0x0d0d0d00, 0x9a9a9a00, 0x66666600,
	0xfbfbfb00, 0xcccccc00, 0xb0b0b000, 0x2d2d2d00,
	0x74747400, 0x12121200, 0x2b2b2b00, 0x20202000,
	0xf0f0f000, 0xb1b1b100, 0x84848400, 0x99999900,
	0xdfdfdf00, 0x4c4c4c00, 0xcbcbcb00, 0xc2c2c200,
	0x34343400, 0x7e7e7e00, 0x76767600, 0x05050500,
	0x6d6d6d00, 0xb7b7b700, 0xa9a9a900, 0x31313100,
	0xd1d1d100, 0x17171700, 0x04040400, 0xd7d7d700,
	0x14141400, 0x58585800, 0x3a3a3a00, 0x61616100,
	0xdedede00, 0x1b1b1b00, 0x11111100, 0x1c1c1c00,
	0x32323200, 0x0f0f0f00, 0x9c9c9c00, 0x16161600,
	0x53535300, 0x18181800, 0xf2f2f200, 0x22222200,
	0xfefefe00, 0x44444400, 0xcfcfcf00, 0xb2b2b200,
	0xc3c3c300, 0xb5b5b500, 0x7a7a7a00, 0x91919100,
	0x24242400, 0x08080800, 0xe8e8e800, 0xa8a8a800,
	0x60606000, 0xfcfcfc00, 0x69696900, 0x50505000,
	0xaaaaaa00, 0xd0d0d000, 0xa0a0a000, 0x7d7d7d00,
	0xa1a1a100, 0x89898900, 0x62626200, 0x97979700,
	0x54545400, 0x5b5b5b00, 0x1e1e1e00, 0x95959500,
	0xe0e0e000, 0xffffff00, 0x64646400, 0xd2d2d200,
	0x10101000, 0xc4c4c400, 0x00000000, 0x48484800,
	0xa3a3a300, 0xf7f7f700, 0x75757500, 0xdbdbdb00,
	0x8a8a8a00, 0x03030300, 0xe6e6e600, 0xdadada00,
	0x09090900, 0x3f3f3f00, 0xdddddd00, 0x94949400,
	0x87878700, 0x5c5c5c00, 0x83838300, 0x02020200,
	0xcdcdcd00, 0x4a4a4a00, 0x90909000, 0x33333300,
	0x73737300, 0x67676700, 0xf6f6f600, 0xf3f3f300,
	0x9d9d9d00, 0x7f7f7f00, 0xbfbfbf00, 0xe2e2e200,
	0x52525200, 0x9b9b9b00, 0xd8d8d800, 0x26262600,
	0xc8c8c800, 0x37373700, 0xc6c6c600, 0x3b3b3b00,
	0x81818100, 0x96969600, 0x6f6f6f00, 0x4b4b4b00,
	0x13131300, 0xbebebe00, 0x63636300, 0x2e2e2e00,
	0xe9e9e900, 0x79797900, 0xa7a7a700, 0x8c8c8c00,
	0x9f9f9f00, 0x6e6e6e00, 0xbcbcbc00, 0x8e8e8e00,
	0x29292900, 0xf5f5f500, 0xf9f9f900, 0xb6b6b600,
	0x2f2f2f00, 0xfdfdfd00, 0xb4b4b400, 0x59595900,
	0x78787800, 0x98989800, 0x06060600, 0x6a6a6a00,
	0xe7e7e700, 0x46464600, 0x71717100, 0xbababa00,
	0xd4d4d400, 0x25252500, 0xababab00, 0x42424200,
	0x88888800, 0xa2a2a200, 0x8d8d8d00, 0xfafafa00,
	0x72727200, 0x07070700, 0xb9b9b900, 0x55555500,
	0xf8f8f800, 0xeeeeee00, 0xacacac00, 0x0a0a0a00,
	0x36363600, 0x49494900, 0x2a2a2a00, 0x68686800,
	0x3c3c3c00, 0x38383800, 0xf1f1f100, 0xa4a4a400,
	0x40404000, 0x28282800, 0xd3d3d300, 0x7b7b7b00,
	0xbbbbbb00, 0xc9c9c900, 0x43434300, 0xc1c1c100,
	0x15151500, 0xe3e3e300, 0xadadad00, 0xf4f4f400,
	0x77777700, 0xc7c7c700, 0x80808000, 0x9e9e9e00
	},
	{
	0x00e0e0e0, 0x00050505, 0x00585858, 0x00d9d9d9,
	0x00676767, 0x004e4e4e, 0x00818181, 0x00cbcbcb,
	0x00c9c9c9, 0x000b0b0b, 0x00aeaeae, 0x006a6a6a,
	0x00d5d5d5, 0x00181818, 0x005d5d5d, 0x00828282,
	0x00464646, 0x00dfdfdf, 0x00d6d6d6, 0x00272727,
	0x008a8a8a, 0x00323232, 0x004b4b4b, 0x00424242,
	0x00dbdbdb, 0x001c1c1c, 0x009e9e9e, 0x009c9c9c,
	0x003a3a3a, 0x00cacaca, 0x00252525, 0x007b7b7b,
	0x000d0d0d, 0x00717171, 0x005f5f5f, 0x001f1f1f,
	0x00f8f8f8, 0x00d7d7d7, 0x003e3e3e, 0x009d9d9d,
	0x007c7c7c, 0x00606060, 0x00b9b9b9, 0x00bebebe,
	0x00bcbcbc, 0x008b8b8b, 0x00161616, 0x00343434,
	0x004d4d4d, 0x00c3c3c3, 0x00727272, 0x00959595,
	0x00ababab, 0x008e8e8e, 0x00bababa, 0x007a7a7a,
	0x00b3b3b3, 0x00020202, 0x00b4b4b4, 0x00adadad,
	0x00a2a2a2, 0x00acacac, 0x00d8d8d8, 0x009a9a9a,
	0x00171717, 0x001a1a1a, 0x00353535, 0x00cccccc,
	0x00f7f7f7, 0x00999999, 0x00616161, 0x005a5a5a,
	0x00e8e8e8, 0x00242424, 0x00565656, 0x00404040,
	0x00e1e1e1, 0x00636363, 0x00090909, 0x00333333,
	0x00bfbfbf, 0x00989898, 0x00979797, 0x00858585,
	0x00686868, 0x00fcfcfc, 0x00ececec, 0x000a0a0a,
	0x00dadada, 0x006f6f6f, 0x00535353, 0x00626262,
	0x00a3a3a3, 0x002e2e2e, 0x00080808, 0x00afafaf,
	0x00282828, 0x00b0b0b0, 0x00747474, 0x00c2c2c2,
	0x00bdbdbd, 0x00363636, 0x00222222, 0x00383838,
	0x00646464, 0x001e1e1e, 0x00393939, 0x002c2c2c,
	0x00a6a6a6, 0x00303030, 0x00e5e5e