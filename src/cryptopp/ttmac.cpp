// ttmac.cpp - written and placed in the public domain by Kevin Springle

#include "pch.h"
#include "ttmac.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

void TTMAC_Base::UncheckedSetKey(const byte *userKey, unsigned int keylength, const NameValuePairs &)
{
	AssertValidKeyLength(keylength);

	memcpy(m_key, userKey, KEYLENGTH);
	CorrectEndianess(m_key, m_key, KEYLENGTH);

	Init();
}

void TTMAC_Base::Init()
{
	m_digest[0] = m_digest[5] = m_key[0];
	m_digest[1] = m_digest[6] = m_key[1];
	m_digest[2] = m_digest[7] = m_key[2];
	m_digest[3] = m_digest[8] = m_key[3];
	m_digest[4] = m_digest[9] = m_key[4];
}

void TTMAC_Base::TruncatedFinal(byte *hash, size_t size)
{
	PadLastBlock(BlockSize() - 2*sizeof(HashWordType));
	CorrectEndianess(m_data, m_data, BlockSize() - 2*sizeof(HashWordType));

	m_data[m_data.size()-2] = GetBitCountLo();
	m_data[m_data.size()-1] = GetBitCountHi();

	Transform(m_digest, m_data, true);

	word32 t2 = m_digest[2];
	word32 t3 = m_digest[3];
	if (size != DIGESTSIZE)
	{
		switch (size)
		{
			case 16:
				m_digest[3] += m_digest[1] + m_digest[4];

			case 12:
				m_digest[2] += m_digest[0] + t3;

			case 8:
				m_digest[0] += m_digest[1] + t3;
				m_digest[1] += m_digest[4] + t2;
				break;

			case 4:
				m_digest[0] +=
						m_digest[1] +
						m_digest[2] +
						m_digest[3] +
						m_digest[4];
				break;

			case 0:
				// Used by HashTransformation::Restart()
				break;

			default:
				throw InvalidArgument("TTMAC_Base: can't truncate a Two-Track-MAC 20 byte digest to " + IntToString(size) + " bytes");
				break;
		}
	}

	CorrectEndianess(m_digest, m_digest, size);
	memcpy(hash, m_digest, size);

	Restart();		// reinit for next use
}

// RIPEMD-160 definitions used by Two-Track-MAC

#define F(x, y, z)	(x ^ y ^ z)
#define G(x, y, z)	(z ^ (x & (y^z)))
#define H(x, y, z)	(z ^ (x | ~y))
#define I(x, y, z)	(y ^ (z & (x^y)))
#define J(x, y, z)	(x ^ (y | ~z))

#define k0 0
#define k1 0x5a827999UL
#define k2 0x6ed9eba1UL
#define k3 0x8f1bbcdcUL
#define k4 0xa953fd4eUL
#define k5 0x50a28be6UL
#define k6 0x5c4dd124UL
#define k7 0x6d703ef3UL
#define k8 0x7a6d76e9UL
#define k9 0

void TTMAC_Base::Transform(word32 *digest, const word32 *X, bool last)
{
#define Subround(f, a, b, c, d, e, x, s, k)		\
	a += f(b, c, d) + x + k;\
	a = rotlFixed((word32)a, s) + e;\
	c = rotlFixed((word32)c, 10U)

	word32 a1, b1, c1, d1, e1, a2, b2, c2, d2, e2;
	word32 *trackA, *trackB;

	if (!last)
	{
		trackA = digest;
		trackB = digest+5;
	}
	else
	{
		trackB = digest;
		trackA = digest+5;
	}
	a1 = trackA[0];
	b1 = trackA[1];
	c1 = trackA[2];
	d1 = trackA[3];
	e1 = trackA[4];
	a2 = trackB[0];
	b2 = trackB[1];
	c2 = trackB[2];
	d2 = trackB[3];
	e2 = trackB[4];

	Subround(F, a1, b1, c1, d1, e1, X[ 0], 11, k0);
	Subround(F, e1, a1, b1, c1, d1, X[ 1], 14, k0);
	Subround(F, d1, e1, a1, b1, c1, X[ 2], 15, k0);
	Subround(F, c1, d1, e1, a1, b1, X[ 3], 12, k0);
	Subround(F, b1, c1, d1, e1, a1, X[ 4],  5, k0);
	Subround(F, a1, b1, c1, d1, e1, X[ 5],  8, k0);
	Subround(F, e1, a1, b1, c1, d1, X[ 6],  7, k0);
	Subround(F, d1, e1, a1, b1, c1, X[ 7],  9, k0);
	Subround(F, c1, d1, e1, a1, b1, X[ 8], 11, k0);
	Subround(F, b1, c1, d1, e1, a1, X[ 9], 13, k0);
	Subround(F, a1, b1, c1, d1, e1, X[10], 14, k0);
	Subround(F, e1, a1, b1, c1, d1, X[11], 15, k0);
	Subround(F, d1, e1, a1, b1, c1, X[12],  6, k0);
	Subround(F, c1, d1, e1, a1, b1, X[13],  7, k0);
	Subround(F, b1, c1, d1, e1, a1, X[14],  9, k0);
	Subround(F, a1, b1, c1, d1, e1, X[15],  8, k0);

	Subround(G, e1, a1, b1, c1, d1, X[ 7],  7, k1);
	Subround(G, d1, e1, a1, b1, c1, X[ 4],  6, k1);
	Subround(G, c1, d1, e1, a1, b1, X[13],  8, k1);
	Subround(G, b1, c1, d1, e1, a1, X[ 1], 13, k1);
	Subround(G, a1, b1, c1, d1, e1, X[10], 11, k1);
	Subround(G, e1, a1, b1, c1, d1, X[ 6],  9, k1);
	Subround(G, d1, e1, a1, b1, c1, X[15],  7, k1);
	Subround(G, c1, d1, e1, a1, b1, X[ 3], 15, k1);
	Subround(G, b1, c1, d1, e1, a1, X[12],  7, k1);
	Subround(G, a1, b1, c1, d1, e1, X[ 0], 12, k1);
	Subround(G, e1, a1, b1, c1, d1, X[ 9], 15, k1);
	Subround(G, d1, e1, a1, b1, c1, X[ 5],  9, k1);
	Subround(G, c1, d1, e1, a1, b1, X[ 2], 11, k1);
	Subround(G, b1, c1, d1, e1, a1, X[14],  7, k1);
	Subround(G, a1, b1, c1, d1, e1, X[11], 13, k1);
	Subround(G, e1, a1, b1, c1, d1, X[ 8], 12, k1);

	Subround(H, d1, e1, a1, b1, c1, X[ 3], 11, k2);
	Subround(H, c1, d1, e1, a1, b1, X[10], 13, k2);
	Subround(H, b1, c1, d1, e1, a1, X[14],  6, k2);
	Subround(H, a1, b1, c1, d1, e1, X[ 4],  7, k2);
	Sub