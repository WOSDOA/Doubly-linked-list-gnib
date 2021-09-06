// ecp.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "ecp.h"
#include "asn.h"
#include "nbtheory.h"

#include "algebra.cpp"

NAMESPACE_BEGIN(CryptoPP)

ANONYMOUS_NAMESPACE_BEGIN
static inline ECP::Point ToMontgomery(const ModularArithmetic &mr, const ECP::Point &P)
{
	return P.identity ? P : ECP::Point(mr.ConvertIn(P.x), mr.ConvertIn(P.y));
}

static inline ECP::Point FromMontgomery(const ModularArithmetic &mr, const ECP::Point &P)
{
	return P.identity ? P : ECP::Point(mr.ConvertOut(P.x), mr.ConvertOut(P.y));
}
NAMESPACE_END

ECP::ECP(const ECP &ecp, bool convertToMontgomeryRepresentation)
{
	if (convertToMontgomeryRepresentation && !ecp.GetField().IsMontgomeryRepresentation())
	{
		m_fieldPtr.reset(new MontgomeryRepresentation(ecp.GetField().GetModulus()));
		m_a = GetField().ConvertIn(ecp.m_a);
		m_b = GetField().ConvertIn(ecp.m_b);
	}
	else
		operator=(ecp);
}

ECP::ECP(BufferedTransformation &bt)
	: m_fieldPtr(new Field(bt))
{
	BERSequenceDecoder seq(bt);
	GetField().BERDecodeElement(seq, m_a);
	GetField().BERDecodeElement(seq, m_b);
	// skip optional seed
	if (!seq.EndReached())
	{
		SecByteBlock seed;
		unsigned int unused;
		BERDecodeBitString(seq, seed, unused);
	}
	seq.MessageEnd();
}

void ECP::DEREncode(BufferedTransformation &bt) const
{
	GetField().DEREncode(bt);
	DERSequenceEncoder seq(bt);
	GetField().DEREncodeElement(seq, m_a);
	GetField().DEREncodeElement(seq, m_b);
	seq.MessageEnd();
}

bool ECP::DecodePoint(ECP::Point &P, const byte *encodedPoint, size_t encodedPointLen) const
{
	StringStore store(encodedPoint, encodedPointLen);
	return DecodePoint(P, store, encodedPointLen);
}

bool ECP::DecodePoint(ECP::Point &P, BufferedTransformation &bt, size_t encodedPointLen) const
{
	byte type;
	if (encodedPointLen < 1 || !bt.Get(type))
		return false;

	switch (type)
	{
	case 0:
		P.identity = true;
		return true;
	case 2:
	case 3:
	{
		if (encodedPointLen != EncodedPointSize(true))
			return false;

		Integer p = FieldSize();

		P.identity = false;
		P.x.Decode(bt, GetField().MaxElementByteLength()); 
		P.y = ((P.x*P.x+m_a)*P.x+m_b) % p;

		if (Jacobi(P.y, p) !=1)
			return false;

		P.y = ModularSquareRoot(P.y, p);

		if ((type & 1) != P.y.GetBit(0))
			P.y = p-P.y;

		return true;
	}
	case 4:
	{
		if (encodedPointLen != EncodedPointSize(false))
			return false;

		unsigned int len = GetField().MaxElementByteLength();
		P.identity = false;
		P.x.Decode(bt, len);
		P.y.Decode(bt, len);
		return true;
	}
	default:
		return false;
	}
}

void ECP::EncodePoint(BufferedTransformation &bt, const Point &P, bool compressed) const
{
	if (P.identity)
		NullStore().TransferTo(bt, EncodedPointSize(compressed));
	else if (compressed)
	{
		bt.Put(2 + P.y.GetBit(0));
		P.x.Encode(bt, GetField().MaxElementByteLength());
	}
	else
	{
		unsigned int len = GetField().MaxElementByteLength();
		bt.Put(4);	// uncompressed
		P.x.Encode(bt, len);
		P.y.Encode(bt, len);
	}
}

void ECP::EncodePoint(byte *encodedPoint, const Point &P, bool compressed) const
{
	ArraySink sink(encodedPoint, EncodedPointSize(compressed));
	EncodePoint(sink, P, compressed);
	assert(sink.TotalPutLength() == EncodedPointSize(compressed));
}

ECP::Point ECP::BERDecodePoint(BufferedTransformation &bt) const
{
	SecByteBlock str;
	BERDecodeOctetString(bt, str);
	Point P;
	if (!DecodePoint(P, str, str.size()))
		BERDecodeError();
	return P;
}

void ECP::DEREncodePoint(BufferedTransformation &bt, const Point &P, bool compressed) const
{
	SecByteBlock str(EncodedPointSize(compressed));
	EncodePoint(str, P, compressed);
	DEREncodeOctetString(bt, str);
}

bool ECP::ValidateParameters(RandomNumberGenerator &rng, unsigned int level) const
{
	Integer p = FieldSize();

	bool pass = p.IsOdd();
	pass = pass && !m_a.IsNegative() && m_a<p && !m_b.IsNegative() && m_b<p;

	if (level >= 1)
		pass = pass && ((4*m_a*m_a*m_a+27*m_b*m_b)%p).IsPositive();

	if (level >= 2)
		pass = pass && VerifyPrime(rng, p);

	return pass;
}

bool ECP::VerifyPoint(const Point &P) const
{
	const FieldElement &x = P.x, &y = P.y;
	Integer p = FieldSize();
	return P.identity ||
		(!x.IsNegative() && x<p && !y.IsNegative() && y<p
		&& !(((x*x+m_a)*x+m_b-y*y)%p));
}

bool ECP::Equal(const Point &P, const Point &Q) const
{
	if (P.identity && Q.identity)
		return true;

	if (P.identity && !Q.identity)
		return false;

	if (!P.identity && Q.identity)
		return false;

	return (GetField().Equal(P.x,Q.x) && GetField().Equal(P.y,Q.y));
}

const ECP::Point& ECP::Identity() const
{
	return Singleton<Point>().Ref();
}

const ECP::Point& ECP::Inverse(const Point &P) const
{
	if (P.identity)
		return P;
	else
	{
		m_R.identity = false;
		m_R.x = P.x;
		m_R.y = GetField().Inverse(P.y);
		return m_R;
	}
}

const ECP::Point& ECP::Add(const Point &P, const Point &Q) const
{
	if (P.identity) return Q;
	if (Q.identity) return P;
	if (GetField()