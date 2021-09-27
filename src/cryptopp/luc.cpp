// luc.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "luc.h"
#include "asn.h"
#include "nbtheory.h"
#include "sha.h"
#include "algparam.h"

NAMESPACE_BEGIN(CryptoPP)

void LUC_TestInstantiations()
{
	LUC_HMP<SHA>::Signer t1;
	LUCFunction t2;
	InvertibleLUCFunction t3;
}

void DL_Algorithm_LUC_HMP::Sign(const DL_GroupParameters<Integer> &params, const Integer &x, const Integer &k, const Integer &e, Integer &r, Integer &s) const
{
	const Integer &q = params.GetSubgroupOrder();
	r = params.ExponentiateBase(k);
	s = (k + x*(r+e)) % q;
}

bool DL_Algorithm_LUC_HMP::Verify(const DL_GroupParameters<Integer> &params, const DL_PublicKey<Integer> &publicKey, const Integer &e, const Integer &r, const Integer &s) const
{
	Integer p = params.GetGroupOrder()-1;
	const Integer &q = params.GetSubgroupOrder();

	Integer Vsg = params.ExponentiateBase(s);
	Integer Vry = publicKey.ExponentiatePublicElement((r+e)%q);
	return (Vsg*Vsg + Vry*Vry + r*r) % p == (Vsg * Vry * r + 4) % p;
}

Integer DL_BasePrecomputation_LUC::Exponentiate(const DL_GroupPrecomputation<Element> &group, const Integer &exponent) const
{
	return Lucas(exponent, m_g, static_cast<const DL_GroupPrecomputation_LUC &>(group).GetModulus());
}

void DL_GroupParameters_LUC::SimultaneousExponentiate(Element *results, const Element &base, const Integer *exponents, unsigned int exponentsCount) const
{
	for (unsigned int i=0; i<exponentsCount; i++)
		results[i] = Lucas(exponents[i], base, GetModulus());
}

void LUCFunction::BERDecode(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	m_n.BERDecode(seq);
	m_e.BERDecode(seq);
	seq.MessageEnd();
}

void LUCFuncti