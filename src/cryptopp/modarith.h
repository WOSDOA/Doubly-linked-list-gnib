#ifndef CRYPTOPP_MODARITH_H
#define CRYPTOPP_MODARITH_H

// implementations are in integer.cpp

#include "cryptlib.h"
#include "misc.h"
#include "integer.h"
#include "algebra.h"

NAMESPACE_BEGIN(CryptoPP)

CRYPTOPP_DLL_TEMPLATE_CLASS AbstractGroup<Integer>;
CRYPTOPP_DLL_TEMPLATE_CLASS AbstractRing<Integer>;
CRYPTOPP_DLL_TEMPLATE_CLASS AbstractEuclideanDomain<Integer>;

//! ring of congruence classes modulo n
/*! \note this implementation represents each congruence class as the smallest non-negative integer in that class */
class CRYPTOPP_DLL ModularArithmetic : public AbstractRing<Integer>
{
public:

	typedef int RandomizationParameter;
	typedef Integer Element;

	ModularArithmetic(const Integer &modulus = Integer::One())
		: m_modulus(modulus), m_result((word)0, modulus.reg.size()) {}

	ModularArithmetic(const ModularArithmetic &ma)
		: m_modulus(ma.m_modulus), m_result((word)0, m_modulus.reg.size()) {}

	ModularArithmetic(BufferedTransformation &bt);	// construct from BER encoded parameters

	virtual ModularArithmetic * Clone() const {return new ModularArithmetic(*this);}

	void DEREncode(BufferedTransformation &bt) const;

	void DEREncodeElement(BufferedTransformation &out, const Element &a) const;
	void BERDecodeElement(BufferedTransformation &in, Element &a) const;

	const Integer& GetModulus() const {return m_modulus;}
	void SetModulus(const Integer &newModulus) {m_modulus = newModulus; m_result.reg.resize(m_modulus.reg.size());}

	virtual bool IsMontgomeryRepresentation() const {return false;}

	virtual Integer ConvertIn(const Integer &a) const
		{retu