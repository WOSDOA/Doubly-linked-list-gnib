#ifndef CRYPTOPP_ECCRYPTO_H
#define CRYPTOPP_ECCRYPTO_H

/*! \file
*/

#include "pubkey.h"
#include "integer.h"
#include "asn.h"
#include "hmac.h"
#include "sha.h"
#include "gfpcrypt.h"
#include "dh.h"
#include "mqv.h"
#include "ecp.h"
#include "ec2n.h"

NAMESPACE_BEGIN(CryptoPP)

//! Elliptic Curve Parameters
/*! This class corresponds to the ASN.1 sequence of the same name
    in ANSI X9.62 (also SEC 1).
*/
template <class EC>
class DL_GroupParameters_EC : public DL_GroupParametersImpl<EcPrecomputation<EC> >
{
	typedef DL_GroupParameters_EC<EC> ThisClass;

public:
	typedef EC EllipticCurve;
	typedef typename EllipticCurve::Point Point;
	typedef Point Element;
	typedef IncompatibleCofactorMultiplication DefaultCofactorOption;

	DL_GroupParameters_EC() : m_compress(false), m_encodeAsOID(false) {}
	DL_GroupParameters_EC(const OID &oid)
		: m_compress(false), m_encodeAsOID(false) {Initialize(oid);}
	DL_GroupParameters_EC(const EllipticCurve &ec, const Point &G, const Integer &n, const Integer &k = Integer::Zero())
		: m_compress(false), m_encodeAsOID(false) {Initialize(ec, G, n, k);}
	DL_GroupParameters_EC(BufferedTransformation &bt)
		: m_compress(false), m_encodeAsOID(false) {BERDecode(bt);}

	void Initialize(const EllipticCurve &ec, const Point &G, const Integer &n, const Integer &k = Integer::Zero())
	{
		this->m_groupPrecomputation.SetCurve(ec);
		this->SetSubgroupGenerator(G);
		m_n = n;
		m_k = k;
	}
	void Initialize(const OID &oid);

	// NameValuePairs
	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const;
	void AssignFrom(const NameValuePairs &source);

	// GeneratibleCryptoMaterial interface
	//! this implementation doesn't actually generate a curve, it just initializes the parameters with existing values
	/*! parameters: (Curve, SubgroupGenerator, SubgroupOrder, Cofactor (optional)), or (GroupOID) */
	void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &alg);

	// DL_GroupParameters
	const DL_FixedBasePrecomputation<Element> & GetBasePrecomputation() const {return this->m_gpc;}
	DL_FixedBasePrecomputation<Element> & AccessBasePrecomputation() {return this->m_gpc;}
	const Integer & GetSubgroupOrder() const {return m_n;}
	Integer GetCofactor() const;
	bool ValidateGroup(RandomNumberGenerator &rng, unsigned int level) const;
	bool ValidateElement(unsigned int level, const Element &element, const DL_FixedBasePrecomputation<Element> *precomp) const;
	bool FastSubgroupCheckAvailable() const {return false;}
	void EncodeElement(bool reversible, const Element &element, byte *encoded) const
	{
		if (reversible)
			GetCurve().EncodePoint(encoded, element, m_compress);
		else
			element.x.Encode(encoded, GetEncodedElementSize(false));
	}
	unsigned int GetEncodedElementSize(bool reversible) const
	{
		if (reversible)
			return GetCurve().EncodedPointSize(m_compress);
		else
			return GetCurve().GetField().MaxElementByteLength();
	}
	Element DecodeElement(const byte *encoded, bool checkForGroupMembership) const
	{
		Point result;
		if (!GetCurve().DecodePoint(result, encoded, GetEncodedElementSize(true)))
			throw DL_BadElement();
		if (checkForGroupMembership && !ValidateElement(1, result, NULL))
			throw DL_BadElement();
		return result;
	}
	Integer ConvertElementToInteger(const Element &element) const;
	Integer GetMaxExponent() const {return GetSubgroupOrder()-1;}
	bool IsIdentity(const Element &element) const {return element.identity;}
	void SimultaneousExponentiate(Element *results, const Element &base, const Integer *exponents, unsigned int exponentsCount) const;
	static std::string CRYPTOPP_API Static