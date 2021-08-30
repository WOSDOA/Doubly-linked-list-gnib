#ifndef CRYPTOPP_DH_H
#define CRYPTOPP_DH_H

/** \file
*/

#include "gfpcrypt.h"

NAMESPACE_BEGIN(CryptoPP)

//! ,
template <class GROUP_PARAMETERS, class COFACTOR_OPTION = CPP_TYPENAME GROUP_PARAMETERS::DefaultCofactorOption>
class DH_Domain : public DL_SimpleKeyAgreementDomainBase<typename GROUP_PARAMETERS::Element>
{
	typedef DL_SimpleKeyAgreementDomainBase<typename GROUP_PARAMETERS::Element> Base;

public:
	typedef GROUP_PARAMETERS GroupParameters;
	typedef typename GroupParameters::Element Element;
	typedef DL_KeyAgreementAlgorithm_DH<Element, COFACTOR_OPTION> DH_Algorithm;
	typedef DH_Domain<GROUP_PARAMETERS, COFACTOR_OPTION> Domain;

	DH_Domain() {}

	DH_Domain(const GroupParameters &params)
		: m_groupParameters(params) {}

	DH_Domain(BufferedTransformation &bt)
		{m_groupParameters.BERDecode(bt);}

	template <class T2>
	DH_Domain(RandomNumberGenerator &v1, const T2 &v2)
		{m_groupParameters.Initialize(v1, v2);}
	
	template <class T2, class T3>
	DH_Domain(RandomNumberGenerator &v1, const T2 &v2, const T3 &v3)
		{m_groupParameters.Initialize(v1, v2, v3);}
	
	template <class T2, class T3, class T4>
	DH_Domain(RandomNumberGenerator &v1, const T2 &v2, const T3 &v3, const T4 &v4)
		{m_groupParameters.Initialize(v1, v2, v3, v4);}

	template <class T1, class T2>
	DH_Domain(const T1 &v1, const T2 &v2)
		{m_groupParameters.Initialize(v1, v2);}
	
	template <class T1, class T2, class T3>
	DH_Domain(const T1 &v1, const T2 &v2, const T3 &v3)
		{m_groupParameters.Initialize(v1, v2, v3);}
	
	template <class T1, class T2, class T3, class T4>
	DH_Domain(const T1 &v1, const T2 &v2, const T3 &v3, const T4 &v4