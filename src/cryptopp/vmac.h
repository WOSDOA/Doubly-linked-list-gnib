#ifndef CRYPTOPP_VMAC_H
#define CRYPTOPP_VMAC_H

#include "iterhash.h"
#include "seckey.h"

NAMESPACE_BEGIN(CryptoPP)

/// .
class VMAC_Base : public IteratedHashBase<word64, MessageAuthenticationCode>
{
public:
	std::st