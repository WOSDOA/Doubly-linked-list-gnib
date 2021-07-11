#ifndef CRYPTOPP_CBCMAC_H
#define CRYPTOPP_CBCMAC_H

#include "seckey.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

//! _
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE CBC_MAC_Base : public MessageAuthenticationCode
{
public:
	CBC_MAC_Base() {}

	void UncheckedSetKey(const byte *key, unsigned int length, const NameValuePairs &params);
	void Update(const byte *input, size_t length);
	void TruncatedFinal(byte *mac, size_t size);
	unsigned int DigestSize() const {return const_cast<CBC_MAC_Base*>(this)->AccessCipher().BlockSize();}

protected:
	virtual BlockC