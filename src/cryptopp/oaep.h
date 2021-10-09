#ifndef CRYPTOPP_OAEP_H
#define CRYPTOPP_OAEP_H

#include "pubkey.h"
#include "sha.h"

NAMESPACE_BEGIN(CryptoPP)

//! _
class CRYPTOPP_DLL OAEP_Base : public PK_EncryptionMessageEncodingMethod
{
public:
	bool ParameterSupported(const char *name) const {return strcmp(name, Name::EncodingParameters()) == 0;}
	size_t MaxUnpaddedLength(size_t paddedLength) const;
	void Pad(RandomNumberGenerator &rng, const byte 