// emsa2.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "emsa2.h"

#ifndef CRYPTOPP_IMPORTS

NAMESPACE_BEGIN(CryptoPP)

void EMSA2Pad::ComputeMessageRepresentative(RandomNumberGenerator &rng, 
	const byte *recoverableMessage, size_t recoverableMessageLength,
	HashTransformation &hash, HashIdentifier hashIdentifier, bool messageEmpty,
	byte *representative, size_t representativeBitLength) const
{
	assert(representativeBitLength >= MinRepresentativeBitLength(hashIdentifier.second, hash.DigestSize()));

	if (representativeBitLength % 8 != 7)
		throw PK_SignatureScheme::InvalidKeyLength("EMSA2: EMSA2 requires a key length that is a multi