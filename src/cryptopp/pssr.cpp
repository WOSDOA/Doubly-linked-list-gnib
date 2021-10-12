// pssr.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "pssr.h"
#include <functional>

NAMESPACE_BEGIN(CryptoPP)

// more in dll.cpp
template<> const byte EMSA2HashId<RIPEMD160>::id = 0x31;
template<> const byte EMSA2HashId<RIPEMD128>::id = 0x32;
template<> const byte EMSA2HashId<Whirlpool>::id = 0x37;

#ifndef CRYPTOPP_IMPORTS

size_t PSSR_MEM_Base::MinRepresentativeBitLength(size_t hashIdentifierLength, size_t digestLength) const
{
	size_t saltLen = SaltLen(digestLength);
	size_t minPadLen = MinPadLen(digestLength);
	return 9 + 8*(minPadLen + saltLen + digestLength + hashIdentifierLength);
}

size_t PSSR_MEM_Base::MaxRecoverableLength(size_t representativeBitLength, size_t hashIdentifierLength, size_t digestLength) const
{
	if (AllowRecovery())
		return SaturatingSubtract(representativeBitLength, MinRepresentativeBitLength(hashIdentifierLength, digestLength)) / 8;
	return 0;
}

bool PSSR_MEM_Base::IsProbabilistic() const 
{
	return SaltLen(1) > 0;
}

bool PSSR_MEM_Base::AllowNonrecoverablePart() const
{
	return true;
}

bool PSSR_MEM_Base::RecoverablePartFirst() const
{
	return false;
}

void PSSR_MEM_Base::ComputeMessageRepresentative(RandomNumberGenerator &rng, 
	const byte *recoverableMessage, size_t recoverableMessageLength,
	HashTransformation &hash, HashIdentifier hashIdentifier, bool messageEmpty,
	byte *representative, size_t representativeBitLength) const
{
	assert(representativeBitLength >= MinRepresentativeBitLength(hashIdentifier.second, hash.DigestSize()));

	const size_t u = hashIdentifier.second + 1;
	const size_t representativeByteLength = BitsToBytes(representativeBitLength);
	const size_t digestSize = hash.DigestSize();
	const size_t saltSize = SaltLen(digestSize);
	byte *const h = representative + representativeByteLength - u - digestSize;

	SecByteBlock digest(digestSize), salt(saltSize);
	hash.Final(digest);
	rng.GenerateBlock(salt, saltSize);

	/