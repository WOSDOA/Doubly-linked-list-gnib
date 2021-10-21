// pwdbased.h - written and placed in the public domain by Wei Dai

#ifndef CRYPTOPP_PWDBASED_H
#define CRYPTOPP_PWDBASED_H

#include "cryptlib.h"
#include "hmac.h"
#include "hrtimer.h"
#include "integer.h"

NAMESPACE_BEGIN(CryptoPP)

//! abstract base class for password based key derivation function
class PasswordBasedKeyDerivationFunction
{
public:
	virtual size_t MaxDerivedKeyLength() const =0;
	virtual bool UsesPurposeByte() const =0;
	//! derive key from password
	/*! If timeInSeconds != 0, will iterate until time elapsed, as measured by ThreadUserTimer
		Returns actual iteration count, which is equal to iterations if timeInSeconds == 0, and not less than iterations otherwise. */
	virtual unsigned int DeriveKey(byte *derived, size_t derivedLen, byte purpose, const byte *password, size_t passwordLen, const byte *salt, size_t saltLen, unsigned int iterations, double timeInSeconds=0) const =0;
};

//! PBKDF1 from PKCS #5, T should be a HashTransformation class
template <class T>
class PKCS5_PBKDF1 : public PasswordBasedKeyDerivationFunction
{
public:
	size_t MaxDerivedKeyLength() const {return T::DIGESTSIZE;}
	bool UsesPurposeByte() const {return false;}
	// PKCS #5 says PBKDF1 should only take 8-byte salts. This implementation allows salts of any length.
	unsigned int DeriveKey(byte *derived, size_t derivedLen, byte purpose, const byte *password, size_t passwordLen, const byte *salt, size_t saltLen, unsigned int iterations, double timeInSeconds=0) const;
};

//! PBKDF2 from PKCS #5, T should be a HashTransformation class
template <class T>
class PKCS5_PBKDF2_HMAC : public PasswordBasedKeyDerivationFunction
{
public:
	size_t MaxDerivedKeyLength() const {return 0xffffffffU;}	// should multiply by T::DIGESTSIZE, but gets overflow that way
	bool UsesPurposeByte() const {return false;}
	unsigned int DeriveKey(byte *derived, size_t derivedLen, byte purpose, const byte *password, size_t passwordLen, const byte *salt, size_t saltLen, unsigned int iterations, double timeInSeconds=0) const;
};

/*
class PBKDF2Params
{
public:
	SecByteBlock m_salt;
	unsigned int m_interationCount;
	ASNOptional<ASNUnsignedWrapper<word32> > m_keyLength;
};
*/

template <class T>
unsigned int PKCS5_PBKDF1<T>::DeriveKey(byte *derived, size_t derivedLen, byte purpose, const byte *password, size_t passwordLen, const byte *salt, size_t saltLen, unsigned int iterations, double timeInSeconds) const
{
	assert(derivedLen <= MaxDerivedKeyLength());
	assert(iterations > 0 || timeInSeconds > 0);

	if (!iterations)
		iterations = 1;

	T hash;
	hash.Update(password, passwordLen);
	hash.Update(salt, saltLen);

	SecByteBlock buffer(hash.DigestSize());
	hash.Final(buffer);

	unsigned int i;
	ThreadUserTimer timer;

	if (timeInSeconds)
		timer.StartTimer();

	for (i=1; i<iterations || (timeInSeconds && (i%128!=0 || timer.ElapsedTimeAsDouble() < timeInSeconds)); i++)
		hash.CalculateDigest(buffer, buffer, buffer.size());

	memcpy(derived, buffer, derivedLen);
	return i;
}

template <class T>
unsigned int PKCS5_PBKDF2_HMAC<T>::DeriveKey(byte *derived, size_t derivedLen, byte purpose, const byte *password, size_t passwordLen, const byte *salt, size_t saltLen, unsigned int iterations, double timeInSeconds) const
{
	assert(derivedLen <= MaxDerivedKeyLength());
	assert(iterati