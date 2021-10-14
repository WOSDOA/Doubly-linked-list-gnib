// pubkey.h - written and placed in the public domain by Wei Dai

#ifndef CRYPTOPP_PUBKEY_H
#define CRYPTOPP_PUBKEY_H

/** \file

	This file contains helper classes/functions for implementing public key algorithms.

	The class hierachies in this .h file tend to look like this:
<pre>
                  x1
                 / \
                y1  z1
                 |  |
            x2<y1>  x2<z1>
                 |  |
                y2  z2
                 |  |
            x3<y2>  x3<z2>
                 |  |
                y3  z3
</pre>
	- x1, y1, z1 are abstract interface classes defined in cryptlib.h
	- x2, y2, z2 are implementations of the interfaces using "abstract policies", which
	  are pure virtual functions that should return interfaces to interchangeable algorithms.
	  These classes have "Base" suffixes.
	- x3, y3, z3 hold actual algorithms and implement those virtual functions.
	  These classes have "Impl" suffixes.

	The "TF_" prefix means an implementation using trapdoor functions on integers.
	The "DL_" prefix means an implementation using group operations (in groups where discrete log is hard).
*/

#include "modarith.h"
#include "filters.h"
#include "eprecomp.h"
#include "fips140.h"
#include "argnames.h"
#include <memory>

// VC60 workaround: this macro is defined in shlobj.h and conflicts with a template parameter used in this file
#undef INTERFACE

NAMESPACE_BEGIN(CryptoPP)

//! _
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE TrapdoorFunctionBounds
{
public:
	virtual ~TrapdoorFunctionBounds() {}

	virtual Integer PreimageBound() const =0;
	virtual Integer ImageBound() const =0;
	virtual Integer MaxPreimage() const {return --PreimageBound();}
	virtual Integer MaxImage() const {return --ImageBound();}
};

//! _
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE RandomizedTrapdoorFunction : public TrapdoorFunctionBounds
{
public:
	virtual Integer ApplyRandomizedFunction(RandomNumberGenerator &rng, const Integer &x) const =0;
	virtual bool IsRandomized() const {return true;}
};

//! _
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE TrapdoorFunction : public RandomizedTrapdoorFunction
{
public:
	Integer ApplyRandomizedFunction(RandomNumberGenerator &rng, const Integer &x) const
		{return ApplyFunction(x);}
	bool IsRandomized() const {return false;}

	virtual Integer ApplyFunction(const Integer &x) const =0;
};

//! _
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE RandomizedTrapdoorFunctionInverse
{
public:
	virtual ~RandomizedTrapdoorFunctionInverse() {}

	virtual Integer CalculateRandomizedInverse(RandomNumberGenerator &rng, const Integer &x) const =0;
	virtual bool IsRandomized() const {return true;}
};

//! _
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE TrapdoorFunctionInverse : public RandomizedTrapdoorFunctionInverse
{
public:
	virtual ~TrapdoorFunctionInverse() {}

	Integer CalculateRandomizedInverse(RandomNumberGenerator &rng, const Integer &x) const
		{return CalculateInverse(rng, x);}
	bool IsRandomized() const {return false;}

	virtual Integer CalculateInverse(RandomNumberGenerator &rng, const Integer &x) const =0;
};

// ********************************************************

//! message encoding method for public key encryption
class CRYPTOPP_NO_VTABLE PK_EncryptionMessageEncodingMethod
{
public:
	virtual ~PK_EncryptionMessageEncodingMethod() {}

	virtual bool ParameterSupported(const char *name) const {return false;}

	//! max size of unpadded message in bytes, given max size of padded message in bits (1 less than size of modulus)
	virtual size_t MaxUnpaddedLength(size_t paddedLength) const =0;

	virtual void Pad(RandomNumberGenerator &rng, const byte *raw, size_t inputLength, byte *padded, size_t paddedBitLength, const NameValuePairs &parameters) const =0;

	virtual DecodingResult Unpad(const byte *padded, size_t paddedBitLength, byte *raw, const NameValuePairs &parameters) const =0;
};

// ********************************************************

//! _
template <class TFI, class MEI>
class CRYPTOPP_NO_VTABLE TF_Base
{
protected:
	virtual const TrapdoorFunctionBounds & GetTrapdoorFunctionBounds() const =0;

	typedef TFI TrapdoorFunctionInterface;
	virtual const TrapdoorFunctionInterface & GetTrapdoorFunctionInterface() const =0;

	typedef MEI MessageEncodingInterface;
	virtual const MessageEncodingInterface & GetMessageEncodingInterface() const =0;
};

// ********************************************************

//! _
template <class BASE>
class CRYPTOPP_NO_VTABLE PK_FixedLengthCryptoSystemImpl : public BASE
{
public:
	size_t MaxPlaintextLength(size_t ciphertextLength) const
		{return ciphertextLength == FixedCiphertextLength() ? FixedMaxPlaintextLength() : 0;}
	size_t CiphertextLength(size_t plaintextLength) const
		{return plaintextLength <= FixedMaxPlaintextLength() ? FixedCiphertextLength() : 0;}

	virtual size_t FixedMaxPlaintextLength() const =0;
	virtual size_t FixedCiphertextLength() const =0;
};

//! _
template <class INTERFACE, class BASE>
class CRYPTOPP_NO_VTABLE TF_CryptoSystemBase : public PK_FixedLengthCryptoSystemImpl<INTERFACE>, protected BASE
{
public:
	bool ParameterSupported(const char *name) const {return this->GetMessageEncodingInterface().ParameterSupported(name);}
	size_t FixedMaxPlaintextLength() const {return this->GetMessageEncodingInterface().MaxUnpaddedLength(PaddedBlockBitLength());}
	size_t FixedCiphertextLength() const {return this->GetTrapdoorFunctionBounds().MaxImage().ByteCount();}

protected:
	size_t PaddedBlockByteLength() const {return BitsToBytes(PaddedBlockBitLength());}
	size_t PaddedBlockBitLength() const {return this->GetTrapdoorFunctionBounds().PreimageBound().BitCount()-1;}
};

//! _
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE TF_DecryptorBase : public TF_CryptoSystemBase<PK_Decryptor, TF_Base<TrapdoorFunctionInverse, PK_EncryptionMessageEncodingMethod> >
{
public:
	DecodingResult Decrypt(RandomNumberGenerator &rng, const byte *ciphertext, size_t ciphertextLength, byte *plaintext, const NameValuePairs &parameters = g_nullNameValuePairs) const;
};

//! _
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE TF_EncryptorBase : public TF_CryptoSystemBase<PK_Encryptor, TF_Base<RandomizedTrapdoorFunction, PK_EncryptionMessageEncodingMethod> >
{
public:
	void Encrypt(RandomNumberGenerator &rng, const byte *plaintext, size_t plaintextLength, byte *ciphertext, const NameValuePairs &parameters = g_nullNameValuePairs) const;
};

// ********************************************************

typedef std::pair<const byte *, size_t> HashIdentifier;

//! interface for message encoding method for public key signature schemes
class CRYPTOPP_NO_VTABLE PK_SignatureMessageEncodingMethod
{
public:
	virtual ~PK_SignatureMessageEncodingMethod() {}

	virtual size_t MinRepresentativeBitLength(size_t hashIdentifierLength, size_t digestLength) const
		{return 0;}
	virtual size_t MaxRecoverableLength(size_t representativeBitLength, size_t hashIdentifierLength, size_t digestLength) const
		{return 0;}

	bool IsProbabilistic() const 
		{return true;}
	bool AllowNonrecoverablePart() const
		{throw NotImplemented("PK_MessageEncodingMethod: this signature scheme does not support message recovery");}
	virtual bool RecoverablePartFirst() const
		{throw NotImplemented("PK_MessageEncodingMethod: this signature scheme does not support message recovery");}

	// for verification, DL
	virtual void ProcessSemisignature(HashTransformation &hash, const byte *semisignature, size_t semisignatureLength) const {}

	// for signature
	virtual void ProcessRecoverableMessage(HashTransformation &hash, 
		const byte *recoverableMessage, size_t recoverableMessageLength, 
		const byte *presignature, size_t presignatureLength,
		SecByteBlock &semisignature) const
	{
		if (RecoverablePartFirst())
			assert(!"ProcessRecoverableMessage() not implemented");
	}

	virtual void ComputeMessageRepresentative(RandomNumberGenerator &rng, 
		const byte *recoverableMessage, size_t recoverableMessage