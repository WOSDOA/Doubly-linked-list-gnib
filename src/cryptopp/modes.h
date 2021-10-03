#ifndef CRYPTOPP_MODES_H
#define CRYPTOPP_MODES_H

/*! \file
*/

#include "cryptlib.h"
#include "secblock.h"
#include "misc.h"
#include "strciphr.h"
#include "argnames.h"
#include "algparam.h"

NAMESPACE_BEGIN(CryptoPP)

//! Cipher modes documentation. See NIST SP 800-38A for definitions of these modes. See AuthenticatedSymmetricCipherDocumentation for authenticated encryption modes.

/*! Each class derived from this one defines two types, Encryption and Decryption, 
	both of which implement the SymmetricCipher interface.
	For each mode there are two classes, one of which is a template class,
	and the other one has a name that ends in "_ExternalCipher".
	The "external cipher" mode objects hold a reference to the underlying block cipher,
	instead of holding an instance of it. The reference must be passed in to the constructor.
	For the "cipher holder" classes, the CIPHER template parameter should be a class
	derived from BlockCipherDocumentation, for example DES or AES.
*/
struct CipherModeDocumentation : public SymmetricCipherDocumentation
{
};

class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE CipherModeBase : public SymmetricCipher
{
public:
	size_t MinKeyLength() const {return m_cipher->MinKeyLength();}
	size_t MaxKeyLength() const {return m_cipher->MaxKeyLength();}
	size_t DefaultKeyLength() const {return m_cipher->DefaultKeyLength();}
	size_t GetValidKeyLength(size_t n) const {return m_cipher->GetValidKeyLength(n);}
	bool IsValidKeyLength(size_t n) const {return m_cipher->IsValidKeyLength(n);}

	unsigned int OptimalDataAlignment() const {return m_cipher->OptimalDataAlignment();}

	unsigned int IVSize() const {return BlockSize();}
	virtual IV_Requirement IVRequirement() const =0;

	void SetCipher(BlockCipher &cipher)
	{
		this->ThrowIfResynchronizable();
		this->m_cipher = &cipher;
		this->ResizeBuffers();
	}

	void SetCipherWithIV(BlockCipher &cipher, const byte *iv, int feedbackSize = 0)
	{
		this->ThrowIfInvalidIV(iv);
		this->m_cipher = &cipher;
		this->ResizeBuffers();
		this->SetFeedbackSize(feedbackSize);
		if (this->IsResynchronizable())
			this->Resynchronize(iv);
	}

protected:
	CipherModeBase() : m_cipher(NULL) {}
	inline unsigned int BlockSize() const {assert(m_register.size() > 0); return (unsigned int)m_register.size();}
	virtual void SetFeedbackSize(unsigned int feedbackSize)
	{
		if (!(feedbackSize == 0 || feedbackSize == BlockSize()))
			throw InvalidArgument("CipherModeBase: feedback size cannot be specified for this cipher mode");
	}
	virtual void ResizeBuffers()
	{
		m_register.New(m_cipher->BlockSize());
	}

	BlockCipher *m_cipher;
	AlignedSecByteBlock m_register;
};

template <class POLICY_INTERFACE>
class CRYPTOPP_NO_VTABLE ModePolicyCommonTemplate : public CipherModeBase, public POLICY_INTERFACE
{
	unsigned int GetAlignment() const {return m_cipher->OptimalDataAlignment();}
	void CipherSetKey(const NameValuePairs &params, const byte *key, size_t length);
};

template <class POLICY_INTERFACE>
void ModePolicyCommonTemplate<POLICY_INTERFACE>::CipherSetKey(const NameValuePairs &params, const byte *key, size_t length)
{
	m_cipher->SetKey(key, length, params);
	ResizeBuffers();
	int feedbackSize = params.GetIntValueWithDefault(Name::FeedbackSize(), 0);
	SetFeedbackSize(feedbackSize);
}

class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE CFB_ModePolicy : public ModePolicyCommonTemplate<CFB_CipherAbstractPolicy>
{
public:
	IV_Requirement IVRequirement() const {return RANDOM_IV;}
	static const char * CRYPTOPP_API StaticAlgorithmName() {return "CFB";}

protected:
	unsigned int GetBytesPerIteration() const {return m_feedbackSize;}
	byte * GetRegisterBegin() {return m_register + BlockSize() - m_feedbackSize;}
	bool CanIterate() const {return m_feedbackSize == BlockSize();}
	void Iterate(byte *output, const byte *input, CipherDir dir, size_t iterationCount);
	void TransformRegister();
	void CipherResynchronize(const byte *iv, size_t length);
	void SetFeedbackSize(unsigned int feedbackSize);
	void ResizeBuffers();

	SecByteBlock m_temp;
	unsigned int m_feedbackSize;
};

inline void CopyOrZero(void *dest, const void *src, size_t s)
{
	if (src)
		memcpy_s(dest, s, src, s);
	else
		memset(dest, 0, s);
}

class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE OFB_ModePolicy : public ModePolicyCommonTemplate<AdditiveCipherAbstractPolicy>
{
public:
	bool CipherIsRandomAccess() const {return false;}
	IV_Requirement IVRequirement() const {return UNIQUE_IV;}
	static const char * CRYPTOPP_API StaticAlgorithmName() {return "OFB";}

private:
	unsigned int GetBytesPerIteration() const {return BlockSize();}
	unsigned int GetIterationsToBuffer() const {return m_cipher->OptimalNumberOfParallelBlocks();}
	void WriteKeystream(byte *keystreamBuffer, size_t iterationCount);
	void CipherResynchronize(byte *keystreamBuffer, const byte *iv, size_t length);
};

class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE CTR_ModePolicy : public ModePolicyCommonTemplate<AdditiveCipherAbstractPolicy>
{
public:
	bool CipherIsRandomAccess() const {return true;}
	IV_Requirement IVRequirement() const {return RANDOM_IV;}
	static const char * CRYPTOPP_API StaticAlgorithmName() {return "CTR";}

protected:
	virtual void IncrementCounterBy256();

	unsigned int GetAlignment() const {return m_cipher->OptimalDataAlignment();}
	unsigned int GetBytesPerIteration() const {return BlockSize();}
	unsigned int GetIterationsToBuffer() const {return m_cipher->OptimalNumberOfParallelBlocks();}
	void WriteKeystream(byte *buffer, size_t iterationCount)
		{OperateKeystream(WRITE_KEYSTREAM, buffer, NULL, iterationCount);}
	bool CanOperateKeystream() const {return true;}
	void OperateKeystream(KeystreamOperation operation, byte *output, const byte *input, size_t iterationCount);
	void CipherResynchronize(byte *keystreamBuffer, const byte *iv, size_t length);
	void SeekToIteration(lword iterationCount);

	AlignedSecByteBlock m_counterArray;
};

class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE BlockOrientedCipherModeBase : public CipherModeBase
{
public:
	void UncheckedSetKey(const byte *key, unsigned int length, const NameValuePairs &params);
	unsigned int MandatoryBlockSize() const {return BlockSize();}
	bool IsRandomAccess() const {return false;}
	bool IsSelfInverting() const {return false;}
	bool IsForwardTransformation() const {return m_cipher->IsForwardTransformation();}
	void Resynchronize(const byte *iv, int length=-1) {memcpy_s(m_register, m_register.size(), iv, ThrowIfInvalidIVLength(length));}

protected:
	bool RequireAlignedInput() const {return true;}
	void ResizeBuffers()
	{
		CipherModeBase::ResizeBuffers();
		m_buffer.New(BlockSize());
	}

	SecByteBlock m_buffer;
};

class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE ECB_OneWay : public BlockOrientedCipherModeBase
{
public:
	void SetKey(const byte *key, size_t length, const NameValuePairs &params = g_nullNameValuePai