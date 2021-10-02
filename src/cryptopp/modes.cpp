// modes.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "modes.h"

#ifndef NDEBUG
#include "des.h"
#endif

NAMESPACE_BEGIN(CryptoPP)

#ifndef NDEBUG
void Modes_TestInstantiations()
{
	CFB_Mode<DES>::Encryption m0;
	CFB_Mode<DES>::Decryption m1;
	OFB_Mode<DES>::Encryption m2;
	CTR_Mode<DES>::Encryption m3;
	ECB_Mode<DES>::Encryption m4;
	CBC_Mode<DES>::Encryption m5;
}
#endif

void CFB_ModePolicy::Iterate(byte *output, const byte *input, CipherDir dir, size_t iterationCount)
{
	assert(m_cipher->IsForwardTransformation());	// CFB mode needs the "encrypt" direction of the underlying block cipher, even to decrypt
	assert(m_feedbackSize == BlockSize());

	unsigned int s = BlockSize();
	if (dir == ENCRYPTION)
	{
		m_cipher->ProcessAndXorBlock(m_register, input, output);
		m_cipher->AdvancedProcessBlocks(output, input+s, output+s, (iterationCount-1)*s, 0);
		memcpy(m_register, output+(iterationCount-1)*s, s);
	}
	else
	{
		memcpy(m_temp, input+(iterationCount-1)*s, s);	// make copy first in case of in-place decryption
		m_cipher->AdvancedProcessBlocks(input, input+s, output+s, (iterationCount-1)*s, BlockTransformation::BT_ReverseDirection);
		m_cipher->ProcessAndXorBlock(m_register, input, output);
		memcpy(m_register, m_temp, s);
	}
}

void CFB_ModePolicy::TransformRegister()
{
	assert(m_cipher->IsForwardTransformation());	// CFB mode needs the "encrypt" direction of the underlying block cipher, even to decrypt
	m_cipher->ProcessBlock(m_register, m_temp);
	unsigned int updateSize = BlockSize()-m_feedbackSize;
	memmove_s(m_register, m_register.size(), m_register+m_feedbackSize, updateSize);
	memcpy_s(m_register+updateSize, m_register.size()-updateSize, m_temp, m_feedbackSize);
}

void CFB_ModePolicy::CipherResynchronize(const byte *iv, size_t length)
{
	assert(length == BlockSize());
	CopyOrZero(m_register, iv, length);
	TransformRegister();
}

void CFB_ModePolicy::SetFeedbackSize(unsigned int feedbackSize)
{
	if (feedbackSize > BlockSize())
		throw InvalidArgument("CFB_Mode: invalid feedback size");
	m_feedbackSize = feedbackSize ? feedbackSize : BlockSize();
}

void CFB_ModePolicy::ResizeBuffers()
{
	CipherModeBase::ResizeBuffers();
	m_temp.New(BlockSize());
}
