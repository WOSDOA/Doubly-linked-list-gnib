// authenc.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "authenc.h"

NAMESPACE_BEGIN(CryptoPP)

void AuthenticatedSymmetricCipherBase::AuthenticateData(const byte *input, size_t len)
{
	unsigned int blockSize = AuthenticationBlockSize();
	unsigned int &num = m_bufferedDataLength;
	byte* data = m_buffer.begin();

	if (num != 0)	// process left over data
	{
		if (num+len >= blockSize)
		{
			memcpy(data+num, input, blockSize-num);
			AuthenticateBlocks(data, blockSize);
			input += (blockSize-num);
			len -= (blockSize-num);
			num = 0;
			// drop through and do the rest
		}
		else
		{
			memcpy(data+num, input, len);
			num += (unsigned int)len;
			return;
		}
	}

	// now process the input data in blocks of blockSize bytes and save the leftovers to m_data
	if (len >= blockSize)
	{
		size_t leftOver = AuthenticateBlocks(input, len);
		input += (len - leftOver);
		len = leftOver;
	}

	memcpy(data, input, len);
	num = (unsigned int)len;
}

void AuthenticatedSymmetricCipherBase::SetKey(const byte *userKey, size_t keylength, const NameValuePairs &params)
{
	m_bufferedDataLength = 0;
	m_state = State_Start;

	SetKeyWithoutResync(userKey, keylength, params);
	m_state = State_KeySet;

	size_t length;
	const byte *iv = GetIVAndThrowIfInvalid(params, length);
	if (iv)
		Resynchronize(iv, (int)length);
}

void AuthenticatedSymmetricCipherBase::Resynchronize(const byte *iv, int length)
{
	if (m_state < State_KeySet)
		throw BadState(AlgorithmName(), "Resynchronize", "key is set");

	m_bufferedDataLength = 0;
	m_totalHeaderLength = m_totalMessageLength = m_tot