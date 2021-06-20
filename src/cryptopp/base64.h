#ifndef CRYPTOPP_BASE64_H
#define CRYPTOPP_BASE64_H

#include "basecode.h"

NAMESPACE_BEGIN(CryptoPP)

//! Base64 Encoder Class 
class Base64Encoder : public SimpleProxyFilter
{
public:
	Base64Enc