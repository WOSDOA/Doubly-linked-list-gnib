// fips140.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "fips140.h"
#include "trdlocal.h"	// needs to be included last for cygwin

NAMESPACE_BEGIN(CryptoPP)

// Define this to 1 to turn on FIPS 140-2 compliance features, including additional tests during 
// startup