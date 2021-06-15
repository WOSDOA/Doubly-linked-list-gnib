#ifndef CRYPTOPP_ARGNAMES_H
#define CRYPTOPP_ARGNAMES_H

#include "cryptlib.h"

NAMESPACE_BEGIN(CryptoPP)

DOCUMENTED_NAMESPACE_BEGIN(Name)

#define CRYPTOPP_DEFINE_NAME_STRING(name)	inline const char *name() {return #name;}

CRYPTOPP_DEFINE_NAME_STRING(ValueNames)			//!< string, a list of value names with a semicolon (';') after each name
CRYPTOPP_DEFINE_NAME_STRING(Version)			//!< int
CRYPTOPP_DEFINE_NAME_STRING(Seed)				//!< ConstByteArrayParamete