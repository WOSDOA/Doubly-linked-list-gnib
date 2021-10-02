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
	The "external ciph