// dll.cpp - written and placed in the public domain by Wei Dai

#define CRYPTOPP_MANUALLY_INSTANTIATE_TEMPLATES
#define CRYPTOPP_DEFAULT_NO_DLL

#include "dll.h"
#pragma warning(default: 4660)

#if defined(CRYPTOPP_EXPORTS) && defined(CRYPTOPP_WIN32_AVAILABLE)
#include <windows.h>
#endif

#ifndef CRYPTOPP_IMPORTS

NAMESPACE_BEGIN(CryptoPP)

template<> const byte PKCS_DigestDecoration<SHA1>::decoration[] = {0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14};
template<> const unsigned int PKCS_DigestDecoration<SHA1>::length = sizeof(PKCS_DigestDecoration<SHA1>::decoration);

template<> const byte PKCS_DigestDecoration<SHA224>::decoration[] = {0x30,0x2d,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x04,0x05,0x00,0x04,0x1c};
template<> const unsigned int PKCS_DigestDecoration<SHA224>::length = sizeof(PKCS_DigestDecoration<SHA224>::decoration);

template<> const byte PKCS_DigestDecoration<SHA256>::decoration[] = {0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20};
template<> const unsigned int PKCS_DigestDecoration<SHA256>::length = sizeof(PKCS_DigestDecoration<SHA256>::decoration);

template<> const byte PKCS_DigestDecoration<SHA384>::decoration[] = {0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30};
template<> const unsigned int PKCS_DigestDecoration<SHA384>::length = sizeof(PKCS_DigestDecoration<SHA384>::decoration);

template<> const byte PKCS_DigestDecoration<SHA512>::decoration[] = {0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40};
template<> const unsigned int PKCS_DigestDecoration<SHA512>::length = sizeof(PKCS_DigestDecoration<SHA512>::decoration);

template<> const byte EMSA2HashId<SHA>::id = 0x33;
template<> const byte EMSA2HashId<SHA224>::id = 0x38;
template<> const byte EMSA2HashId<SHA256>::id = 0x34;
template<> const byte EMSA2HashId<SHA384>::id = 0x36;
template<> const byte 