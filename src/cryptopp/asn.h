#ifndef CRYPTOPP_ASN_H
#define CRYPTOPP_ASN_H

#include "filters.h"
#include "queue.h"
#include <vector>

NAMESPACE_BEGIN(CryptoPP)

// these tags and flags are not complete
enum ASNTag
{
	BOOLEAN 			= 0x01,
	INTEGER 			= 0x02,
	BIT_STRING			= 0x03,
	OCTET_STRING		= 0x04,
	TAG_NULL			= 0x05,
	OBJECT_IDENTIFIER	= 0x06,
	OBJECT_DESCRIPTOR	= 0x07,
	EXTERNAL			= 0x08,
	REAL				= 0x09,
	ENUMERATED			= 0x0a,
	UTF8_STRING			= 0x0c,
	SEQUENCE			= 0x10,
	SET 				= 0x11,
	NUMERIC_STRING		= 0x12,
	PRINTABLE_STRING 	= 0x13,
	T61_STRING			= 0x14,
	VIDEOTEXT_STRING 	= 0x15,
	IA5_STRING			= 0x16,
	UTC_TIME 			= 0x17,
	GENERALIZED_TIME 	= 0x18,
	GRAPHIC_STRING		= 0x19,
	VISIBLE_STRING		= 0x1a,
	GENERAL_STRING		= 0x1b
};

enum ASNIdFlag
{
	UNIVERSAL			= 0x00,
//	DATA				= 0x01,
//	HEADER				= 0x02,
	CONSTRUCTED 		= 0x20,
	APPLICATION 		= 0x40,
	CONTEXT_SPECIFIC	= 0x80,
	PRIVATE 			= 0xc0
};

inline void BERDecodeError() {throw BERDecodeErr();}

class CRYPTOPP_DLL UnknownOID : public BERDecodeErr
{
public:
	UnknownOID() : BERDecodeErr("BER decode error: unknown object identifier") {}
	UnknownOID(const char *err) : BERDecodeErr(err) {}
};

// unsigned int DERLengthEncode(unsigned int length, byte *output=0);
CRYPTOPP_DLL size_t CRYPTOPP_API DERLengthEncode(BufferedTransformation &out, lword length);
// returns false if indefinite length
CRYPTOPP_DLL bool CRYPTOPP_API BERLengthDecode(BufferedTransformation &in, size_t &length);

CRYPTOPP_DLL void CRYPTOPP_API DEREncodeNull(BufferedTransformation &out);
CRYPTOPP_DLL void CRYPTOPP_API 