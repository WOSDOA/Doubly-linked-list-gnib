#ifndef CRYPTOPP_GF2N_H
#define CRYPTOPP_GF2N_H

/*! \file */

#include "cryptlib.h"
#include "secblock.h"
#include "misc.h"
#include "algebra.h"

#include <iosfwd>

NAMESPACE_BEGIN(CryptoPP)

//! Polynomial with Coefficients in GF(2)
/*!	\nosubgrouping */
class CRYPTOPP_DLL PolynomialMod2
{
public:
	//! \name ENUMS, EXCEPTIONS, and TYPEDEFS
	//@{
		//! divide by zero exception
		class DivideByZero : public Exception
		{
		public:
			DivideByZero() : Exception(OTHER_ERROR, "PolynomialMod2: division by zero") {}
		};

		typedef unsigned int RandomizationParameter;
	//@}

	//! \name CREATORS
	//@{
		//! creates the zero polynomial
		PolynomialMod2();
		//! copy constructor
		PolynomialMod2(const PolynomialMod2& t);

		//! convert from word
		/*! value should be encoded with the least significant bit as coefficient to x^0
			and most significant bit as coefficient to x^(WORD_BITS-1)
			bitLength denotes how much memory to allocate initially
		*/
		PolynomialMod2(word value, size_t bitLength=WORD_BITS);

		//! convert from big-endian byte array
		PolynomialMod2(const byte *encodedPoly, size_t byteCount)
			{Decode(encodedPoly, byteCount);}

		//! convert from big-endian form stored in a BufferedTransformation
		PolynomialMod2(BufferedTransformation &encodedPoly, size_t byteCount)
			{Decode(encodedPoly, byteCount);}

		//! create a random polynomial uniformly distributed over all polynomials with degree less than bitcount
		PolynomialMod2(RandomNumberGenerator &rng, size_t bitcount)
			{Randomize(rng, bitcount);}

		//! return x^i
		static PolynomialMod2 CRYPTOPP_API Monomial(size_t i);
		//! return x^t0 + x^t1 + x^t2
		static PolynomialMod2 CRYPTOPP_API Trinomial(size_t t0, size_t t1, size_t t2);
		//! return x^t0 + x^t1 + x^t2 + x^t3 + x^t4
		static PolynomialMod2 CRYPTOPP_API Pentanomial(size_t t0, size_t t1, size_t t2, size_t t3, size_t t4);
		//! return x^(n-1) + ... + x + 1
		static PolynomialMod2 CRYPTOPP_API AllOnes(size_t n);

		//!
		static const PolynomialMod2 & CRYPTOPP_API Zero();
		//!
		static const PolynomialMod2 & CRYPTOPP_API One();
	//@}

	//! \name ENCODE/DECODE
	//@{
		//! minimum number of bytes to encode this polynomial
		/*! MinEncodedSize of 0 is 1 */
		unsigned int MinEncodedSize() const {return STDMAX(1U, ByteCount());}

		//! encode in big-endian format
		/*! if outputLen < MinEncodedSize, the most significant bytes will be dropped
			if outputLen > MinEncodedSize, the most significant bytes will be padded
		*/
		void Encode(byte *output, size_t outputLen) const;
		//!
		void Encode(BufferedTransformation &bt, size_t outputLen) const;

		//!
		void Decode(const byte *input, size_t inputLen);
		//! 
		//* Precondition: bt.MaxRetrievable() >= inputLen
		void Decode(BufferedTransformation &bt, size_t inputLen);

		//! encode value as big-endian octet string
		void DEREncodeAsOctetString(BufferedTransformation &bt, size_t length) const;
		//! decode value as big-endian octet string
		void BERDecodeAsOctetString(BufferedTransformation &bt, size_t length);
	//@}

	//! \name ACCESSORS
	//@{
		//! number of significant bits = Degree() + 1
		unsigned int BitCount() const;
		//! number of significant bytes = ceiling(BitCount()/8)
		unsigned int ByteCount() const;
		//! number of significant words = ceiling(ByteCount()/sizeof(word))
		unsigned int WordCount() const;

		//! return the n-th bit, n=0 being the least significant bit
		bool GetBit(size_t n) const {return GetCoefficient(n)!=0;}
		//! return the n-th byte
		byte GetByte(size_t n) const;

		//! the zero polynomial will return a degree of -1
		signed int Degree() const {return 