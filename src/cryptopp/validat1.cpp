// validat1.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "files.h"
#include "hex.h"
#include "base32.h"
#include "base64.h"
#include "modes.h"
#include "cbcmac.h"
#include "dmac.h"
#include "idea.h"
#include "des.h"
#include "rc2.h"
#include "arc4.h"
#include "rc5.h"
#include "blowfish.h"
#include "3way.h"
#include "safer.h"
#include "gost.h"
#include "shark.h"
#include "cast.h"
#include "square.h"
#include "seal.h"
#include "rc6.h"
#include "mars.h"
#include "rijndael.h"
#include "twofish.h"
#include "serpent.h"
#include "skipjack.h"
#include "shacal2.h"
#include "camellia.h"
#include "osrng.h"
#include "zdeflate.h"
#include "cpu.h"

#include <time.h>
#include <memory>
#include <iostream>
#include <iomanip>

#include "validate.h"

USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)

bool ValidateAll(bool thorough)
{
	bool pass=TestSettings();
	pass=TestOS_RNG() && pass;

	pass=ValidateCRC32() && pass;
	pass=ValidateAdler32() && pass;
	pass=ValidateMD2() && pass;
	pass=ValidateMD5() && pass;
	pass=ValidateSHA() && pass;
	pass=RunTestDataFile("TestVectors/sha3.txt") && pass;
	pass=ValidateTiger() && pass;
	pass=ValidateRIPEMD() && pass;
	pass=ValidatePanama() && pass;
	pass=ValidateWhirlpool() && pass;

	pass=ValidateHMAC() && pass;
	pass=ValidateTTMAC() && pass;

	pass=ValidatePBKDF() && pass;

	pass=ValidateDES() && pass;
	pass=ValidateCipherModes() && pass;
	pass=ValidateIDEA() && pass;
	pass=ValidateSAFER() && pass;
	pass=ValidateRC2() && pass;
	pass=ValidateARC4() && pass;
	pass=ValidateRC5() && pass;
	pass=ValidateBlowfish() && pass;
	pass=ValidateThreeWay() && pass;
	pass=ValidateGOST() && pass;
	pass=ValidateSHARK() && pass;
	pass=ValidateCAST() && pass;
	pass=ValidateSquare() && pass;
	pass=ValidateSKIPJACK() && pass;
	pass=ValidateSEAL() && pass;
	pass=ValidateRC6() && pass;
	pass=ValidateMARS() && pass;
	pass=ValidateRijndael() && pass;
	pass=ValidateTwofish() && pass;
	pass=ValidateSerpent() && pass;
	pass=ValidateSHACAL2() && pass;
	pass=ValidateCamellia() && pass;
	pass=ValidateSalsa() && pass;
	pass=ValidateSosemanuk() && pass;
	pass=ValidateVMAC() && pass;
	pass=ValidateCCM() && pass;
	pass=ValidateGCM() && pass;
	pass=ValidateCMAC() && pass;
	pass=RunTestDataFile("TestVectors/eax.txt") && pass;
	pass=RunTestDataFile("TestVectors/seed.txt") && pass;

	pass=ValidateBBS() && pass;
	pass=ValidateDH() && pass;
	pass=ValidateMQV() && pass;
	pass=ValidateRSA() && pass;
	pass=ValidateElGamal() && pass;
	pass=ValidateDLIES() && pass;
	pass=ValidateNR() && pass;
	pass=ValidateDSA(thorough) && pass;
	pass=ValidateLUC() && pass;
	pass=ValidateLUC_DH() && pass;
	pass=ValidateLUC_DL() && pass;
	pass=ValidateXTR_DH() && pass;
	pass=ValidateRabin() && pass;
	pass=ValidateRW() && pass;
//	pass=ValidateBlumGoldwasser() && pass;
	pass=ValidateECP() && pass;
	pass=ValidateEC2N() && pass;
	pass=ValidateECDSA() && pass;
	pass=ValidateESIGN() && pass;

	if (pass)
		cout << "\nAll tests passed!\n";
	else
		cout << "\nOops!  Not all tests passed.\n";

	return pass;
}

bool TestSettings()
{
	bool pass = true;

	cout << "\nTesting Settings...\n\n";

	word32 w;
	memcpy_s(&w, sizeof(w), "\x01\x02\x03\x04", 4);

	if (w == 0x04030201L)
	{
#ifdef IS_LITTLE_ENDIAN
		cout << "passed:  ";
#else
		cout << "FAILED:  ";
		pass = false;
#endif
		cout << "Your machine is little endian.\n";
	}
	else if (w == 0x01020304L)
	{
#ifndef IS_LITTLE_ENDIAN
		cout << "passed:  ";
#else
		cout << "FAILED:  ";
		pass = false;
#endif
		cout << "Your machine is big endian.\n";
	}
	else
	{
		cout << "FAILED:  Your machine is neither big endian nor little endian.\n";
		pass = false;
	}

#ifdef CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS
	byte testvals[10] = {1,2,2,3,3,3,3,2,2,1};
	if (*(word32 *)(testvals+3) == 0x03030303 && *(word64 *)(testvals+1) == W64LIT(0x0202030303030202))
		cout << "passed:  Your machine allows unaligned data access.\n";
	else
	{
		cout << "FAILED:  Unaligned data access gave incorrect results.\n";
		pass = false;
	}
#else
	cout << "passed:  CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS is not defined. Will restrict to aligned data access.\n";
#endif

	if (sizeof(byte) == 1)
		cout << "passed:  ";
	else
	{
		cout << "FAILED:  ";
		pass = false;
	}
	cout << "sizeof(byte) == " << sizeof(byte) << endl;

	if (sizeof(word16) == 2)
		cout << "passed:  ";
	else
	{
		cout << "FAILED:  ";
		pass = false;
	}
	cout << "sizeof(word16) == " << sizeof(word16) << endl;

	if (sizeof(word32) == 4)
		cout << "passed:  ";
	else
	{
		cout << "FAILED:  ";
		pass = false;
	}
	cout << "sizeof(word32) == " << sizeof(word32) << endl;

	if (sizeof(word64) == 8)
		cout << "passed:  ";
	else
	{
		cout << "FAILED:  ";
		pass = false;
	}
	cout << "sizeof(word64) == " << sizeof(word64) << endl;

#ifdef CRYPTOPP_WORD128_AVAILABLE
	if (sizeof(word128) == 16)
		cout << "passed:  ";
	else
	{
		cout << "FAILED:  ";
		pass = false;
	}
	cout << "sizeof(word128) == " << sizeof(word128) << endl;
#endif

	if (sizeof(word) == 2*sizeof(hword)
#ifdef CRYPTOPP_NATIVE_DWORD_AVAILABLE
		&& sizeof(dword) == 2*sizeof(word)
#endif
		)
		cout << "passed:  ";
	else
	{
		cout << "FAILED:  ";
		pass = false;
	}
	cout << "sizeof(hword) == " << sizeof(hword) << ", sizeof(word) == " << sizeof(word);
#ifdef CRYPTOPP_NATIVE_DWORD_AVAILABLE
	cout << ", sizeof(dword) == " << sizeof(dword);
#endif
	cout << endl;

#ifdef CRYPTOPP_CPUID_AVAILABLE
	bool hasMMX = HasMMX();
	bool hasISSE = HasISSE();
	bool hasSSE2 = HasSSE2();
	bool hasSSSE3 = HasSSSE3();
	bool isP4 = IsP4();
	int cacheLineSize = GetCacheLineSize();

	if ((isP4 && (!hasMMX || !hasSSE2)) || (hasSSE2 && !hasMMX) || (cacheLineSize < 16 || cacheLineSize > 256 || !IsPowerOf2(cacheLineSize)))
	{
		cout << "FAILED:  ";
		pass = false;
	}
	else
		cout << "passed:  ";

	cout << "hasMMX == " << hasMMX << ", hasISSE == " << hasISSE << ", hasSSE2 == " << hasSSE2 << ", hasSSSE3 == " << hasSSSE3 << ", hasAESNI == " << HasAESNI() << ", hasCLMUL == " << HasCLMUL() << ", isP4 == " << isP4 << ", cacheLineSize == " << cacheLineSize;
	cout << ", AESNI_INTRINSICS == " << CRYPTOPP_BOOL_AESNI_INTRINSICS_AVAILABLE << endl;
#endif

	if (!pass)
	{
		cout << "Some critical setting in config.h is in error.  Please fix it and recompile." << endl;
		abort();
	}
	return pass;
}

bool TestOS_RNG()
{
	bool pass = true;

	member_ptr<RandomNumberGenerator> rng;
#ifdef BLOCKING_RNG_AVAILABLE
	try {rng.reset(new BlockingRng);}
	catch (OS_RNG_Err &) {}
#endif

	if (rng.get())
	{
		cout << "\nTesting operating system provided blocking random number generator...\n\n";

		ArraySink *sink;
		RandomNumberSource test(*rng, UINT_MAX, false, new Deflator(sink=new ArraySink(NULL,0)));
		unsigned long total=0, length=0;
		time_t t = time(NULL), t1 = 0;

		// check that it doesn't take too long to generate a reasonable amount of randomness
		while (total < 16 && (t1 < 10 || total*8 > (unsigned long)t1))
		{
			test.Pump(1);
			total += 1;
			t1 = time(NULL) - t;
		}

		if (total < 16)
		{
			cout << "FAILED:";
			pass = false;
		}
		else
			cout << "passed:";
		cout << "  it took " << long(t1) << " seconds to generate " << total << " bytes" << endl;

#if 0	// disable this part. it's causing an unpredictable pause during the validation testing
		if (t1 < 2)
		{
			// that was fast, are we really blocking?
			// first exhaust the extropy reserve
			t = time(NULL);
			while (time(NULL) - t < 2)
			{
				test.Pump(1);
				total += 1;
			}

			// if it generates too many bytes in a certain amount of time,
			// something's probably wrong
			t = time(NULL);
			while (time(NULL) - t < 2)
			{
				test.Pump(1);
				total += 1;
				length += 1;
			}
			if (length > 1024)
			{
				cout << "FAILED:";
				pass = false;
			}
			else
				cout << "passed:";
			cout << "  it generated " << length << " bytes in " << long(time(NULL) - t) << " seconds" << endl;
		}
#endif

		test.AttachedTransformation()->MessageEnd();

		if (sink->TotalPutLength() < total)
		{
			cout << "FAILED:";
			pass = false;
		}
		else
			cout << "passed:";
		cout << "  " << total << " generated bytes compressed to " << (size_t)sink->TotalPutLength() << " bytes by DEFLATE" << endl;
	}
	else
		cout << "\nNo operating system provided blocking random number generator, skipping test." << endl;

	rng.reset(NULL);
#ifdef NONBLOCKING_RNG_AVAILABLE
	try {rng.reset(new NonblockingRng);}
	catch (OS_RNG_Err &) {}
#endif

	if (rng.get())
	{
		cout << "\nTesting operating system provided nonblocking random number generator...\n\n";

		ArraySink *sink;
		RandomNumberSource test(*rng, 100000, true, new Deflator(sink=new ArraySink(NULL, 0)));
		
		if (sink->TotalPutLength() < 100000)
		{
			cout << "FAILED:";
			pass = false;
		}
		else
			cout << "passed:";
		cout << "  100000 generated bytes compressed to " << (size_t)sink->TotalPutLength() << " bytes by DEFLATE" << endl;
	}
	else
		cout << "\nNo operating system provided nonblocking random number generator, skipping test." << endl;

	return pass;
}

// VC50 workaround
typedef auto_ptr<BlockTransformation> apbt;

class CipherFactory
{
public:
	virtual unsigned int BlockSize() const =0;
	virtual unsigned int KeyLength() const =0;

	virtual apbt NewEncryption(const byte *key) const =0;
	virtual apbt NewDecryption(const byte *key) const =0;
};

template <class E, class D> class FixedRoundsCipherFactory : public CipherFactory
{
public:
	FixedRoundsCipherFactory(unsigned int keylen=0) : m_keylen(keylen?keylen:E::DEFAULT_KEYLENGTH) {}
	unsigned int BlockSize() const {return E::BLOCKSIZE;}
	unsigned int KeyLength() const {return m_keylen;}

	apbt NewEncryption(