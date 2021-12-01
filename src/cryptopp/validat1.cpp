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

	apbt NewEncryption(const byte *key) const
		{return apbt(new E(key, m_keylen));}
	apbt NewDecryption(const byte *key) const
		{return apbt(new D(key, m_keylen));}

	unsigned int m_keylen;
};

template <class E, class D> class VariableRoundsCipherFactory : public CipherFactory
{
public:
	VariableRoundsCipherFactory(unsigned int keylen=0, unsigned int rounds=0)
		: m_keylen(keylen ? keylen : E::DEFAULT_KEYLENGTH), m_rounds(rounds ? rounds : E::DEFAULT_ROUNDS) {}
	unsigned int BlockSize() const {return E::BLOCKSIZE;}
	unsigned int KeyLength() const {return m_keylen;}

	apbt NewEncryption(const byte *key) const
		{return apbt(new E(key, m_keylen, m_rounds));}
	apbt NewDecryption(const byte *key) const
		{return apbt(new D(key, m_keylen, m_rounds));}

	unsigned int m_keylen, m_rounds;
};

bool BlockTransformationTest(const CipherFactory &cg, BufferedTransformation &valdata, unsigned int tuples = 0xffff)
{
	HexEncoder output(new FileSink(cout));
	SecByteBlock plain(cg.BlockSize()), cipher(cg.BlockSize()), out(cg.BlockSize()), outplain(cg.BlockSize());
	SecByteBlock key(cg.KeyLength());
	bool pass=true, fail;

	while (valdata.MaxRetrievable() && tuples--)
	{
		valdata.Get(key, cg.KeyLength());
		valdata.Get(plain, cg.BlockSize());
		valdata.Get(cipher, cg.BlockSize());

		apbt transE = cg.NewEncryption(key);
		transE->ProcessBlock(plain, out);
		fail = memcmp(out, cipher, cg.BlockSize()) != 0;

		apbt transD = cg.NewDecryption(key);
		transD->ProcessBlock(out, outplain);
		fail=fail || memcmp(outplain, plain, cg.BlockSize());

		pass = pass && !fail;

		cout << (fail ? "FAILED   " : "passed   ");
		output.Put(key, cg.KeyLength());
		cout << "   ";
		output.Put(outplain, cg.BlockSize());
		cout << "   ";
		output.Put(out, cg.BlockSize());
		cout << endl;
	}
	return pass;
}

class FilterTester : public Unflushable<Sink>
{
public:
	FilterTester(const byte *validOutput, size_t outputLen)
		: validOutput(validOutput), outputLen(outputLen), counter(0), fail(false) {}
	void PutByte(byte inByte)
	{
		if (counter >= outputLen || validOutput[counter] != inByte)
		{
			std::cerr << "incorrect output " << counter << ", " << (word16)validOutput[counter] << ", " << (word16)inByte << "\n";
			fail = true;
			assert(false);
		}
		counter++;
	}
	size_t Put2(const byte *inString, size_t length, int messageEnd, bool blocking)
	{
		while (length--)
			FilterTester::PutByte(*inString++);

		if (messageEnd)
			if (counter != outputLen)
			{
				fail = true;
				assert(false);
			}

		return 0;
	}
	bool GetResult()
	{
		return !fail;
	}

	const byte *validOutput;
	size_t outputLen, counter;
	bool fail;
};

bool TestFilter(BufferedTransformation &bt, const byte *in, size_t inLen, const byte *out, size_t outLen)
{
	FilterTester *ft;
	bt.Attach(ft = new FilterTester(out, outLen));

	while (inLen)
	{
		size_t randomLen = GlobalRNG().GenerateWord32(0, (word32)inLen);
		bt.Put(in, randomLen);
		in += randomLen;
		inLen -= randomLen;
	}
	bt.MessageEnd();
	return ft->GetResult();
}

bool ValidateDES()
{
	cout << "\nDES validation suite running...\n\n";

	FileSource valdata("TestData/descert.dat", true, new HexDecoder);
	bool pass = BlockTransformationTest(FixedRoundsCipherFactory<DESEncryption, DESDecryption>(), valdata);

	cout << "\nTesting EDE2, EDE3, and XEX3 variants...\n\n";

	FileSource valdata1("TestData/3desval.dat", true, new HexDecoder);
	pass = BlockTransformationTest(FixedRoundsCipherFactory<DES_EDE2_Encryption, DES_EDE2_Decryption>(), valdata1, 1) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<DES_EDE3_Encryption, DES_EDE3_Decryption>(), valdata1, 1) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<DES_XEX3_Encryption, DES_XEX3_Decryption>(), valdata1, 1) && pass;

	return pass;
}

bool TestModeIV(SymmetricCipher &e, SymmetricCipher &d)
{
	SecByteBlock lastIV, iv(e.IVSize());
	StreamTransformationFilter filter(e, new StreamTransformationFilter(d));
	byte plaintext[20480];

	for (unsigned int i=1; i<sizeof(plaintext); i*=2)
	{
		e.GetNextIV(GlobalRNG(), iv);
		if (iv == lastIV)
			return false;
		else
			lastIV = iv;

		e.Resynchronize(iv);
		d.Resynchronize(iv);

		unsigned int length = STDMAX(GlobalRNG().GenerateWord32(0, i), (word32)e.MinLastBlockSize());
		GlobalRNG().GenerateBlock(plaintext, length);

		if (!TestFilter(filter, plaintext, length, plaintext, length))
			return false;
	}

	return true;
}

bool ValidateCipherModes()
{
	cout << "\nTesting DES modes...\n\n";
	const byte key[] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
	const byte iv[] = {0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef};
	const byte plain[] = {	// "Now is the time for all " without tailing 0
		0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
		0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
		0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20};
	DESEncryption desE(key);
	DESDecryption desD(key);
	bool pass=true, fail;

	{
		// from FIPS 81
		const byte encrypted[] = {
			0x3f, 0xa4, 0x0e, 0x8a, 0x98, 0x4d, 0x48, 0x15,
			0x6a, 0x27, 0x17, 0x87, 0xab, 0x88, 0x83, 0xf9,
			0x89, 0x3d, 0x51, 0xec, 0x4b, 0x56, 0x3b, 0x53};

		ECB_Mode_ExternalCipher::Encryption modeE(desE);
		fail = !TestFilter(StreamTransformationFilter(modeE, NULL, StreamTransformationFilter::NO_PADDING).Ref(),
			plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "ECB encryption" << endl;
		
		ECB_Mode_ExternalCipher::Decryption modeD(desD);
		fail = !TestFilter(StreamTransformationFilter(modeD, NULL, StreamTransformationFilter::NO_PADDING).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "ECB decryption" << endl;
	}
	{
		// from FIPS 81
		const byte encrypted[] = {
			0xE5, 0xC7, 0xCD, 0xDE, 0x87, 0x2B, 0xF2, 0x7C, 
			0x43, 0xE9, 0x34, 0x00, 0x8C, 0x38, 0x9C, 0x0F, 
			0x68, 0x37, 0x88, 0x49, 0x9A, 0x7C, 0x05, 0xF6};

		CBC_Mode_ExternalCipher::Encryption modeE(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeE, NULL, StreamTransformationFilter::NO_PADDING).Ref(),
			plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC encryption with no padding" << endl;
		
		CBC_Mode_ExternalCipher::Decryption modeD(desD, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD, NULL, StreamTransformationFilter::NO_PADDING).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC decryption with no padding" << endl;

		fail = !TestModeIV(modeE, modeD);
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC mode IV generation" << endl;
	}
	{
		// generated with Crypto++, matches FIPS 81
		// but has extra 8 bytes as result of padding
		const byte encrypted[] = {
			0xE5, 0xC7, 0xCD, 0xDE, 0x87, 0x2B, 0xF2, 0x7C, 
			0x43, 0xE9, 0x34, 0x00, 0x8C, 0x38, 0x9C, 0x0F, 
			0x68, 0x37, 0x88, 0x49, 0x9A, 0x7C, 0x05, 0xF6, 
			0x62, 0xC1, 0x6A, 0x27, 0xE4, 0xFC, 0xF2, 0x77};

		CBC_Mode_ExternalCipher::Encryption modeE(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeE).Ref(),
			plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC encryption with PKCS #7 padding" << endl;
		
		CBC_Mode_ExternalCipher::Decryption modeD(desD, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC decryption with PKCS #7 padding" << endl;
	}
	{
		// generated with Crypto++ 5.2, matches FIPS 81
		// but has extra 8 bytes as result of padding
		const byte encrypted[] = {
			0xE5, 0xC7, 0xCD, 0xDE, 0x87, 0x2B, 0xF2, 0x7C, 
			0x43, 0xE9, 0x34, 0x00, 0x8C, 0x38, 0x9C, 0x0F, 
			0x68, 0x37, 0x88, 0x49, 0x9A, 0x7C, 0x05, 0xF6, 
			0xcf, 0xb7, 0xc7, 0x64, 0x0e, 0x7c, 0xd9, 0xa7};

		CBC_Mode_ExternalCipher::Encryption modeE(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeE, NULL, StreamTransformationFilter::ONE_AND_ZEROS_PADDING).Ref(),
			plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC encryption with one-and-zeros padding" << endl;

		CBC_Mode_ExternalCipher::Decryption modeD(desD, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD, NULL, StreamTransformationFilter::ONE_AND_ZEROS_PADDING).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC decryption with one-and-zeros padding" << endl;
	}
	{
		const byte plain[] = {'a', 0, 0, 0, 0, 0, 0, 0};
		// generated with Crypto++
		const byte encrypted[] = {
			0x9B, 0x47, 0x57, 0x59, 0xD6, 0x9C, 0xF6, 0xD0};

		CBC_Mode_ExternalCipher::Encryption modeE(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeE, NULL, StreamTransformationFilter::ZEROS_PADDING).Ref(),
			plain, 1, encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC encryption with zeros padding" << endl;

		CBC_Mode_ExternalCipher::Decryption modeD(desD, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD, NULL, StreamTransformationFilter::ZEROS_PADDING).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC decryption with zeros padding" << endl;
	}
	{
		// generated with Crypto++, matches FIPS 81
		// but with last two blocks swapped as result of CTS
		const byte encrypted[] = {
			0xE5, 0xC7, 0xCD, 0xDE, 0x87, 0x2B, 0xF2, 0x7C, 
			0x68, 0x37, 0x88, 0x49, 0x9A, 0x7C, 0x05, 0xF6, 
			0x43, 0xE9, 0x34, 0x00, 0x8C, 0x38, 0x9C, 0x0F};

		CBC_CTS_Mode_ExternalCipher::Encryption modeE(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeE).Ref(),
			plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC encryption with ciphertext stealing (CTS)" << endl;
		
		CBC_CTS_Mode_ExternalCipher::Decryption modeD(desD, iv);
		fail = !TestFilter(StreamTransformationFilter(modeD).Ref(),
			encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC decryption with ciphertext stealing (CTS)" << endl;

		fail = !TestModeIV(modeE, modeD);
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC CTS IV generation" << endl;
	}
	{
		// generated with Crypto++
		const byte decryptionIV[] = {0x4D, 0xD0, 0xAC, 0x8F, 0x47, 0xCF, 0x79, 0xCE};
		const byte encrypted[] = {0x12, 0x34, 0x56};

		byte stolenIV[8];

		CBC_CTS_Mode_ExternalCipher::Encryption modeE(desE, iv);
		modeE.SetStolenIV(stolenIV);
		fail = !TestFilter(StreamTransformationFilter(modeE).Ref(),
			plain, 3, encrypted, sizeof(encrypted));
		fail = memcmp(stolenIV, decryptionIV, 8) != 0 || fail;
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC encryption with ciphertext and IV stealing" << endl;
		
		CBC_CTS_Mode_ExternalCipher::Decryption modeD(desD, stolenIV);
		fail = !TestFilter(StreamTransformationFilter(modeD).Ref(),
			encrypted, sizeof(encrypted), plain, 3);
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC decryption with ciphertext and IV stealing" << endl;
	}
	{
		const byte encrypted[] = {	// from FIPS 81
			0xF3,0x09,0x62,0x49,0xC7,0xF4,0x6E,0x51,
			0xA6,0x9E,0x83,0x9B,0x1A,0x92,0xF7,0x84,
			0x03,0x46,0x71,0x33,0x89,0x8E,0xA6,0x22};

		CFB_Mode_ExternalCipher::Encryption modeE(desE, iv);
		fail = !TestFilter(StreamTransformationFilter(modeE).Ref(),
			plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass &&