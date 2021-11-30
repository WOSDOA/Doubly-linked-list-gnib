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
