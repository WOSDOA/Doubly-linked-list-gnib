// fipstest.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#define CRYPTOPP_DEFAULT_NO_DLL
#include "dll.h"

#ifdef CRYPTOPP_WIN32_AVAILABLE
#define _WIN32_WINNT 0x0400
#include <windows.h>

#if defined(_MSC_VER) && _MSC_VER >= 1400
#ifdef _M_IX86
#define _CRT_DEBUGGER_HOOK _crt_debugger_hook
#else
#define _CRT_DEBUGGER_HOOK __crt_debugger_hook
#endif
extern "C" {_CRTIMP void __cdecl _CRT_DEBUGGER_HOOK(int);}
#endif
#endif

#include <iostream>

NAMESPACE_BEGIN(CryptoPP)

extern PowerUpSelfTestStatus g_powerUpSelfTestStatus;
SecByteBlock g_actualMac;
unsigned long g_macFileLocation = 0;

// use a random dummy string here, to be searched/replaced later with the real MAC
static const byte s_moduleMac[CryptoPP::HMAC<CryptoPP::SHA1>::DIGESTSIZE] = CRYPTOPP_DUMMY_DLL_MAC;
CRYPTOPP_COMPILE_ASSERT(sizeof(s_moduleMac) == CryptoPP::SHA1::DIGESTSIZE);

#ifdef CRYPTOPP_WIN32_AVAILABLE
static HMODULE s_hModule = NULL;
#endif

const byte * CRYPTOPP_API GetActualMacAndLocation(unsigned int &macSize, unsigned int &fileLocation)
{
	macSize = (unsigned int)g_actualMac.size();
	fileLocation = g_macFileLocation;
	return g_actualMac;
}

void KnownAnswerTest(RandomNumberGenerator &rng, const char *output)
{
	EqualityComparisonFilter comparison;

	RandomNumberStore(rng, strlen(output)/2).TransferAllTo(comparison, "0");
	StringSource(output, true, new HexDecoder(new ChannelSwitch(comparison, "1")));

	comparison.ChannelMessageSeriesEnd("0");
	comparison.ChannelMessageSeriesEnd("1");
}

template <class CIPHER>
void X917RNG_KnownAnswerTest(
	const char *key, 
	const char *seed, 
	const char *deterministicTimeVector,
	const char *output,
	CIPHER *dummy = NULL)
{
#ifdef OS_RNG_AVAILABLE
	std::string decodedKey, decodedSeed, decodedDeterministicTimeVector;
	StringSource(key, true, new HexDecoder(new StringSink(decodedKey)));
	StringSource(seed, true, new HexDecoder(new StringSink(decodedSeed)));
	StringSource(deterministicTimeVector, true, new HexDecoder(new StringSink(decodedDeterministicTimeVector)));

	AutoSeededX917RNG<CIPHER> rng(false, false);
	rng.Reseed((const byte *)decodedKey.data(), decodedKey.size(), (const byte *)decodedSeed.data(), (const byte *)decodedDeterministicTimeVector.data());
	KnownAnswerTest(rng, output);
#else
	throw 0;
#endif
}

void KnownAnswerTest(StreamTransformation &encryption, StreamTransformation &decryption, const char *plaintext, const char *ciphertext)
{
	EqualityComparisonFilter comparison;

	StringSource(plaintext, true, new HexDecoder(new StreamTransformationFilter(encryption, new ChannelSwitch(comparison, "0"), StreamTransformationFilter::NO_PADDING)));
	StringSource(ciphertext, true, new HexDecoder(new ChannelSwitch(comparison, "1")));

	StringSource(ciphertext, true, new HexDecoder(new StreamTransformationFilter(decryption, new ChannelSwitch(comparison, "0"), StreamTransformationFilter::NO_PADDING)));
	StringSource(plaintext, true, new HexDecoder(new ChannelSwitch(comparison, "1")));

	comparison.ChannelMessageSeriesEnd("0");
	comparison.ChannelMessageSeriesEnd("1");
}

template <class CIPHER>
void SymmetricEncryptionKnownAnswerTest(
	const char *key, 
	const char *hexIV, 
	const char *plaintext, 
	const char *ecb,
	const char *cbc,
	const char *cfb,
	const char *ofb,
	const char *ctr,
	CIPHER *dummy = NULL)
{
	std::string decodedKey;
	StringSource(key, true, new HexDecoder(new StringSink(decodedKey)));

	typename CIPHER::Encryption encryption((const byte *)decodedKey.data(), decodedKey.size());
	typename CIPHER::Decryption decryption((const byte *)decodedKey.data(), decodedKey.size());

	SecByteBlock iv(encryption.BlockSize());
	StringSource(hexIV, true, new HexDecoder(new ArraySink(iv, iv.size())));

	if (ecb)
		KnownAnswerTest(ECB_Mode_ExternalCipher::Encryption(encryption).Ref(), ECB_Mode_ExternalCipher::Decryption(decryption).Ref(), plaintext, ecb);
	if (cbc)
		KnownAnswerTest(CBC_Mode_ExternalCipher::Encryption(encryption, iv).Ref(), CBC_Mode_ExternalCipher::Decryption(decryption, iv).Ref(), plaintext, cbc);
	if (cfb)
		KnownAnswerTest(CFB_Mode_ExternalCipher::Encryption(encryption, iv).Ref(), CFB_Mode_ExternalCipher::Decryption(encryption, iv).Ref(), plaintext, cfb);
	if (ofb)
		KnownAnswerTest(OFB_Mode_ExternalCipher::Encryption(encryption, iv).Ref(), OFB_Mode_ExternalCipher::Decryption(encryption, iv).Ref(), plaintext, ofb);
	if (ctr)
		KnownAnswerTest(CTR_Mode_ExternalCipher::Encryption(encryption, iv).Ref(), CTR_Mode_ExternalCipher::Decryption(encryption, iv).Ref(), plaintext, ctr);
}

void KnownAnswerTest(HashTransformation &hash, const char *message, const char *digest)
{
	EqualityComparisonFilter comparison;
	StringSource(digest, true, new HexDecoder(new ChannelSwitch(comparison, "1")));
	StringSource(message, true, new HashFilter(hash, new ChannelSwitch(comparison, "0")));

	comparison.ChannelMessageSeriesEnd("0");
	comparison.ChannelMessageSeriesEnd("1");
}

template <class HASH>
void SecureHashKnownAnswerTest(const char *message, const char *digest, HASH *dummy = NULL)
{
	HASH hash;
	KnownAnswerTest(hash, message, digest);
}

template <class MAC>
void MAC_KnownAnswerTest(const char *key, const char *message, const char *digest, MAC *dummy = NULL)
{
	std::string decodedKey;
	StringSource(key, true, new HexDecoder(new StringSink(decodedKey)));

	MAC mac((const byte *)decodedKey.data(), decodedKey.size());
	KnownAnswerTest(mac, message, digest);
}

template <class SCHEME>
void SignatureKnownAnswerTest(const char *key, const char *message, const char *signature, SCHEME *dummy = NULL)
{
	typename SCHEME::Signer signer(StringSource(key, true, new HexDecoder).Ref());
	typename SCHEME::Verifier verifier(signer);

	RandomPool rng;
	EqualityComparisonFilter comparison;

	StringSource(message, true, new SignerFilter(rng, signer, new ChannelSwitch(comparison, "0")));
	StringSource(signature, true, new HexDecoder(new ChannelSwitch(comparison, "1")));

	comparison.ChannelMessageSeriesEnd("0");
	comparison.ChannelMessageSeriesEnd("1");

	VerifierFilter verifierFilter(verifier, NULL, VerifierFilter::SIGNATURE_AT_BEGIN | VerifierFilter::THROW_EXCEPTION);
	StringSource(signature, true, new HexDecoder(new Redirector(verifierFilter, Redirector::DATA_ONLY)));
	StringSource(message, true, new Redirector(verifierFilter));
}

void EncryptionPairwiseConsistencyTest(const PK_Encryptor &encryptor, const PK_Decryptor &decryptor)
{
	try
	{
		RandomPool rng;
		const char *testMessage ="test message";
		std::string ciphertext, decrypted;

		StringSource(
			testMessage, 
			true, 
			new PK_EncryptorFilter(
				rng, 
				encryptor, 
				new StringSink(ciphertext)));

		if (ciphertext == testMessage)
			throw 0;

		StringSource(
			ciphertext, 
			true, 
			new PK_DecryptorFilter(
				rng, 
				decryptor, 
				new StringSink(decrypted)));

		if (decrypted != testMessage)
			throw 0;
	}
	catch (...)
	{
		throw SelfTestFailure(encryptor.AlgorithmName() + ": pairwise consistency test failed");
	}
}

void SignaturePairwiseConsistencyTest(const PK_Signer &signer, const PK_Verifier &verifier)
{
	try
	{
		RandomPool rng;

		StringSource(
			"test message", 
			true, 
			new SignerFilter(
				rng, 
				signer, 
				new VerifierFilter(verifier, NULL, VerifierFilter::THROW_EXCEPTION),
				true));
	}
	catch (...)
	{
		throw SelfTestFailure(signer.AlgorithmName() + ": pairwise consistency test failed");
	}
}

template <class SCHEME>
void SignaturePairwiseConsistencyTest(const char *key, SCHEME *dummy = NULL)
{
	typename SCHEME::Signer signer(StringSource(key, true, new HexDecoder).Ref());
	typename SCHEME::Verifier verifier(signer);

	SignaturePairwiseConsistencyTest(signer, verifier);
}

MessageAuthenticationCode * NewIntegrityCheckingMAC()
{
	byte key[] = {0x47, 0x1E, 0x33, 0x96, 0x65, 0xB1, 0x6A, 0xED, 0x0B, 0xF8, 0x6B, 0xFD, 0x01, 0x65, 0x05, 0xCC};
	return new HMAC<SHA1>(key, sizeof(key));
}

bool IntegrityCheckModule(const char *moduleFilename, const byte *expectedModuleMac, SecByteBlock *pActualMac, unsigned long *pMacFileLocation)
{
	std::auto_ptr<MessageAuthenticationCode> mac(NewIntegrityCheckingMAC());
	unsigned int macSize = mac->DigestSize();

	SecByteBlock tempMac;
	SecByteBlock &actualMac = pActualMac ? *pActualMac : tempMac;
	actualMac.resize(macSize);

	unsigned long tempLocation;
	unsigned long &macFileLocation = pMacFileLocation ? *pMacFileLocation : tempLocation;
	macFileLocation = 0;

	MeterFilter verifier(new HashFilter(*mac, new ArraySink(actualMac, actualMac.size())));
//	MeterFilter verifier(new FileSink("c:\\dt.tmp"));
	std::ifstream moduleStream;

#ifdef CRYPTOPP_WIN32_AVAILABLE
	HMODULE h;
	{
	char moduleFilenameBuf[MAX_PATH] = "";
	if (moduleFilename == NULL)
	{
#if (_MSC_VER >= 1400 && !defined(_STLPORT_VERSION))	// ifstream doesn't support wide filename on other compilers
		wchar_t wideModuleFilename[MAX_PATH];
		if (GetModuleFileNameW(s_hModule, wideModuleFilename, MAX_PATH) > 0)
		{
			moduleStream.open(wideModuleFilename, std::ios::in | std::ios::binary);
			h = GetModuleHandleW(wideModuleFilename);
		}
		else
#endif
		{
			GetModuleFileNameA(s_hModule, moduleFilenameBuf, MAX_PATH);
			moduleFilename = moduleFilenameBuf;
		}
	}
#endif
	if (moduleFilename != NULL)
	{
			moduleStream.open(moduleFilename, std::ios::in | std::ios::binary);
#ifdef CRYPTOPP_WIN32_AVAILABLE
			h = GetModuleHandleA(moduleFilename);
			moduleFilename = NULL;
	}
#endif
	}

	if (!moduleStream)
	{
#ifdef CRYPTOPP_WIN32_AVAILABLE
		OutputDebugString("Crypto++ DLL integrity check failed. Cannot open file for reading.");
#endif
		return false;
	}
	FileStore file(moduleStream);

#ifdef CRYPTOPP_WIN32_AVAILABLE
	// try to hash from memory first
	const byte *memBase = (const byte *)h;
	const IMAGE_DOS_HEADER *ph = (IMAGE_DOS_HEADER *)memBase;
	const IMAGE_NT_HEADERS *phnt = (IMAGE_NT_HEADERS *)(memBase + ph->e_lfanew);
	const IMAGE_SECTION_HEADER *phs = IMAGE_FIRST_SECTION(phnt);
	DWORD nSections = phnt->FileHeader.NumberOfSections;
	size_t currentFilePos = 0;

	size_t checksumPos = (byte *)&phnt->OptionalHeader.CheckSum - memBase;
	size_t checksumSize = sizeof(phnt->OptionalHeader.CheckSum);
	size_t certificateTableDirectoryPos = (byte *)&phnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] - memBase;
	size_t certificateTableDirectorySize = sizeof(phnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]);
	size_t certificateTablePos = phnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
	size_t certificateTableSize = phnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;

	verifier.AddRangeToSkip(0, checksumPos, checksumSize);
	verifier.AddRangeToSkip(0, certificateTableDirectoryPos, certificateTableDirectorySize);
	verifier.AddRangeToSkip(0, certificateTablePos, certificateTableSize);

	while (nSections--)
	{
		switch (phs->Characteristics)
		{
		default:
			break;
		case IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ:
		case IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ:
			unsigned int sectionSize = STDMIN(phs->SizeOfRawData, phs->Misc.VirtualSize);
			const byte *sectionMemStart = memBase + phs->VirtualAddress;
			unsigned int sectionFileStart = phs->PointerToRawData;
			size_t subSectionStart = 0, nextSubSectionStart;

			do
			{
				const byte *subSectionMemStart = sectionMemStart + subSectionStart;
				size_t subSectionFileStart = sectionFileStart + subSectionStart;
				size_t subSectionSize = sectionSize - subSectionStart;
				nextSubSectionStart = 0;

				unsigned int entriesToReadFromDisk[] = {IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_IAT};
				for (unsigned int i=0; i<sizeof(entriesToReadFromDisk)/sizeof(entriesToReadFromDisk[0]); i++)
				{
					const IMAGE_DATA_DIRECTORY &entry = phnt->OptionalHeader.DataDirectory[entriesToReadFromDisk[i]];
					const byte *entryMemStart = memBase + entry.VirtualAddress;
					if (subSectionMemStart <= entryMemStart && entryMemStart < subSectionMemStart + subSectionSize)
					{
						subSectionSize = entryMemStart - subSectionMemStart;
						nextSubSectionStart = entryMemStart - sectionMemStart + entry.Size;
					}
				}

#if defined(_MSC_VER) && _MSC_VER >= 1400
				// first byte of _CRT_DEBUGGER_HOOK gets modified in memory by the debugger invisibly, so read it from file
				if (IsDebuggerPresent())
				{
					if (subSectionMemStart <= (byte *)&_CRT_DEBU