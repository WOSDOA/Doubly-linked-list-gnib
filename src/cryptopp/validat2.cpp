// validat2.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "blumshub.h"
#include "rsa.h"
#include "md2.h"
#include "elgamal.h"
#include "nr.h"
#include "dsa.h"
#include "dh.h"
#include "mqv.h"
#include "luc.h"
#include "xtrcrypt.h"
#include "rabin.h"
#include "rw.h"
#include "eccrypto.h"
#include "ecp.h"
#include "ec2n.h"
#include "asn.h"
#include "rng.h"
#include "files.h"
#include "hex.h"
#include "oids.h"
#include "esign.h"
#include "osrng.h"

#include <iostream>
#include <iomanip>

#include "validate.h"

USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)

class FixedRNG : public RandomNumberGenerator
{
public:
	FixedRNG(BufferedTransformation &source) : m_source(source) {}

	void GenerateBlock(byte *output, size_t size)
	{
		m_source.Get(output, size);
	}

private:
	BufferedTransformation &m_source;
};

bool ValidateBBS()
{
	cout << "\nBlumBlumShub validation suite running...\n\n";

	Integer p("212004934506826557583707108431463840565872545889679278744389317666981496005411448865750399674653351");
	Integer q("100677295735404212434355574418077394581488455772477016953458064183204108039226017738610663984508231");
	Integer seed("63239752671357255800299643604761065219897634268887145610573595874544114193025997412441121667211431");
	BlumBlumShub bbs(p, q, seed);
	bool pass = true, fail;
	int j;

	const byte output1[] = {
		0x49,0xEA,0x2C,0xFD,0xB0,0x10,0x64,0xA0,0xBB,0xB9,
		0x2A,0xF1,0x01,0xDA,0xC1,0x8A,0x94,0xF7,0xB7,0xCE};
	const byte output2[] = {
		0x74,0x45,0x48,0xAE,0xAC,0xB7,0x0E,0xDF,0xAF,0xD7,
		0xD5,0x0E,0x8E,0x29,0x83,0x75,0x6B,0x27,0x46,0xA1};

	byte buf[20];

	bbs.GenerateBlock(buf, 20);
	fail = memcmp(output1, buf, 20) != 0;
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	for (j=0;j<20;j++)
		cout << setw(2) << setfill('0') << hex << (int)buf[j];
	cout << endl;

	bbs.Seek(10);
	bbs.GenerateBlock(buf, 10);
	fail = memcmp(output1+10, buf, 10) != 0;
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	for (j=0;j<10;j++)
		cout << setw(2) << setfill('0') << hex << (int)buf[j];
	cout << endl;

	bbs.Seek(1234567);
	bbs.GenerateBlock(buf, 20);
	fail = memcmp(output2, buf, 20) != 0;
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	for (j=0;j<20;j++)
		cout << setw(2) << setfill('0') << hex << (int)buf[j];
	cout << endl;

	return pass;
}

bool SignatureValidate(PK_Signer &priv, PK_Verifier &pub, bool thorough = false)
{
	bool pass = true, fail;

	fail = !pub.GetMaterial().Validate(GlobalRNG(), thorough ? 3 : 2) || !priv.GetMaterial().Validate(GlobalRNG(), thorough ? 3 : 2);
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "signature key validation\n";

	const byte *message = (byte *)"test message";
	const int messageLen = 12;

	SecByteBlock signature(priv.MaxSignatureLength());
	size_t signatureLength = priv.SignMessage(GlobalRNG(), message, messageLen, signature);
	fail = !pub.VerifyMessage(message, messageLen, signature, signatureLength);
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "signature and verification\n";

	++signature[0];
	fail = pub.VerifyMessage(message, messageLen, signature, signatureLength);
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "checking invalid signature" << endl;

	if (priv.MaxRecoverableLength() > 0)
	{
		signatureLength = priv.SignMessageWithRecovery(GlobalRNG(), message, messageLen, NULL, 0, signature);
		SecByteBlock recovered(priv.MaxRecoverableLengthFromSignatureLength(signatureLength));
		DecodingResult result = pub.RecoverMessage(recovered, NULL, 0, signature, signatureLength);
		fail = !(result.isValidCoding && result.messageLength == messageLen && memcmp(recovered, message, messageLen) == 0);
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "signature and verification with recovery" << endl;

		++signature[0];
		result = pub.RecoverMessage(recovered, NULL, 0, signature, signatureLength);
		fail = result.isValidCoding;
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "recovery with invalid signature" << endl;
	}

	return pass;
}

bool CryptoSystemValidate(PK_Decryptor &priv, PK_Encryptor &pub, bool thorough = false)
{
	bool pass = true, fail;

	fail = !pub.GetMaterial().Validate(GlobalRNG(), thorough ? 3 : 2) || !priv.GetMaterial().Validate(GlobalRNG(), thorough ? 3 : 2);
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "cryptosystem key validation\n";

	const byte *message = (byte *)"test message";
	const int messageLen = 12;
	SecByteBlock ciphertext(priv.CiphertextLength(messageLen));
	SecByteBlock plaintext(priv.MaxPlaintextLength(ciphertext.size()));

	pub.Encrypt(GlobalRNG(), message, messageLen, ciphertext);
	fail = priv.Decrypt(GlobalRNG(), ciphertext, priv.CiphertextLength(messageLen), plaintext) != DecodingResult(messageLen);
	fail = fail || memcmp(message, plaintext, messageLen);
	pass = pass && !fail;

	cout << (fail ? "FAILED    " : "passed    ");
	cout << "encryption and decryption\n";

	return pass;
}

bool SimpleKeyAgreementValidate(SimpleKeyAgreementDomain &d)
{
	if (d.GetCryptoParameters().Validate(GlobalRNG(), 3))
		cout << "passed    simple key agreement domain parameters validation" << endl;
	else
	{
		cout << "FAILED    simple key agreement domain parameters invalid" << endl;
		return false;
	}

	SecByteBlock priv1(d.PrivateKeyLength()), priv2(d.PrivateKeyLength());
	SecByteBlock pub1(d.PublicKeyLength()), pub2(d.PublicKeyLength());
	SecByteBlock val1(d.AgreedValueLength()), val2(d.AgreedValueLength());

	d.GenerateKeyPair(GlobalRNG(), priv1, pub1);
	d.GenerateKeyPair(GlobalRNG(), priv2, pub2);

	memset(val1.begin(), 0x10, val1.size());
	memset(val2.begin(), 0x11, val2.size());

	if (!(d.Agree(val1, priv1, pub2) && d.Agree(val2, priv2, pub1)))
	{
		cout << "FAILED    simple key agreement failed" << endl;
		return false;
	}

	if (memcmp(val1.begin(), val2.begin(), d.AgreedValueLength()))
	{
		cout << "FAILED    simple agreed values not equal" << endl;
		return false;
	}

	cout << "passed    simple key agreement" << endl;
	return true;
}

bool AuthenticatedKeyAgreementValidate(AuthenticatedKeyAgreementDomain &d)
{
	if (d.GetCryptoParameters().Validate(GlobalRNG(), 3))
		cout << "passed    authenticated key agreement domain parameters validation" << endl;
	else
	{
		cout << "FAILED    authenticated key agreement domain parameters invalid" << endl;
		return false;
	}

	SecByteBlock spriv1(d.StaticPrivateKeyLength()), spriv2(d.StaticPrivateKeyLength());
	SecByteBlock epriv1(d.EphemeralPrivateKeyLength()), epriv2(d.EphemeralPrivateKeyLength());
	SecByteBlock spub1(d.StaticPublicKeyLength()), spub2(d.StaticPublicKeyLength());
	SecByteBlock epub1(d.EphemeralPublicKeyLength()), epub2(d.EphemeralPublicKeyLength());
	SecByteBlock val1(d.AgreedValueLength()), val2(d.AgreedValueLength());

	d.GenerateStaticKeyPair(GlobalRNG(), spriv1, spub1);
	d.GenerateStaticKeyPair(GlobalRNG(), spriv2, spub2);
	d.GenerateEphemeralKeyPair(GlobalRNG(), epriv1, epub1);
	d.GenerateEphemeralKeyPair(GlobalRNG(), epriv2, epub2);

	memset(val1.begin(), 0x10, val1.size());
	memset(val2.begin(), 0x11, val2.size());

	if (!(d.Agree(val1, spriv1, epriv1, spub2, epub2) && d.Agree(val2, spriv2, epriv2, spub1, epub1)))
	{
		cout << "FAILED    authenticated key agreement failed" << endl;
		return false;
	}

	if (memcmp(val1.begin(), val2.begin(), d.AgreedValueLength()))
	{
		cout << "FAILED    authenticated agreed values not equal" << endl;
		return false;
	}

	cout << "passed    authenticated key agreement" << endl;
	return true;
}

bool ValidateRSA()
{
	cout << "\nRSA validation suite running...\n\n";

	byte out[100], outPlain[100];
	bool pass = true, fail;

	{
		const char *plain = "Everyone gets Friday off.";
		byte *signature = (byte *)
			"\x05\xfa\x6a\x81\x2f\xc7\xdf\x8b\xf4\xf2\x54\x25\x09\xe0\x3e\x84"
			"\x6e\x11\xb9\xc6\x20\xbe\x20\x09\xef\xb4\x40\xef\xbc\xc6\x69\x21"
			"\x69\x94\xac\x04\xf3\x41\xb5\x7d\x05\x20\x2d\x42\x8f\xb2\xa2\x7b"
			"\x5c\x77\xdf\xd9\xb1\x5b\xfc\x3d\x55\x93\x53\x50\x34\x10\xc1\xe1";

		FileSource keys("TestData/rsa512a.dat", true, new HexDecoder);
		Weak::RSASSA_PKCS1v15_MD2_Signer rsaPriv(keys);
		Weak::RSASSA_PKCS1v15_MD2_Verifier rsaPub(rsaPriv);

		size_t signatureLength = rsaPriv.SignMessage(GlobalRNG(), (byte *)plain, strlen(plain), out);
		fail = memcmp(signature, out, 64) != 0;
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "signature check against test vector\n";

		fail = !rsaPub.VerifyMessage((byte *)plain, strlen(plain), out, signatureLength);
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "verification check against test vector\n";

		out[10]++;
		fail = rsaPub.VerifyMessage((byte *)plain, strlen(plain), out, signatureLength);
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "invalid signature verification\n";
	}
	{
		FileSource keys("TestData/rsa1024.dat", true, new HexDecoder);
		RSAES_PKCS1v15_Decryptor rsaPriv(keys);
		RSAES_PKCS1v15_Encryptor rsaPub(rsaPriv);

		pass = CryptoSystemValidate(rsaPriv, rsaPub) && pass;
	}
	{
		RSAES<OAEP<SHA> >::Decryptor rsaPriv(GlobalRNG(), 512);
		RSAES<OAEP<SHA> >::Encryptor rsaPub(rsaPriv);

		pass = CryptoSystemValidate(rsaPriv, rsaPub) && pass;
	}
	{
		byte *plain = (byte *)
			"\x54\x85\x9b\x34\x2c\x49\xea\x2a";
		byte *encrypted = (byte *)
			"\x14\xbd\xdd\x28\xc9\x83\x35\x19\x23\x80\xe8\xe5\x49\xb1\x58\x2a"
			"\x8b\x40\xb4\x48\x6d\x03\xa6\xa5\x31\x1f\x1f\xd5\xf0\xa1\x80\xe4"
			"\x17\x53\x03\x29\xa9\x34\x90\x74\xb1\x52\x13\x54\x29\x08\x24\x52"
			"\x62\x51";
		byte *oaepSeed = (byte *)
			"\xaa\xfd\x12\xf6\x59\xca\xe6\x34\x89\xb4\x79\xe5\x07\x6d\xde\xc2"
			"\xf0\x6c\xb5\x8f";
		ByteQueue bq;
		bq.Put(oaepSeed, 20);
		FixedRNG rng(bq);

		FileSource privFile("TestData/rsa400pv.dat", true, new HexDecoder);
		FileSource pubFile("TestData/rsa400pb.dat", true, new HexDecoder);
		RSAES_OAEP_SHA_Decryptor rsaPriv;
		rsaPriv.AccessKey().BERDecodePrivateKey(privFile, false, 0);
		RSAES_OAEP_SHA_Encryptor rsaPub(pubFile);

		memset(out, 0, 50);
		memset(outPlain, 0, 8);
		rsaPub.Encrypt(rng, plain, 8, out);
		DecodingResult result = rsaPriv.FixedLengthDecrypt(GlobalRNG(), encrypted, outPlain);
		fail = !result.isValidCoding || (result.messageLength!=8) || memcmp(out, encrypted, 50) || memcmp(plain, outPlain, 8);
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << "PKCS 2.0 encryption and decryption\n";
	}

	return pass;
}

bool ValidateDH()
{
	cout << "\nDH validation suite running...\n\n";

	FileSource f("TestData/dh1024.dat", true, new HexDecoder());
	DH dh(f);
	return SimpleKeyAgreementValidate(dh);
}

bool ValidateMQV()
{
	cout << "\nMQV validation suite running...\n\n";

	FileSource f("TestData/mqv1024.dat", true, new HexDecoder());
	MQV mqv(f);
	return AuthenticatedKeyAgreementValidate(mqv);
}

bool ValidateLUC_DH()
{
	cout << "\nLUC-DH validation suite running...\n\n";

	FileSource f("TestData/lucd512.dat", true, new HexDecoder());
	LUC_DH dh(f);
	return SimpleKeyAgreementValidate(dh);
}

bool ValidateXTR_DH()
{
	cout << "\nXTR-DH validation suite running...\n\n";

	FileSource f("TestData/xtrdh171.dat", true, new HexDecoder());
	XTR_DH dh(f);
	return SimpleKeyAgreementValidate(dh);
}

bool ValidateElGamal()
{
	cout << "\nElGamal validation suite running...\n\n";
	bool pass = true;
	{
		FileSource fc("TestData/elgc1024.dat", true, new HexDecoder);
		ElGamalDecryptor privC(fc);
		ElGamalEncryptor pubC(privC);
		privC.AccessKey().Precompute();
		ByteQueue queue;
		privC.AccessKey().SavePrecomputation(queue);
		privC.AccessKey().LoadPrecomputation(queue);

		pass = CryptoSystemValidate(privC, pubC) && pass;
	}
	return pass;
}

bool ValidateDLIES()
{
	cout << "\nDLIES validation suite running...\n\n";
	bool pass = true;
	{
		FileSource fc("TestData/dlie1024.dat", true, new HexDecoder);
		DLIES<>::Decryptor privC(fc);
		DLIES<>::Encryptor pubC(privC);
		pass = CryptoSystemValidate(privC, pubC) && pass;
	}
	{
		cout << "Generating new encryption key..." << endl;
		DLIES<>::GroupParameters gp;
		gp.GenerateRandomWithKeySize(GlobalRNG(), 128);
		DLIES<>::Decryptor decryptor;
		decryptor.AccessKey().GenerateRandom(GlobalRNG(), gp);
		DLIES<>::Encryptor encryptor(decryptor);

		pass = CryptoSystemValidate(decryptor, encryptor) && pass;
	}
	return pass;
}

bool ValidateNR()
{
	cout << "\nNR validation suite running...\n\n";
	bool pass = true;
	{
		FileSource f("TestData/nr2048.dat", true, new HexDecoder);
		NR<SHA>::Signer privS(f);
		privS.AccessKey().Precompute();
		NR<SHA>::Verifier pubS(privS);

		pass = SignatureValidate(privS, pubS) && pass;
	}
	{
		cout << "Generating new signature key..." << endl;
		NR<SHA>::Signer privS(GlobalRNG(), 256);
		NR<SHA>::Verifier pubS(privS);

		pass = SignatureValidate(privS, pubS) && pass;
	}
	return pass;
}

bool ValidateDSA(bool thorough)
{
	cout << "\nDSA validation suite running...\n\n";

	bool pass = true;
	FileSource fs1("TestData/dsa1024.dat", true, new HexDecoder());
	DSA::Signer priv(fs1);
	DSA::Verifier pub(priv);
	FileSource fs2("TestData/dsa1024b.dat", true, new HexDecoder());
	DSA::Verifier pub1(fs2);
	assert(pub.GetKey() == pub1.GetKey());
	pass = SignatureValidate(priv, pub, thorough) && pass;
	pass = RunTestDataFile("TestVectors/dsa.txt", g_nullNameValuePairs, thorough) && pass;
	return pass;
}

bool ValidateLUC()
{
	cout << "\nLUC validation suite running...\n\n";
	bool pass=true;

	{
		FileSource f("TestData/luc1024.dat", true, new HexDecoder);
		LUCSSA_PKCS1v15_SHA_Signer priv(f);
		LUCSSA_PKCS1v15_SHA_Verifier pub(priv);
		pass = SignatureValidate(priv, pub) && pass;
	}
	{
		LUCES_OAEP_SHA_Decryptor priv(GlobalRNG(), 512);
		LUCES_OAEP_SHA_Encryptor pub(priv);
		pass = CryptoSystemValidate(priv, pub) && pass;
	}
	return pass;
}

bool ValidateLUC_DL()
{
	cout << "\nLUC-HMP validation suite running...\n\n";

	FileSource f("TestData/lucs512.dat", true, new HexDecoder);
	LUC_HMP<SHA>::Signer privS(f