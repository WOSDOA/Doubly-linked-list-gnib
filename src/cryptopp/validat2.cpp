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
	pass = pass &&