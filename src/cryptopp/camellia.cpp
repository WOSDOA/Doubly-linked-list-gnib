// camellia.cpp - by Kevin Springle, 2003
// This code is hereby placed in the public domain.

/*
Optimisations and defense against timing attacks added in Jan 2007 by Wei Dai.

The first 2 rounds and the last round seem especially vulnerable to timing
attacks. The protection is similar to what was implemented for Rijndael.
See comments at top of rijndael.cpp for more details.
*/

#include "pch.h"

#include "camellia.h"
#include "misc.h"
#include "cpu.h"

NAMESPACE_BEGIN(CryptoPP)

// round implementation that uses a small table for protection against timing attacks
#define SLOW_ROUND(lh, ll, rh, rl, kh, kl)	{							\
	word32 zr = ll ^ kl;												\
	word32 zl = lh ^ kh;												\
	zr=	rotlFixed(s1[GETBYTE(zr, 3)], 1) |