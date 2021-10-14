// pubkey.h - written and placed in the public domain by Wei Dai

#ifndef CRYPTOPP_PUBKEY_H
#define CRYPTOPP_PUBKEY_H

/** \file

	This file contains helper classes/functions for implementing public key algorithms.

	The class hierachies in this .h file tend to look like this:
<pre>
                  x1
                 / \
                y1  z1
                 |  |
            x2<y1>  x2<z1>
                 |  |
                y2  z2
                 |  |
            x3<y2>  x3<z2>
                 |  |
                y3  z3
</pre>
	- x1, y1, z1 are abstract interface classes defined in cryptlib.h
	- x2, y2, z2 are implementations of the interfaces using "abstract policies", which
	  are pure virtual functions that should return interfaces to interchangeable algorithms.
	  These classes have "Base" suffixes.
	- x3, y3, z3 hold actual algorithms and implement those virtual functions.
	  These classes have "Impl" suffixes.

	The "TF_" prefix means an implementation using trapdoor functions on integers.
	The "DL_" prefix means an implementation using group operations (in groups where discrete log is hard).
*/

#include "modarith.h"
#include "filters.h"
#include "eprecomp.h"
#include "fips140.h"
#include "argnames.h"
#include <memory>

// VC60 workaround: this macro is defined in shlobj.h and conflicts with a template parameter used in this file
#undef INTERFACE

NAMESPACE_BEGIN(CryptoPP)

//! _
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE TrapdoorFunctionBounds
{
public:
	virtual ~TrapdoorFunctionBounds() {}

	virtual Integer PreimageBound() const =0;
	virtual Integer ImageBound() const =0;
	virtual Integer MaxPreimage() const {return --PreimageBound();}
	virtual Integer MaxImage() const {return --ImageBound();}
};

//! _
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE RandomizedTrapdoorFunction : public TrapdoorFunctionBounds
{
public:
	virtual Integer ApplyRandomizedFunction(RandomNumberGenerator &rng, const Integer &x) const =0;
	virtual bool IsRandomized() const {return true;}
};

//! _
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE TrapdoorFunction : public RandomizedT