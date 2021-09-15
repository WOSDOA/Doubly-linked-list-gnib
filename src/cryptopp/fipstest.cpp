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

extern PowerUpSelfTest