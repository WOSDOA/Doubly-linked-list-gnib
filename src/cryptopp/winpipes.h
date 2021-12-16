#ifndef CRYPTOPP_WINPIPES_H
#define CRYPTOPP_WINPIPES_H

#include "config.h"

#ifdef WINDOWS_PIPES_AVAILABLE

#include "network.h"
#include "queue.h"
#include <winsock2.h>

NAMESPACE_BEGIN(CryptoPP)

//! Windows Handle
class WindowsHandle
{
public:
	WindowsHandle(HANDLE h = INVALID_HANDLE_VALUE, bool own=false);
	WindowsHandle(const WindowsHandle &h) : m_h(h.m_h), m_own(false) {}
	virtual ~WindowsHandle();

	bool GetOwnership() const {return m_own;}
	void SetOwnership(bool own) {m_own = own;}

	operator HANDLE() {return m_h;}
	HANDLE GetHandle() const {return m_h;}
	bool HandleValid() const;
	void AttachHandle(HANDLE h, bool own=false);
	HANDLE DetachHandle();
	void CloseHandle();

protected:
	virtual void HandleChanged() {}

	HANDLE m_h;
	bool m_own;
};

//! Windows Pipe
class WindowsPipe
{
public:
	class Err : public OS_Error
	{
	public:
		Err(HANDLE h, const std::string& operation, int error);
		HANDLE GetHandle() const {return m_h;}

	