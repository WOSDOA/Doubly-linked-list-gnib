// wait.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "wait.h"
#include "misc.h"

#ifdef SOCKETS_AVAILABLE

#ifdef USE_BERKELEY_STYLE_SOCKETS
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#endif

NAMESPACE_BEGIN(CryptoPP)

unsigned int WaitObjectContainer::MaxWaitObjects()
{
#ifdef USE_WINDOWS_STYLE_SOCKETS
	return MAXIMUM_WAIT_OBJECTS * (MAXIMUM_WAIT_OBJECTS-1);
#else
	return FD_SETSIZE;
#endif
}

WaitObjectContainer::WaitObjectContainer(WaitObjectsTracer* tracer)
	: m_tracer(tracer), m_eventTimer(Timer::MILLISECONDS)
	, m_sameResultCount(0), m_noWaitTimer(Timer::MILLISECONDS)
{
	Clear();
	m_eventTimer.StartTimer();
}

void WaitObjectContainer::Clear()
{
#ifdef USE_WINDOWS_STYLE_SOCKETS
	m_handles.clear();
#else
	m_maxFd = 0;
	FD_ZERO(&m_readfds);
	FD_ZERO(&m_writefds);
#endif
	m_noWait = false;
	m_firstEventTime = 0;
}

inline void WaitObjectContainer::SetLastResult(LastResultType result)
{
	if (result == m_lastResult)
		m_sameResultCount++;
	else
	{
		m_lastResult = result;
		m_sameResultCount = 0;
	}
}

void WaitObjectContainer::DetectNoWait(LastResultType result, CallStack const& callStack)
{
	if (result == m_lastResult && m_noWaitTimer.ElapsedTime() > 1000)
	{
		if (m_sameResultCount > m_noWaitTimer.ElapsedTime())
		{
			if (m_tracer)
			{
				std::string desc = "No wait loop detected - m_lastResult: ";
				desc.append(IntToString(m_lastResult)).append(", call stack:");
				for (CallStack const* cs = &callStack; cs; cs = cs->Prev())
					desc.append("\n- ").append(cs->Format());
				m_tracer->TraceNoWaitLoop(desc);
			}
			try { throw 0; } catch (...) {}		// help debugger break
		}

		m_noWaitTimer.StartTimer();
		m_sameResultCount = 0;
	}
}

void WaitObjectContainer::SetNoWait(CallStack const& callStack)
{
	DetectNoWait(LASTRESULT_NOWAIT, CallStack("WaitObjectContainer::SetNoWait()", &callStack));
	m_noWait = true;
}

void WaitObjectContainer::ScheduleEvent(double milliseconds, CallStack const& callStack)
{
	if (milliseconds <= 3)
		DetectNoWait(LASTRESULT_SCHEDULED, CallStack("WaitObjectContainer::ScheduleEvent()", &callStack));
	double thisEventTime = m_eventTimer.ElapsedTimeAsDouble() + milliseconds;
	if (!m_firstEventTime || thisEventTime < m_firstEventTime)
		m_firstEventTime = thisEventTime;
}

#ifdef USE_WINDOWS_STYLE_SOCKETS

struct WaitingThreadData
{
	bool waitingToWait, terminate;
	HANDLE startWaiting, stopWaiting;
	const HANDLE *waitHandles;
	unsigned int count;
	HANDLE threadHandle;
	DWORD threadId;
	DWORD* error;
};

WaitObjectContainer::~WaitObjectContainer()
{
	try		// don't let exceptions escape destructor
	{
		if (!m_threads.empty())
		{
			HANDLE threadHandles[MAXIMUM_WAIT_OBJECTS];
			unsigned int i;
			for (i=0; i<m_threads.size(); i++)
			{
				WaitingThreadData &thread = *m_threads[i];
				while (!thread.waitingToWait)	// spin until thread is in the initial "waiting to wait" state
					Sleep(0);
				thread.terminate = true;
				threadHandles[i] = thread.threadHandle;
			}
			PulseEvent(m_startWaiting);
			::WaitForMultipleObjects((DWORD)m_threads.size(), threadHandles, TRUE, INFINITE);
			for (i=0; i<m_threads.size(); i++)
				CloseHandle(threadHandles[i]);
			CloseHandle(m_startWaiting);
			CloseHandle(m_stopWaiting);
		}
	}
	catch (...)
	{
	}
}


void WaitObjectContainer::AddHandle(HANDLE handle, CallStack const& callStack)
{
	DetectNoWait(m_handles.size(), CallStack("WaitObjectContainer::AddHan