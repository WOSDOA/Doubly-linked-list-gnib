// queue.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "queue.h"
#include "filters.h"

NAMESPACE_BEGIN(CryptoPP)

static const unsigned int s_maxAutoNodeSize = 16*1024;

// this class for use by ByteQueue only
class ByteQueueNode
{
public:
	ByteQueueNode(size_t maxSize)
		: buf(maxSize)
	{
		m_head = m_tail = 0;
		next = 0;
	}

	inline size_t MaxSize() const {return buf.size();}

	inline size_t CurrentSize() const
	{
		return m_tail-m_head;
	}

	inline bool UsedUp() const
	{
		return (m_head==MaxSize());
	}

	inline void Clear()
	{
		m_head = m_tail = 0;
	}

	inline size_t Put(const byte *begin, size_t length)
	{
		size_t l = STDMIN(length, MaxSize()-m_tail);
		if (buf+m_tail != begin)
			memcpy(buf+m_tail, begin, l);
		m_tail += l;
		return l;
	}

	inline size_t Peek(byte &outByte) const
	{
		if (m_tail==m_head)
			return 0;

		outByte=buf[m_head];
		return 1;
	}

	inline size_t Peek(byte *target, size_t copyMax) const
	{
		size_t len = STDMIN(copyMax, m_tail-m_head);
		memcpy(target, buf+m_head, len);
		return len;
	}

	inline size_t CopyTo(BufferedTransformation &target, const std::string &channel=DEFAULT_CHANNEL) const
	{
		size_t len = m_tail-m_head;
		target.ChannelPut(channel, buf+m_head, len);
		return len;
	}

	inline size_t CopyTo(BufferedTransformation &target, size_t copyMax, const std::string &channel=DEFAULT_CHANNEL) const
	{
		size_t len = STDMIN(copyMax, m_tail-m_head);
		target.ChannelPut(channel, buf+m_head, len);
		return len;
	}

	inline size_t Get(byte &outByte)
	{
		size_t len = Peek(outByte);
		m_head += len;
		return len;
	}

	inline size_t Get(byte *outString, size_t getMax)
	{
		size_t len = Peek(outString, getMax);
		m_head += len;
		return len;
	}

	inline size_t TransferTo(BufferedTransformation &target, const std::string &channel=DEFAULT_CHANNEL)
	{
		size_t len = m_tail-m_head;
		target.ChannelPutModifiable(channel, buf+m_head, len);
		m_head = m_tail;
		return len;
	}

	inline size_t TransferTo(BufferedTransformation &target, lword transferMax, const std::string &channel=DEFAULT_CHANNEL)
	{
		size_t len = UnsignedMin(m_tail-m_head, transferMax);
		target.ChannelPutModifiable(channel, buf+m_head, len);
		m_head += len;
		return len;
	}

	inline size_t Skip(size_t skipMax)
	{
		size_t len = STDMIN(skipMax, m_tail-m_head);
		m_head += len;
		return len;
	}

	inline byte operator[](size_t i) const
	{
		return buf[m_head+i];
	}

	ByteQueueNode *next;

	SecByteBlock buf;
	size_t m_head, m_tail;
};

// ********************************************************

ByteQueue::ByteQueue(size_t nodeSize)
	: m_lazyString(NULL), m_lazyLength(0)
{
	SetNodeSize(nodeSize);
	m_head = m_tail = new ByteQueueNode(m_nodeSize);
}

void ByteQueue::SetN