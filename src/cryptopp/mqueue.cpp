// mqueue.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "mqueue.h"

NAMESPACE_BEGIN(CryptoPP)

MessageQueue::MessageQueue(unsigned int nodeSize)
	: m_queue(nodeSize), m_lengths(1, 0U), m_messageCounts(1, 0U)
{
}

size_t MessageQueue::CopyRangeTo2(BufferedTransformation &target, lword &begin, lword end, const std::string &channel, bool 