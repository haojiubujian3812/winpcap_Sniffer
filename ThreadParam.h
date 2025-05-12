#pragma once
#include "PacketPool.h"
#include "pcap.h"

/**
*	����������capture_thread()�н��в�������
*/
class ThreadParam
{
public:
	pcap_t* m_adhandle;
	PacketPool* m_pool;
	pcap_dumper_t* m_dumper;
	int				m_mode;

	ThreadParam();
	ThreadParam(pcap_t* adhandle, PacketPool* pool, pcap_dumper_t* dumper, int mode);
	~ThreadParam();
};

