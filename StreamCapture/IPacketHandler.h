#pragma once

#include <Packet.h>

namespace strcap 
{
	class IPacketHandler
	{
	public:
		virtual void handle(pcpp::Packet&) = 0;
	};
}



