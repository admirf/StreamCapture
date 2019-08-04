#pragma once

#include "IPacketHandler.h"

#include <map>
#include <string>

namespace strcap
{
	class NetflixHandler: public IPacketHandler
	{
	private:
		const char* keyword = "nflxvideo.net";
		std::map<std::string, bool> netflixIPs;
	public:
		void handle(pcpp::Packet&);
	protected:
		bool isNetflixPacket(pcpp::Packet&);
	};
}



