#include "NetflixHandler.h"

#include <IPv4Layer.h>
#include <SSLLayer.h>
#include <iostream>
#include <sstream>

namespace strcap
{
	void NetflixHandler::handle(pcpp::Packet& packet)
	{
		if (this->isNetflixPacket(packet)) {
			auto ip = packet.getLayerOfType<pcpp::IPv4Layer>();

			std::cout << "Netflix stream packet, Src IP: " << ip->getSrcIpAddress().toString() << ", Dst IP: " << ip->getDstIpAddress().toString()
				<< ", Packet Size: " << packet.getRawPacket()->getFrameLength() << '\n';
		}
	}
	
	bool NetflixHandler::isNetflixPacket(pcpp::Packet& packet)
	{
		auto ssl = packet.getLayerOfType<pcpp::SSLLayer>();

		if (ssl) {
			if (ssl->getRecordType() == pcpp::SSL_HANDSHAKE) {
				auto handshake = dynamic_cast<pcpp::SSLHandshakeLayer*>(ssl);
				auto clientMessage = handshake->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
				if (clientMessage) {
					auto ext = clientMessage->getExtensionOfType(pcpp::SSLExtensionType::SSL_EXT_SERVER_NAME);
					if (ext) {
						std::stringstream buffer;
						std::string value;
						for (auto i = 0; i < ext->getLength(); ++i) buffer << (char) * (ext->getData() + i);
						buffer >> value;

						if (value.find(std::string(this->keyword)) != std::string::npos) {
							auto ip = packet.getLayerOfType<pcpp::IPv4Layer>();
							if (ip) {
								this->netflixIPs[ip->getDstIpAddress().toString()] = true;
							}

							return true;
						}
					}
				}
			}
		}

		auto ip = packet.getLayerOfType<pcpp::IPv4Layer>();

		if (ip) {
			auto value = ip->getSrcIpAddress().toString();
			return this->netflixIPs[value];
		}

		return false;
	}
}