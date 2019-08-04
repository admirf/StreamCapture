#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapLiveDeviceList.h>
#include <SSLLayer.h>
#include <PlatformSpecificUtils.h>
#include <iostream>
#include "NetflixHandler.h"

using namespace std;

string getProtocolTypeAsString(pcpp::ProtocolType);
static void onPacketArrives(pcpp::RawPacket*, pcpp::PcapLiveDevice*, void*);

int main() 
{
	std::string interfaceIPAddr = "192.168.0.13";

	pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr.c_str());

	if (dev == nullptr)
	{
		cout << "Cannot find interface with IPv4 address of " << interfaceIPAddr << endl;
		return 1;
	}

	if (!dev->open())
	{
		cout << "Cannot open device\n";
		return 1;
	}

	cout << "Starting capture on: " << interfaceIPAddr << endl;

	vector<strcap::IPacketHandler*> handlers;
	handlers.push_back(new strcap::NetflixHandler());

	dev->startCapture(onPacketArrives, &handlers);

	PCAP_SLEEP(60);

	dev->stopCapture();

	for (auto& handler : handlers) {
		delete handler;
	}

	return 0;
}

void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
	auto handlers = static_cast<vector<strcap::IPacketHandler*>*>(cookie);

	pcpp::Packet parsedPacket(packet);

	for (auto& handler : *handlers) {
		handler->handle(parsedPacket);
	}
	/*
	for (auto curLayer = parsedPacket.getFirstLayer(); curLayer != nullptr; curLayer = curLayer->getNextLayer())
	{
		auto type = getProtocolTypeAsString(curLayer->getProtocol());

		if (type == "SSL") {
			auto ssl = parsedPacket.getLayerOfType<pcpp::SSLLayer>();
			if (ssl->getRecordType() == pcpp::SSL_HANDSHAKE) {
				cout << "Test\n";
				auto handshake = dynamic_cast<pcpp::SSLHandshakeLayer*>(ssl);
				auto clientMessage = handshake->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
				if (clientMessage != nullptr) {
					for (short i = 0; i < clientMessage->getExtensionCount(); ++i) {
						auto ext = clientMessage->getExtension(i);
						auto ptr = ext->getData();
						for (short j = 0; j < ext->getLength(); ++j) cout << (char) * (ptr + j);
						cout << endl;
					}
				}
			}
		}
	}*/
}

std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
	switch (protocolType)
	{
	case pcpp::Ethernet:
		return "Ethernet";
	case pcpp::IPv4:
		return "IPv4";
	case pcpp::TCP:
		return "TCP";
	case pcpp::HTTPRequest:
	case pcpp::SSL:
		return "SSL";
	case pcpp::HTTPResponse:
		return "HTTP";
	default:
		return "Unknown";
	}
}
