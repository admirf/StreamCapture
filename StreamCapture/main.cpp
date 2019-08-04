#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapLiveDeviceList.h>
#include <SSLLayer.h>
#include <PlatformSpecificUtils.h>
#include <iostream>

using namespace std;

string getProtocolTypeAsString(pcpp::ProtocolType);
static void onPacketArrives(pcpp::RawPacket*, pcpp::PcapLiveDevice*, void*);

int main() 
{
	// IPv4 address of the interface we want to sniff
	std::string interfaceIPAddr = "192.168.0.13";

	// find the interface by IP address
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

	dev->startCapture(onPacketArrives, nullptr);

	PCAP_SLEEP(10);

	dev->stopCapture();

	return 0;
}

void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
	cout << packet->getFrameLength() << endl;

	pcpp::Packet parsedPacket(packet);

	for (pcpp::Layer* curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer())
	{
		auto type = getProtocolTypeAsString(curLayer->getProtocol());

		//printf("Layer type: %s; Total data: %d [bytes]; Layer data: %d [bytes]; Layer payload: %d [bytes]\n",
		//	getProtocolTypeAsString(curLayer->getProtocol()).c_str(), // get layer type
		//	(int)curLayer->getDataLen(),                              // get total length of the layer
		//	(int)curLayer->getHeaderLen(),                            // get the header length of the layer
		//	(int)curLayer->getLayerPayloadSize());                    // get the payload length of the layer (equals total length minus header length)

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
	}
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
