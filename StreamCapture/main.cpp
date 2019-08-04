#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapLiveDeviceList.h>
#include <iostream>

using namespace std;

int main() 
{
	// IPv4 address of the interface we want to sniff
	std::string interfaceIPAddr = "192.168.0.13";

	// find the interface by IP address
	pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr.c_str());

	if (dev == nullptr)
	{
		printf("Cannot find interface with IPv4 address of '%s'\n", interfaceIPAddr.c_str());
		return 1;
	}

	return 0;
}