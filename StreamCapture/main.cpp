#define TINS_STATIC
#define WIN32

#include <iostream>
#include <tins/tins.h>

using namespace Tins;
using namespace std;

bool callback(const PDU& pdu) {
	cout << pdu.size() << ':';

	// Find the IP layer
	const IP& ip = pdu.rfind_pdu<IP>();
	// Find the TCP layer
	const TCP& tcp = pdu.rfind_pdu<TCP>();

	cout << ip.src_addr() << ':' << tcp.sport() << " -> "
		 << ip.dst_addr() << ':' << tcp.dport() << endl;
	

	return true;
}

int main() {
	NetworkInterface iface = NetworkInterface::default_interface();

	Sniffer sniff(iface.name());
	sniff.set_filter("ip src 172.217.19.110");
	sniff.sniff_loop(callback);
}