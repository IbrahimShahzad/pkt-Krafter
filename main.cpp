#include "stdlib.h"
#include "Packet.h"
#include "EthLayer.h"
#include "VlanLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include "UdpLayer.h"
#include "DnsLayer.h"
#include "PcapFileDevice.h"
#include <in.h>
#include <iostream>
#include <string.h>
using namespace std;

int main(void){ 
	cout<<"CAUTION: This is work in progress and will only work for ether->ipv4->udp->DNS\n";
	cout<<"\nEnter Src MacAddress (For example 00:50:43:11:22:33): ";
	String SrcMac;
	String DstMac;
	gets(SrcMac);
	cout<<\nEnter Dst MacAddress (For example 00:50:43:11:22:33): ";
	gets(DstMac);
	int option;
	
	// create a new Ethernet layer
	cout<<"\nCreating EthernetLayer";
	pcpp::EthLayer newEthernetLayer(pcpp::MacAddress(SrcMac), pcpp::MacAddress(DstMac));

	cout<<"\nPress 1 for ipv4, 2 for ipv6: ";
	cin option;
	if(option==1){
		String SrcIp4;
		String DstIp4;
		cout<<"\nEnter src ip (for example 192.168.1.1): ";
		gets(SrcIp4);
		cout<<"\nEnter dst ip (for example 192.168.1.1): ";
		gets(DstIp6);
		// create a new IPv4 layer
		cout<<"\nCreating IPv4 Layer";
		pcpp::IPv4Layer newIPLayer(pcpp::IPv4Address(std::string(SrcIp4)), pcpp::IPv4Address(std::string(DstIp4)));
		newIPLayer.getIPv4Header()->ipId = htons(2000);
		newIPLayer.getIPv4Header()->timeToLive = 64;
	}
	elseif(option==2){
		String SrcIp6;
		String DstIp6;
		cout<<"\nEnter src ip (for example 192.168.1.1): ";
		gets(SrcIp6);
		cout<<"\nEnter dst ip (for example 192.168.1.1): ";
		gets(DstIp6)
	}
	else
		cout<<"\nwrong input"<<endl;
		exit(0);
	
	cout<<"\nPress 1 for udp, 2 for tcp: ";
	cin option;
	if(option==1){
		int srcPort;
		int dstPort;
		cout<<"\nEnter udp src port (for example 1234): ";
		cin>>srcPort;
		cout<<"\nEnter udp dst port (for example 1813): ";		
		cin>>dstPort;
		// create a new UDP layer
		cout<<\nCreating UDP Layer";
		pcpp::UdpLayer newUdpLayer(srcPort, dstPort);
	}
	String dnsQuery;
	cout<<"\nEnter dns query (forexample www.google.com): ";
	gets(dnsQuery);
	
	// create a new DNS layer
	cout<<"\nCreating DNS layer";
	pcpp::DnsLayer newDnsLayer;
	newDnsLayer.addQuery(dnsQuery, pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN);
    
	
	String fileName;
	cout<<"\nEnter filename (for example ipv4.pcap)";
	gets(fileName);
	int number;
	cout<< "\nNumber of packets to write: "
	cin>>number;
	
	// create a packet with initial capacity of 100 bytes (will grow automatically if needed)
	cout<<"\nCreating packet";
	pcpp::Packet newPacket(100);
            
	// add all the layers we created
	cout<<"\nAdding Layers";
	newPacket.addLayer(&newEthernetLayer);
	newPacket.addLayer(&newIPLayer);
	newPacket.addLayer(&newUdpLayer);
	newPacket.addLayer(&newDnsLayer);

	cout<<"\nComputing Fields";
	// compute all calculated fields
	newPacket.computeCalculateFields();
    
	cout<<"\nWriting to file";
	// write the new packet to a pcap file
	pcpp::PcapFileWriterDevice writer2(fileName);
	writer2.open(true);
	while(i>0){
		writer2.writePacket(*(newPacket.getRawPacket()));
		i--;
	}
	writer2.close();			

	
}
