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
#include <cstring>
using namespace std;

int main(void){ 
  /*
  cout<<"CAUTION: This is work in progress and will only work for ether->ipv4->udp->DNS\n";
  cout<<"\nEnter Src MacAddress (For example 00:50:43:11:22:33): ";
  char SrcMac[20];
  char DstMac[20];
  gets(SrcMac);
  cout<<"\nEnter Dst MacAddress (For example 00:50:43:11:22:33): ";
  gets(DstMac);
  int option;
  char SrcIp4[20];
  char DstIp4[20];
  char SrcIp6[20];
  char DstIp6[20];
  int srcPort;
  int dstPort;
  char dnsQuery[20];
  char fileName[20];
  int number;
  // create a new Ethernet layer
  cout<<"\nPress 1 for ipv4, 2 for ipv6: ";
  cin>>option;
  if(option==1){
    cout<<"\nEnter src ip (for example 192.168.1.1): ";
    gets(SrcIp4);
    cout<<"\nEnter dst ip (for example 192.168.1.1): ";
    gets(DstIp4);
  }
  else if(option==2){
    cout<<"\nEnter src ip (for example 192.168.1.1): ";
    gets(SrcIp6);
    cout<<"\nEnter dst ip (for example 192.168.1.1): ";
    gets(DstIp6);
  }
  else{
    cout << "\nWrong Input\n";
    exit(0);
  }
  
  cout<<"\nPress 1 for udp, 2 for tcp: ";
  option =0;
  cin>>option;
  if(option==1){
    srcPort = 0;
    dstPort = 0;
    cout<<"\nEnter udp src port (for example 1234): ";
    cin>>srcPort;
    cout<<"\nEnter udp dst port (for example 1813): ";		
    cin>>dstPort;
  }
  cout<<"\nEnter dns query (forexample www.google.com): ";
  gets(dnsQuery);
  
  cout<<"\nEnter filename (for example ipv4.pcap)";
  gets(fileName);
 */ 
  int number=10;
  
  
  
  cout<<"\nCreating EthernetLayer";
  pcpp::EthLayer newEthernetLayer(pcpp::MacAddress("00:50:43:11:22:33"), pcpp::MacAddress("00:50:43:11:22:33"));
  
  
  cout<<"\nCreating IPv4 Layer";
  pcpp::IPv4Layer newIPLayer(pcpp::IPv4Address(std::string("172.168.23.5")), pcpp::IPv4Address(std::string("192.168.1.2")));
  newIPLayer.getIPv4Header()->ipId = htons(2000);
  newIPLayer.getIPv4Header()->timeToLive = 64;   
  
  // create a new UDP layer
  cout<<"\nCreating UDP Layer";
  pcpp::UdpLayer newUdpLayer(4096,1813);
  
  // create a new DNS layer
  cout<<"\nCreating DNS layer";
  pcpp::DnsLayer newDnsLayer;
  newDnsLayer.addQuery("www.google.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN);
  
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
  pcpp::PcapFileWriterDevice writer2("testipv4.pcap");
  writer2.open(true);
  while(number>0){
  	writer2.writePacket(*(newPacket.getRawPacket()));
  	number--;
  }
  writer2.close();			
  cout<<"\ndone\n";
  getchar();
  
}
