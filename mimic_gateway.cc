#include <sys/socket.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>  //htons etc
#include <iostream>
using namespace std;
#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60

#pragma pack(1)
struct arp_header {
	unsigned short hardware_type;
	unsigned short protocol_type;
	unsigned char hardware_len;
	unsigned char protocol_len;
	unsigned short opcode;
	unsigned char sender_mac[MAC_LENGTH];
	in_addr_t sender_ip;
	unsigned char target_mac[MAC_LENGTH];
	in_addr_t  target_ip;
};
#pragma pack()
int get_if_ip4(const char *ipname, uint32_t *ip) {
	inet_pton(AF_INET, ipname, ip);
	return 0;
}

int get_if_info(const char *ifname, uint32_t *ip, char *mac, int *ifindex,const char *ip_name)
{
	int err = -1;
	struct ifreq ifr;
	int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sd <= 0) {
		perror("socket()");
		goto out;
	}
	if (strlen(ifname) > (IFNAMSIZ - 1)) {
		printf("Too long interface name, MAX=%i\n", IFNAMSIZ - 1);
		goto out;
	}

	strcpy(ifr.ifr_name, ifname);

	//Get interface index using name
	if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		goto out;
	}
	*ifindex = ifr.ifr_ifindex;
	printf("interface index is %d\n", *ifindex);

	//Get MAC address of the interface
	if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		goto out;
	}

	//Copy mac address to output
	memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);

	if (get_if_ip4(ip_name, ip)) {
		goto out;
	}

	err = 0;
out:
	if (sd > 0) {
		close(sd);
	}
	return err;
}
int main(int argc, char** argv){

	if (argc < 4)
	{
		cout << "Give Interface name on which you want to listen." << endl;
		return 0;
	}

	/*get mac address of your interface*/
	int des;
	struct ifreq ifr;
	memset(&ifr,0,sizeof(ifr));
	des = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , argv[3] , IFNAMSIZ-1);
	ioctl(des, SIOCGIFHWADDR, &ifr);
	close(des);
	struct sockaddr_in source;
	struct sockaddr_in destination;
	inet_pton(AF_INET, argv[1], &(source.sin_addr));
	inet_pton(AF_INET, argv[2], &(destination.sin_addr));
	//For binding socket with device
	int sockopt;
	struct ifreq ifopts;

	//Code works in root mode only
	int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0)
	{
		cout << "Enable root mode" << endl;
		return 0;
	}

	/*
	 * Next block belongs to binding the socket to specified interface
	 * It uses ioctl() function for that
	 * So, it is Linux based only
	 */
	strncpy(ifopts.ifr_name, argv[3], IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(fd, SIOCSIFFLAGS, &ifopts);
	/* Allow the socket to be reused - incase connection is closed prematurely */
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1)
	{
		perror("setsockopt");
		close(fd);
		exit(EXIT_FAILURE);
	}
	/* Bind to device */
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, argv[3], IFNAMSIZ - 1) == -1)
	{
		perror("SO_BINDTODEVICE");
		close(fd);
		exit(EXIT_FAILURE);
	}
	int broadcastPermission = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (void *) &broadcastPermission, 
				sizeof(broadcastPermission)) < 0)
		perror("setsockopt() failed");
	/*
	 * recieve data in the buffer
	 * setting buffer to empty 
	 */
	unsigned char *buffer = (unsigned char *)malloc(65536);
	memset(buffer, 0, 65536);
	ethhdr* header = (ethhdr*) buffer;
	header->h_dest[0] = 0xff;
	header->h_dest[1] = 0xff;
	header->h_dest[2] = 0xff;
	header->h_dest[3] = 0xff;
	header->h_dest[4] = 0xff;
	header->h_dest[5] = 0xff;
	header->h_source[0] = ifr.ifr_hwaddr.sa_data[0];
	header->h_source[1] = ifr.ifr_hwaddr.sa_data[1];
	header->h_source[2] = ifr.ifr_hwaddr.sa_data[2];
	header->h_source[3] = ifr.ifr_hwaddr.sa_data[3];
	header->h_source[4] = ifr.ifr_hwaddr.sa_data[4];
	header->h_source[5] = ifr.ifr_hwaddr.sa_data[5];
	header->h_proto = htons(ETH_P_ARP);
	struct arp_header* arp = (struct arp_header*)(buffer+sizeof(struct ethhdr));
	arp->hardware_len = 6;
	arp->protocol_len = 4;
	arp->opcode = htons(ARPOP_REQUEST);
	arp->hardware_type = htons(1);
	arp->protocol_type = htons(ETH_P_IP);
	arp->target_ip = destination.sin_addr.s_addr;
	arp->sender_ip = source.sin_addr.s_addr;
	arp->target_mac[0] = 0xff;
	arp->target_mac[1] = 0xff;
	arp->target_mac[2] = 0xff;
	arp->target_mac[3] = 0xff;
	arp->target_mac[4] = 0xff;
	arp->target_mac[5] = 0xff;
	arp->sender_mac[0] = ifr.ifr_hwaddr.sa_data[0];
	arp->sender_mac[1] = ifr.ifr_hwaddr.sa_data[1];
	arp->sender_mac[2] = ifr.ifr_hwaddr.sa_data[2];
	arp->sender_mac[3] = ifr.ifr_hwaddr.sa_data[3];
	arp->sender_mac[4] = ifr.ifr_hwaddr.sa_data[4];
	arp->sender_mac[5] = ifr.ifr_hwaddr.sa_data[5];
	struct sockaddr_ll sadr_ll;
	memset(&sadr_ll,0,sizeof(struct sockaddr_ll));
	uint32_t src;
	char mac[6];
	int ifindex;
	const char* ifname = argv[3];
	const char* ip_name = argv[1];
	if (get_if_info(ifname, &src, mac, &ifindex,ip_name)) {
	}
	sadr_ll.sll_ifindex = ifindex; // index of interface
	sadr_ll.sll_halen = 6; // length of destination mac address
	sadr_ll.sll_addr[0] = 0xff;
	sadr_ll.sll_addr[1] = 0xff;
	sadr_ll.sll_addr[2] = 0xff;
	sadr_ll.sll_addr[3] = 0xff;
	sadr_ll.sll_addr[4] = 0xff;
	sadr_ll.sll_addr[5] = 0xff;
	int saddr_len = sizeof(sadr_ll);

	while (1)
	{
		if(sendto(fd,(const void*)buffer,(sizeof(ethhdr)+sizeof(struct arp_header)),0,(const struct sockaddr*)&sadr_ll,saddr_len)<0){
			char buf[50];
			perror(buf);
			cout<<"Could not send"<<endl;
		}
		sleep(1);
	}
}
