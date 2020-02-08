#include <sys/socket.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <string.h>
#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h> 

#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define PROTO_ARP 0x806
#define ARP_REQUEST 0x01
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
	in_addr_t target_ip;
};
#pragma pack()
using namespace std;
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
int out(int *sockfd){
	printf("out function called CLEANUP SOCKET");
	close(*sockfd);
	return -1;
}
int socket_bind_arp(int iface_index,int *sockfd){
	printf("entered socket_bind_arp\n");
	int err =0;

	printf("starting binding of socket for listening to arp request\n");

	struct sockaddr_ll sll;
	memset(&sll,0,sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = iface_index;

	if(bind(*sockfd,(struct sockaddr*) &sll,sizeof(struct sockaddr_ll))<0){
		printf("error in binding");
		err = out(sockfd);
		return err;
	}
	return err;

}
int send_arp_reply(int *sockfd,const char *buff,struct ifreq *ifr,int *ifaceindex){
	int err = 0;
	struct sockaddr_ll socket_address;
	socket_address.sll_family = AF_PACKET;
	socket_address.sll_protocol = htons(ETH_P_ARP);
	socket_address.sll_ifindex = *ifaceindex;
	socket_address.sll_hatype = htons(ARPHRD_ETHER);
	socket_address.sll_pkttype = (PACKET_BROADCAST);
	socket_address.sll_halen = MAC_LENGTH;
	socket_address.sll_addr[6] = 0x00;
	socket_address.sll_addr[7] = 0x00;
	char sendBuffer[100];
	struct ethhdr* src_eth = (struct ethhdr*) buff;
	struct arp_header* src_arp = (struct arp_header*) (buff+14);
	struct ethhdr *send_eth = (struct ethhdr *) sendBuffer;
	struct arp_header *arp_rep = (struct arp_header *) (sendBuffer + 14);

	send_eth->h_dest[0] = src_eth->h_source[0];
	send_eth->h_dest[1] = src_eth->h_source[1];
	send_eth->h_dest[2] = src_eth->h_source[2];
	send_eth->h_dest[3] = src_eth->h_source[3];
	send_eth->h_dest[4] = src_eth->h_source[4];
	send_eth->h_dest[5] = src_eth->h_source[5];

	send_eth->h_source[0] = ifr->ifr_hwaddr.sa_data[0];
	send_eth->h_source[1] = ifr->ifr_hwaddr.sa_data[1];
	send_eth->h_source[2] = ifr->ifr_hwaddr.sa_data[2];
	send_eth->h_source[3] = ifr->ifr_hwaddr.sa_data[3];
	send_eth->h_source[4] = ifr->ifr_hwaddr.sa_data[4];
	send_eth->h_source[5] = ifr->ifr_hwaddr.sa_data[5];
	
	send_eth->h_proto = htons(ETH_P_ARP);

	arp_rep->hardware_len = 6;
	arp_rep->hardware_type = htons(1);
	arp_rep->protocol_len = 4;
	arp_rep->opcode = htons(ARPOP_REPLY);
	arp_rep->sender_ip = src_arp->target_ip;
	arp_rep->target_ip = src_arp->sender_ip;
	arp_rep->protocol_type = htons(ETH_P_IP);
	arp_rep->sender_mac[0] = ifr->ifr_hwaddr.sa_data[0];
	arp_rep->sender_mac[1] = ifr->ifr_hwaddr.sa_data[1];
	arp_rep->sender_mac[2] = ifr->ifr_hwaddr.sa_data[2];
	arp_rep->sender_mac[3] = ifr->ifr_hwaddr.sa_data[3];
	arp_rep->sender_mac[4] = ifr->ifr_hwaddr.sa_data[4];
	arp_rep->sender_mac[5] = ifr->ifr_hwaddr.sa_data[5];
	arp_rep->target_mac[0] = src_eth->h_source[0];
	arp_rep->target_mac[1] = src_eth->h_source[1];
	arp_rep->target_mac[2] = src_eth->h_source[2];
	arp_rep->target_mac[3] = src_eth->h_source[3];
	arp_rep->target_mac[4] = src_eth->h_source[4];
	arp_rep->target_mac[5] = src_eth->h_source[5];

	if(sendto(*sockfd, sendBuffer,42,0,(struct sockaddr *)&socket_address,sizeof(socket_address))< 0){
		perror("SEND: ");
		return err;
	}
	perror("SEND: ");
	return err;

}
int listen_arp(int *sockfd,int *iface_index,struct ifreq* ifr){
	char buff[100];
	memset(buff,0,sizeof(buff));
	int err =0;
	while(1){
		cout<<"Listen arp"<<endl;
		ssize_t len=recvfrom(*sockfd,buff,sizeof(buff),0,NULL,NULL);
		cout<<"Silent: "<<len<<endl;
		char ip[100];
		if(len==-1)
		{
			printf("error recv_from");
			return out(sockfd);
		}

		struct ethhdr *recv_req = (struct ethhdr *) buff;
		printf("%2X:%2X:%2X:%2x:%2X:%2X\n",recv_req->h_dest[0],recv_req->h_dest[1],recv_req->h_dest[2],recv_req->h_dest[3],recv_req->h_dest[4],recv_req->h_dest[5]);
		struct arp_header *arp_req = (struct arp_header *) (buff + 14);								
		inet_ntop(AF_INET,&(arp_req->target_ip),ip,INET_ADDRSTRLEN);
		printf("Destination IP: %s\n",ip);
		inet_ntop(AF_INET,&(arp_req->sender_ip),ip,INET_ADDRSTRLEN);
		printf("Source IP: %s\n",ip);
		if(ntohs(recv_req->h_proto)!= PROTO_ARP)
		{
			printf("error not arp packet");
			continue;
		}
		if(ntohs(arp_req->opcode)!=ARP_REQUEST)
		{
			continue;

		}
		err = send_arp_reply(sockfd,buff,ifr,iface_index);
	}
	return err;
}
int main(int argc ,char **argv){
	if(argc != 2) exit(0);

	char error[100];
	const char *interface_name = argv[1];

	int des;
	struct ifreq ifrr;
	memset(&ifrr,0,sizeof(ifrr));
	des = socket(AF_INET, SOCK_DGRAM, 0);
	ifrr.ifr_addr.sa_family = AF_INET;
	strncpy(ifrr.ifr_name , argv[1] , IFNAMSIZ-1);
	ioctl(des, SIOCGIFHWADDR, &ifrr);
	close(des);
	int sockfd;
	struct ifreq ifr;
	sockfd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ARP));
	strcpy(ifr.ifr_name,interface_name);
	int iface_index;
	if(sockfd < 0) {
		printf("socket creation failed");
		return 0;
	}
	perror(error);
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		return 0;
	}
	iface_index = ifr.ifr_ifindex; 	
	int x;
	if((x=socket_bind_arp(iface_index,&sockfd))  < 0) {
		perror(error);
		return 0;
	}
	printf("Here: %d\n",x);
	int val = listen_arp(&sockfd,&iface_index,&ifrr);
	if(val!=0) {
		printf("while listening: ");
		char error[100];
		perror(error);
		return 0;
	}
	printf("There\n");
}

