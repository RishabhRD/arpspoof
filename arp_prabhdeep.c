#include <sys/socket.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <string.h>
#include <stdio.h>
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
int out(int *sockfd){
	printf("out function called CLEANUP SOCKET");
	close(*sockfd);
	return -1;
}
int socket_bind_arp(int iface_index,int *sockfd){
	printf("entered socket_bind_arp\n");
	int err =0;

	printf("starting binding of socket for listening to arp request");

	struct sockaddr_ll sll;
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = iface_index;

	if(bind(*sockfd,(struct sockaddr*) &sll,sizeof(struct sockaddr_ll))<0){
		printf("error in binding");
		err = out(sockfd);
		return err;
	}
	return err;

}
int send_arp_reply(int *sockfd,const char *buff,const char * src_mac,const char * ipv4_addr,int *ifaceindex){
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

	struct ethhdr *send_req = (struct ethhdr *) buff;
	struct arp_header *arp_req = (struct arp_header *) (buff + 14);

	memset(arp_req->target_mac,0,6);

	memcpy(send_req->h_source, src_mac, MAC_LENGTH);
	memcpy(arp_req->sender_mac, src_mac, MAC_LENGTH);
	memcpy(socket_address.sll_addr, src_mac, MAC_LENGTH);
	send_req->h_proto = htons(ETH_P_ARP);
	in_addr_t src_ip;
	in_addr_t dst_ip;
	inet_pton(AF_PACKET,ipv4_addr,&(src_ip));
	dst_ip = arp_req->sender_ip;

	memcpy(&(arp_req->sender_ip), &src_ip,sizeof(src_ip));
	memcpy(&(arp_req->target_ip), &dst_ip,sizeof(dst_ip));

	if(sendto(*sockfd, buff,42,0,(struct sockaddr *)&socket_address,sizeof(socket_address))< 0){
		err = -1;
		return err;
	}
	return err;

}
int listen_arp(int *sockfd,const char *mac_addr,const char *ip_addr,int *iface_index){
	printf("listen_arp");
	char buff[100];
	memset(buff,0,sizeof(buff));
	int err =0;
	while(1){
		ssize_t len=recvfrom(*sockfd,buff,sizeof(buff),0,NULL,NULL);
		if(len==-1)
		{
			printf("error recv_from");
			return out(sockfd);
		}

		struct ethhdr *recv_req = (struct ethhdr *) buff;
		struct arp_header *arp_req = (struct arp_header *) (buff + 14);								
		if(ntohs(recv_req->h_proto)!= PROTO_ARP)
		{
			printf("error not arp packet");
			return out(sockfd);
		}
		if(ntohs(arp_req->opcode)!=ARP_REQUEST)
		{
			printf("not a request packet");
			return out(sockfd);

		}
		err = send_arp_reply(sockfd,buff,mac_addr,ip_addr,iface_index);
	}
	return err;
}
int main(int argc ,char **argv){
	printf("%d\n",argc);
	if(argc != 4) exit(0);

	const char *interface_name = argv[3];
	const char *mac_addr = argv[1];
	const char *ipv4_addr = argv[2];

	int sockfd;
	struct ifreq ifr;
	sockfd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ARP));
	strcpy(ifr.ifr_name,interface_name);
	int iface_index;
	if(sockfd < 0) {
		printf("socket creation failed");
		return 0;
	}
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		return 0;
	}
	iface_index = ifr.ifr_ifindex; 	
	if(socket_bind_arp(iface_index,&sockfd)  != 0) {
		char error[100];
		perror(error);
		return 0;
	}
	printf("Here\n");
	int val = listen_arp(&sockfd,mac_addr,ipv4_addr,&iface_index);
		if(val!=0) {
			printf("while listening: ");
			char error[100];
			perror(error);
			return 0;
		}
		printf("There\n");
}

