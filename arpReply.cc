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

#define MAC_LEN 6
#define IPV4_LEN 4
#define PROTO_ARP 0x806
#define ARP_REQUEST 0x01
#pragma pack(1)
struct arp_header {
	unsigned short hw_type;
	unsigned short protoctol;
	unsigned char hw_len;
	unsigned char prot_len;
	unsigned short opcode;
	unsigned char sha[MAC_LEN];
	unsigned char spa[IPV4_LEN];
	unsigned char tha[MAC_LEN];
	unsigned char tpa[IPV4_LEN];
};
#pragma pack()
using namespace std;

int get_if_info(const char *ifname, char *mac, int *ifindex){
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

	if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		goto out;
	}
	*ifindex = ifr.ifr_ifindex;
	printf("interface index is %d\n", *ifindex);

	if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		goto out;
	}

	memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LEN);
	err = 0;
out:
	if (sd > 0) {
		close(sd);
	}
	return err;
}
int clean(int* sockfd){
	printf("cleanup function called\n");
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
		perror("Bind");
		err = clean(sockfd);
		return err;
	}
	return err;
}
int send_arp_reply(int* sockfd, const char* buff,const char* mac, int *iface){
	int err = 0;
	struct sockaddr_ll s_addr;
	s_addr.sll_family = AF_PACKET;
	s_addr.sll_protocol = htons(ETH_P_ARP);
	s_addr.sll_ifindex = *iface;
	s_addr.sll_hatype = htons(ARPHRD_ETHER);
	s_addr.sll_pkttype = (PACKET_BROADCAST);
	s_addr.sll_halen = (PACKET_BROADCAST);
	s_addr.sll_halen = MAC_LEN;
	s_addr.sll_addr[6] = 0x00;
	s_addr.sll_addr[7] = 0x00;
	char sendBuffer[100];
	memset(sendBuffer,0,sizeof(sendBuffer));

	struct ethhdr* src_eth = (struct ethhdr*) buff;
	struct arp_header* src_arp = (struct arp_header*) (src_eth+1);
	struct ethhdr* send_eth = (struct ethhdr*) sendBuffer;
	struct arp_header* arp_rep = (struct arp_header*) (send_eth+1);
	memcpy(send_eth->h_dest,src_eth->h_source,MAC_LEN);
	memcpy(send_eth->h_source,mac,MAC_LEN);
	send_eth->h_proto = htons(ETH_P_ARP);
	arp_rep->hw_len = MAC_LEN;
	arp_rep->hw_type = htons(1);
	arp_rep->prot_len = IPV4_LEN;
	arp_rep->opcode = htons(ARPOP_REPLY);
	arp_rep->protoctol = htons(ETH_P_IP);
	memcpy(arp_rep->sha,src_eth->h_source,MAC_LEN);
	memcpy(arp_rep->tha,mac,MAC_LEN);
	memcpy(arp_rep->spa,src_arp->tpa,IPV4_LEN);
	memcpy(arp_rep->tpa,src_arp->spa,IPV4_LEN);

	if(sendto(*sockfd,sendBuffer,42,0,(struct sockaddr*)(&s_addr), sizeof(s_addr))<0){
		perror("SEND");
		return -1;
	}
	return err;
}

int listen_arp(int *sockfd,int *iface_index,const char* mac){
	char buff[100];
	memset(buff,0,sizeof(buff));
	int err =0;
	while(1){
		cout<<"Listen arp"<<endl;
		ssize_t len=recvfrom(*sockfd,buff,sizeof(buff),0,NULL,NULL);
		cout<<"Silent: "<<len<<endl;
		char ip[100];
		if(len==-1) {
			printf("error recv_from");
			return clean(sockfd);
		}

		struct ethhdr *recv_req = (struct ethhdr *) buff;
		printf("%2X:%2X:%2X:%2x:%2X:%2X\n",recv_req->h_dest[0],recv_req->h_dest[1],recv_req->h_dest[2],recv_req->h_dest[3],recv_req->h_dest[4],recv_req->h_dest[5]);
		struct arp_header *arp_req = (struct arp_header *) (buff + 14);								
		inet_ntop(AF_INET,&(arp_req->tpa),ip,INET_ADDRSTRLEN);
		printf("Destination IP: %s\n",ip);
		inet_ntop(AF_INET,&(arp_req->spa),ip,INET_ADDRSTRLEN);
		printf("Source IP: %s\n",ip);
		if(ntohs(recv_req->h_proto)!= PROTO_ARP) {
			printf("error not arp packet");
			continue;
		}
		if(ntohs(arp_req->opcode)!=ARP_REQUEST) {
			continue;
		}
		err = send_arp_reply(sockfd,buff,mac,iface_index);
	}
	return err;
}
int main(int argc ,char **argv){
	if(argc != 2) exit(0);

	char mac[MAC_LEN];
	int ifaceindex,sockfd;

	if((sockfd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ARP)))<0){
		perror("Socket Creation");
		return 1;
	}
	if(get_if_info(argv[1],mac,&ifaceindex)){
		printf("Error in loading mac\n");
		return 1;
	}
	if(socket_bind_arp(ifaceindex,&sockfd)){
		printf("error in binding arp\n");
		return 1;
	}
	if(listen_arp(&sockfd,&ifaceindex,mac)){
		printf("Cannot listen to arp");
		return 1;
	}
}
