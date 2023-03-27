#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
/*
 *  Ethernet II header
 *  Static header size: 14 bytes
 */
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN		6
#endif

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#endif

#ifndef IPPROTOCOL_TCP
#define IPPROTOCOL_TCP		0x06	/* TCP protocol */
#endif
/*
 *  IPv4 header
 *  Internet Protocol, version 4
 *  Static header size: 20 bytes
 */
struct libnet_ipv4_hdr
{
    u_int8_t ip_hvl;      /* header version & length*/
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    //struct in_addr ip_src, ip_dst;
    /* source and dest address */
    u_int8_t ip_src[4];
    u_int8_t ip_dst[4];
};


/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t th_off;        /* data offset & (unused) */
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		//here!
		struct libnet_ethernet_hdr *eth_head;
                eth_head = (struct libnet_ethernet_hdr *)packet;

                if(ntohs(eth_head->ether_type) != ETHERTYPE_IP) continue; //if next protocol is not IP, then continue
                
		packet += 14;
                struct libnet_ipv4_hdr *ip_head;
                ip_head = (struct libnet_ipv4_hdr *)packet;
                
		if(ip_head->ip_p != IPPROTOCOL_TCP) continue; //if next protocol is not TCP, then continue
                
		packet += ((ip_head->ip_hvl) & 0x0F) * 4;
                struct libnet_tcp_hdr *tcp_head;
                tcp_head = (struct libnet_tcp_hdr *)(packet);

		//print Src and Dst MAC address 
                printf("---------------\n");
                int i;
		printf("[ETHERNET]\n");
                printf("Src MAC: ");
                for(i=0; i<6; i++)
                {
                	printf("%02X ", eth_head->ether_shost[i]);
                }
                printf(" /  Dst MAC: ");
                for(i=0; i<6; i++)
                {
                	printf("%02X ", eth_head->ether_dhost[i]);
                }

                printf("\n");
		
		//print Src and Dst IP address
		printf("\n[IP]\n");
		printf("Src IP: %d.%d.%d.%d / ", ip_head->ip_src[0], ip_head->ip_src[1], ip_head->ip_src[2], ip_head->ip_src[3]);
		printf("Dst IP: %d.%d.%d.%d\n", ip_head->ip_dst[0], ip_head->ip_dst[1], ip_head->ip_dst[2], ip_head->ip_dst[3]);
                
		//print Src and Dst Port
		printf("\n[TCP]\n");
		printf("Src Port: %d  /  Dst Port : %d\n", ntohs(tcp_head->th_sport), ntohs(tcp_head->th_dport));
		packet += (tcp_head->th_off >> 4)* 4;	
		
		//print data
		printf("\n[Data]\n");
		int numofdata = ntohs(ip_head->ip_len) - ((ip_head->ip_hvl & 0x0F) * 4) - (tcp_head->th_off >> 4) * 4;
		if(numofdata > 10) numofdata = 10;
		for(i=0; i<numofdata; i++)
		{
			printf("%02X ", *packet);
			packet+=1;
		}
		printf("\n");
	}
	pcap_close(pcap);
}
