#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include "libnet-headers.h"

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
		struct libnet_ether_hdr *eth_head;
                eth_head = (struct libnet_ether_hdr *)packet;
                if(eth_head->ether_type == 0x0800)
                {
                        packet += 14;
                        struct libnet_ipv4_hdr *ip_head;
                        ip_head = (struct libnet_ipv4_hdr *)packet;
                        if(ip_head->ip_p == 0x06)
                        {
                                packet += ip_head->ip_hl * 4;
                                struct libnet_tcp_hdr *tcp_head;
                                tcp_head = (struct libnet_tcp_hdr *)(packet);
                                printf("---------------\n");
                                int i;
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
                                printf("Src IP: %s  /  Dst IP: %s\n", inet_ntoa(ip_head->ip_src), inet_ntoa(ip_head->ip_dst));
                                printf("Src Port: %d  /  Dst Port : %d\n", ntohs(tcp_head->th_sport), ntohs(tcp_head->th_dport));
				packet += tcp_head->th_off * 4;
				printf("Data: ");
				for(i=0; i<10; i++)
				{
					printf("%02X ", *packet);
					packet+=1;
				}
				printf("\n");
                        }
                }
	}
	pcap_close(pcap);
}
