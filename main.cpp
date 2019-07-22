#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

struct ip_hdr {
    unsigned int ihl:4;
    unsigned int version:4;

    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint8_t saddr[4];
    uint8_t daddr[4];
  };
/* TCP header */

struct tcp_hdr {
    u_int16_t th_sport;	/* source port */
    u_int16_t th_dport;	/* destination port */
    u_int th_seq;		/* sequence number */
    u_int th_ack;		/* acknowledgement number */
    u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
};

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(uint8_t* mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
void print_ip(uint8_t* ip) {
    printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
}
void print_port(uint16_t port) {
    printf("%d\n", ntohs(port));
}


int main(int argc, char* argv[]) {

  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

    struct pcap_pkthdr* header;
    const u_char* packet;
    struct ether_header *eth_h;
    struct ip_hdr *ip_h;
    struct tcp_hdr *tcp_h;
    const u_char* payload;

  while (true) {
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    //print_mac(uint8_t* packet[0]);

    eth_h = (struct ether_header*)packet;
    if(ntohs(eth_h->ether_type) != ETHERTYPE_IP){
        continue;
    }
    printf("=============[MAC]============\n");
    print_mac(eth_h->ether_dhost);
    print_mac(eth_h->ether_shost);
    printf("%02x\n\n", eth_h->ether_type);

    ip_h = (struct ip_hdr*)(packet+14);
    printf("=============[IP]============\n");
    print_ip(ip_h->daddr);
    print_ip(ip_h->saddr);
    printf("\n");

    tcp_h = (struct tcp_hdr*)(packet+14+20);
    printf("=============[TCP]============\n");
    print_port(tcp_h->th_dport);
    print_port(tcp_h->th_sport);
    printf("\n");

    payload = (u_char *)(packet+14+20+20);
    printf("===========[TCP_Data]==========\n");
    for(int i = 0; i < 10; i++){
        printf("%02X ",payload[i]);
    }
    printf("\n\n");
    //printf("%u bytes captured\n", header->caplen);
  }

  pcap_close(handle);
  return 0;
}
