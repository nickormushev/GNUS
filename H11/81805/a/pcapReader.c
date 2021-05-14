#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <err.h>
#include <arpa/inet.h>

#define SIZE_ETHERNET 14
#define NUMBER_OF_IP_OCTETS 4
#define PSEUDO_PAYLOAD_HEADER_SIZE 12

typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
typedef struct ethernet_header_s {
    uint8_t ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    uint8_t ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    uint16_t ether_type; /* IP? ARP? RARP? etc */
} ethernet_header_t;

/* IP header */
typedef struct ip_header_s {
    uint8_t ip_vhl;		    /* version << 4 | header length >> 2 */
    uint8_t ip_tos;		    /* type of service */
    uint16_t ip_len;	    /* total length */
    uint16_t ip_id;		    /* identification */
    uint16_t ip_off;	    /* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    uint8_t ip_ttl;		    /* time to live */
    uint8_t ip_p;		    /* protocol */
    uint16_t ip_sum;		/* checksum */
    struct in_addr ip_src, ip_dst; /*[> source and dest address <]*/
} ip_header_t;
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef uint32_t tcp_seq;

typedef struct tcp_header_s {
    uint16_t th_sport;	/* source port */
    uint16_t th_dport;	/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
    uint8_t th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    uint8_t th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    uint16_t th_win;		/* window */
    uint16_t th_sum;		/* checksum */
    uint16_t th_urp;		/* urgent pointer */
} tcp_header_t;

typedef struct pseudo_header_s {
    struct in_addr ip_src, ip_dst; /*[> source and dest address <]*/
    uint8_t rsvd;
    uint8_t ip_p;
    uint16_t tcp_segemnt_length;
} pseudo_header_t;

pseudo_header_t new_pseudo_header(ip_header_t ip) {
    pseudo_header_t pseudo;
    pseudo.ip_dst = ip.ip_dst;
    pseudo.ip_src = ip.ip_src;
    pseudo.ip_p = ip.ip_p;
    pseudo.rsvd = 0x0;
    pseudo.tcp_segemnt_length = htons(ntohs(ip.ip_len) - IP_HL(&ip) * 4);

    return pseudo;
}

void inet_printer (struct in_addr addr) {
    for (int i = 0; i < NUMBER_OF_IP_OCTETS; ++i) {
        if(i != 3) {
            printf("%d.", addr.s_addr & 0x000000ff);
        } else {
            printf("%d ", addr.s_addr & 0x000000ff);
        }
        addr.s_addr = addr.s_addr >> 8;
    }
}

void macToString(uint8_t const mac[ETHER_ADDR_LEN]) {
    for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
        if( i != ETHER_ADDR_LEN - 1) {
            printf("%02X:", mac[i]);
        } else {
            printf("%02X ", mac[i]);
        }
    }
}

uint32_t calculateChecksum(uint16_t* header, uint8_t size, uint32_t checksum) {

    for (int i = 0; i < size/2; ++i) {
        checksum += ntohs(header[i]);
    }

    if(size % 2 == 1) {
        checksum += ntohs(header[size/2]);
    }

    uint16_t top = checksum >> 16;
    while(top != 0x0000) {
        checksum = checksum & 0x0000ffff;
        checksum += top;
        top = checksum >> 16;
    }

    return checksum;
}

bool validTCPHeader(ip_header_t ip, uint16_t* tcpSegment) {
    pseudo_header_t pseudo = new_pseudo_header(ip);
    uint16_t ip_packet_len = ntohs(ip.ip_len);
    uint16_t tcp_segement_length = ip_packet_len - IP_HL(&ip) * 4;

    uint32_t checksum = calculateChecksum((uint16_t*) &pseudo, PSEUDO_PAYLOAD_HEADER_SIZE, 0x0);
    checksum = calculateChecksum(tcpSegment, tcp_segement_length, checksum);

    return checksum == 0x0000ffff;
}

bool validIPHeader(ip_header_t ip) {
    return calculateChecksum((uint16_t*) &ip, IP_HL(&ip) * 4, 0) == 0x0000ffff;
}

void printHeaders(tcp_header_t tcp, ethernet_header_t eth, ip_header_t ip, 
        char* type, uint8_t* packet) {

    macToString(eth.ether_shost);
    macToString(eth.ether_dhost);
    printf("0x%04x ", ntohs(eth.ether_type));

    if(!validIPHeader(ip)) {
        printf("bad_csum\n");
        return;
    }

    inet_printer(ip.ip_src);
    inet_printer(ip.ip_dst);
    printf("%d ", ip.ip_p);

    uint16_t* tcp_segment = (uint16_t*)(packet + SIZE_ETHERNET + IP_HL(&ip) * 4);
    if(!validTCPHeader(ip, tcp_segment)) {
        printf("bad_csum\n");
        return;
    }

    printf("%d %d %s", ntohs(tcp.th_sport), ntohs(tcp.th_dport), type);

    printf("\n");
}

int main(int argc, char *argv[]) {

    if(argc < 2) {
        errx(1, "Not enough arguments");
    }

    if(argc > 2) {
        errx(1, "Too many arguments");
    }

    int fd = open(argv[1], O_RDONLY);

    if(fd < 0) {
        err(2, "Failed to open provided file");
    }

    pcap_hdr_t global_header;
    pcaprec_hdr_t local_header;
    const ethernet_header_t* eth;
    const ip_header_t* ip;
    const tcp_header_t* tcp; /* The TCP header */
    uint8_t* packet;

    if(read(fd, &global_header , sizeof(global_header)) < 0) {
        err(3, "error reading global header from pcap file");
    }

    while(read(fd, &local_header, sizeof(local_header)) > 0) {

        packet = (uint8_t*) malloc(local_header.incl_len);

        if(read(fd, packet, local_header.incl_len) < 0) {
            err(3, "error reading packet data from pcap file");
        }

        eth = (ethernet_header_t*)(packet);

        ip = (ip_header_t*)(packet + SIZE_ETHERNET);
        uint8_t size_ip = IP_HL(ip) * 4;
        if (size_ip < 20) {
            err(4, "* Invalid IP header length: %u bytes\n", size_ip);
        }

        tcp = (tcp_header_t*)(packet + SIZE_ETHERNET + size_ip);
        uint8_t size_tcp = TH_OFF(tcp) * 4;
        if (size_tcp < 20) {
            err(5, "* Invalid TCP header length: %u bytes\n", size_tcp);
        }

        if(tcp->th_flags == 0x00) {
            printHeaders(*tcp, *eth, *ip, "Null", packet);
        } else if(tcp->th_flags == 0x29) {
            printHeaders(*tcp, *eth, *ip, "Xmas", packet);
        } 

        memset(packet, 0, local_header.incl_len);
    }

    return 0;
}
