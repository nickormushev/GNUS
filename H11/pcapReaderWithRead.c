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

#define SIZE_ETHERNET 14
#define NUMBER_OF_IP_OCTETS 4

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
	uint8_t ether_type[2]; /* IP? ARP? RARP? etc */
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

void MacToString(uint8_t const mac[ETHER_ADDR_LEN]) {
    for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
        if( i != ETHER_ADDR_LEN - 1) {
            printf("%02X:", mac[i]);
        } else {
            printf("%02X ", mac[i]);
        }
    }
}

bool validIpHeader(uint16_t* ip, uint8_t size_ip) {
    uint32_t checksum;

    for (int i = 0; i < size_ip/2; ++i) {
        checksum += ip[i];
    }

    uint16_t top = checksum >> 16;
    while(top != 0x0000) {
        top = checksum >> 16;
        checksum = checksum & 0x0000ffff;
        checksum += top;
    }
    
    return checksum == 0x0000ffff;
}

void printHeaders(tcp_header_t tcp, ethernet_header_t eth, ip_header_t ip, 
        char* type, uint8_t size_ip) {

    MacToString(eth.ether_shost);
    MacToString(eth.ether_dhost);
    printf("0x%02x%02x ", eth.ether_type[0], eth.ether_type[1]);
    
    if(!validIpHeader((uint16_t*) & ip, size_ip)) {
        printf("bad_csum ");
    }

    inet_printer(ip.ip_src);
    inet_printer(ip.ip_dst);
    printf("%d ", ip.ip_p);

    printf("%d %d %s", tcp.th_sport, tcp.th_dport, type);

    printf("\n");
}

int main(int argc, char *argv[]) {
   
    int fd = open("./foo.pcap", O_RDONLY);

    pcap_hdr_t global_header;
    pcaprec_hdr_t local_header;
    ethernet_header_t eth;
    ip_header_t ip;
    tcp_header_t tcp; /* The TCP header */
    uint8_t* packet;

    if(read(fd, &global_header , sizeof(global_header)) < 0) {
        err(2, "error reading global header from pcap file");
    }

    printf("magic %04X\n", global_header.magic_number);
    printf("libpcap version is: %d.%d\n", global_header.version_major, global_header.version_minor);

    while(read(fd, &local_header, sizeof(local_header)) > 0) {
        int next_packet = lseek(fd, 0, SEEK_CUR) + local_header.incl_len;
        
        if(read(fd, &eth, SIZE_ETHERNET) < 0) {
            err(3, "Failed reading ethernet");
        }

        if(read(fd, &ip, sizeof(ip)) < 0) {
            err(4, "Failed reading ip");
        }

        uint8_t size_ip = IP_HL(&ip) * 4;
        if (size_ip < 20) {
            err(1, "* Invalid IP header length: %u bytes\n", size_ip);
        }

        if(read(fd, &tcp, sizeof(tcp)) < 0) {
            err(5, "Failed reading tcp");
        }

        uint8_t size_tcp = TH_OFF(&tcp) * 4;
        //if (size_tcp < 20) {
        //    err(1, "* Invalid TCP header length: %u bytes\n", size_tcp);
        //}

        if(size_ip - sizeof(ip) > 0) {
            lseek(fd, size_ip + sizeof(ip) , SEEK_CUR);
        }

        ///*if(tcp->th_flags == 0x00) {*/
        //    /*printHeaders(*tcp, *eth, *ip, "Null", packet, size_ip);*/
        ///*} else if(0x29 == tcp->th_flags) {*/
        //    /*printHeaders(*tcp, *eth, *ip, "Xmas", packet, size_ip);*/
        ///*} */
        //
        printHeaders(tcp, eth, ip, "Xmas", size_ip);
        lseek(fd, next_packet, SEEK_SET);
    }

    return 0;
}
