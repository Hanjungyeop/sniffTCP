#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
#define MAX_MSG_LEN 64

// Ethernet Header
struct ethheader {
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;
};

// IP Header
struct ipheader {
    unsigned char      iph_ihl:4,
                       iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3,
                       iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct in_addr     iph_sourceip;
    struct in_addr     iph_destip;
};

// TCP Header
struct tcpheader {
    unsigned short th_sport;
    unsigned short th_dport;
    unsigned int   th_seq;
    unsigned int   th_ack;
    unsigned char  th_offx2;
    unsigned charr  th_flags;
    unsigned short th_win;
    unsigned short th_sum;
    unsigned short th_urp;
};

void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    struct ethheader* eth = (struct ethheader*)packet;
    if (ntohs(eth->ether_type) != 0x0800) return; // Only IP packets
    struct ipheader* ip_hdr = (struct ipheader*)(packet + sizeof(struct ethheader));
    if (ip_hdr->iph_protocol != 6) return; // Only TCP (protocol number 6)

    int ip_hdr_len = ip_hdr->iph_ihl * 4;
    struct tcpheader* tcp_hdr = (struct tcpheader*)(packet + sizeof(struct ethheader) + ip_hdr_len);
    int tcp_hdr_len = ((tcp_hdr->th_offx2 & 0xF0) >> 4) * 4;
    const u_char* payload = packet + sizeof(struct ethheader) + ip_hdr_len + tcp_hdr_len;
    int payload_len = ntohs(ip_hdr->iph_len) - ip_hdr_len - tcp_hdr_len;

    printf("\n[+] TCP Packet Captured:\n");
    printf("    Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
        eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("    Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
        eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("    Src IP  : %s\n", inet_ntoa(ip_hdr->iph_sourceip));
    printf("    Dst IP  : %s\n", inet_ntoa(ip_hdr->iph_destip));
    printf("    Src Port: %d\n", ntohs(tcp_hdr->th_sport));
    printf("    Dst Port: %d\n", ntohs(tcp_hdr->th_dport));

    if (payload_len > 0) {
        printf("    Message : ");
        for (int i = 0; i < payload_len && i < MAX_MSG_LEN; i++) {
            if (isprint(payload[i])) putchar(payload[i]);
            else putchar('.');}
        printf("\n");}}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;}
    pcap_loop(handle, 10, packet_handler, NULL);
    pcap_close(handle);
    return 0;}
