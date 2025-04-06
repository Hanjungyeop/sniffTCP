#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <ctype.h>
#include <string.h>

#define MAX_MSG_LEN 64

void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    struct ether_header* eth = (struct ether_header*)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
    if (ip_hdr->ip_p != IPPROTO_TCP) return;

    int ip_hdr_len = ip_hdr->ip_hl * 4;
    struct tcphdr* tcp_hdr = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_hdr_len);
    int tcp_hdr_len = tcp_hdr->th_off * 4;

    const u_char* payload = packet + sizeof(struct ether_header) + ip_hdr_len + tcp_hdr_len;
    int payload_len = ntohs(ip_hdr->ip_len) - ip_hdr_len - tcp_hdr_len;

    printf("\n[+] TCP Packet Captured:\n");
    printf("    Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
        eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("    Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
        eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    printf("    Src IP  : %s\n", inet_ntoa(ip_hdr->ip_src));
    printf("    Dst IP  : %s\n", inet_ntoa(ip_hdr->ip_dst));
    printf("    Src Port: %d\n", ntohs(tcp_hdr->th_sport));
    printf("    Dst Port: %d\n", ntohs(tcp_hdr->th_dport));

    if (payload_len > 0) {
        printf("    Message : ");
        for (int i = 0; i < payload_len && i < MAX_MSG_LEN; i++) {
            if (isprint(payload[i])) putchar(payload[i]);
            else putchar('.');
        }
        printf("\n");
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }
    pcap_loop(handle, 10, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}
