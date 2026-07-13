#define _DEFAULT_SOURCE

#include "sniff.h"
#include "stats.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>

static pcap_t *capture;
static char capture_iface[IF_NAMESIZE];

int sniff_open(const char *iface)
{
    char error[PCAP_ERRBUF_SIZE];

    if (iface == NULL || strlen(iface) >= sizeof(capture_iface)) {
        return -1;
    }
    if (capture != NULL) {
        return 0;
    }
    capture = pcap_open_live(iface, BUFSIZ, 1, 1000, error);
    if (capture == NULL) {
        fprintf(stderr, "sniff: %s\n", error);
        return -1;
    }
    if (pcap_setnonblock(capture, 1, error) == -1) {
        fprintf(stderr, "sniff: %s\n", error);
        pcap_close(capture);
        capture = NULL;
        return -1;
    }
    if (pcap_datalink(capture) != DLT_EN10MB) {
        fprintf(stderr, "sniff: bad datalink\n");
        pcap_close(capture);
        capture = NULL;
        return -1;
    }
    strcpy(capture_iface, iface);
    return 0;
}

void sniff_close(void)
{
    if (capture != NULL) {
        pcap_close(capture);
        capture = NULL;
    }
}

int sniff_fd(void)
{
    return capture == NULL ? -1 : pcap_get_selectable_fd(capture);
}

int sniff_handle_packet(void)
{
    struct pcap_pkthdr *header;
    const unsigned char *packet;
    struct iphdr *ip;
    char source[INET_ADDRSTRLEN];
    int result;

    if (capture == NULL) {
        return -1;
    }
    result = pcap_next_ex(capture, &header, &packet);
    if (result <= 0) {
        return result == 0 ? 0 : -1;
    }
    if (header->caplen < 14 + sizeof(struct iphdr) ||
        ((packet[12] << 8) | packet[13]) != ETHERTYPE_IP) {
        return 0;
    }
    ip = (struct iphdr *)(packet + 14);
    if (ip->version != 4 || inet_ntop(AF_INET, &ip->saddr, source, sizeof(source)) == NULL) {
        return 0;
    }
    return stats_increment(capture_iface, source);
}
