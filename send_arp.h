#ifndef SEND_ARP_H
#define SEND_ARP_H
#include <pcap.h>
#include <arpa/inet.h>

#endif // SEND_ARP_H
struct arp_header{
    uint16_t arp_hw_type;
    uint16_t arp_protocol;
    uint8_t arp_hw_size;
    uint8_t arp_protocol_size;
    uint16_t arp_opcode;

#define ARPOP_REQUEST 0x0001
#define ARPOP_REPLY 0x0002
};

struct arp_payload{
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

struct ethernet_header{
    uint8_t ether_dhost[6];
    uint8_t ether_shost[6];
    uint16_t ether_type;
};



