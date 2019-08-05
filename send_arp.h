#ifndef SEND_ARP_H
#define SEND_ARP_H
#include <pcap.h>
#include <arpa/inet.h>

#endif // SEND_ARP_H
struct arp_header{
    u_int16_t arp_hw_type;
    u_int16_t arp_protocol;
    u_int8_t arp_hw_size;
    u_int8_t arp_protocol_size;
    u_int16_t arp_opcode;

#define ARPOP_REQUEST 0x0001
#define ARPOP_REPLY 0x0002
};

struct arp_payload{
    u_int8_t sender_mac[6];
    u_int8_t sender_ip[4];
    u_int8_t target_mac[6];
    u_int8_t target_ip[4];
};

struct ethernet_header{
    u_int8_t ether_dhost[6];
    u_int8_t ether_shost[6];
    u_int16_t ether_type;
};


