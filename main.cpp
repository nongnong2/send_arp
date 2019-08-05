#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "send_arp.h"

struct ARP_PACKET{
    struct arp_header;
    struct arp_payload;
    struct ethernet_header;
};

void getMymac(uint8_t *mac_address){
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { /* handle error */ }
    }

    if (success) memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
}



void makeETH_request(struct ethernet_header *eth, uint8_t *mymac){
    uint8_t eth_dmac_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //broadcast
    uint8_t eth_tmac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //because sender doesn't know target mac
    memcpy(eth->ether_dhost, eth_dmac_broadcast,  6); //sender dst_mac is 0xFF * 6
    memcpy(eth_tmac, mymac, 6); //mymac is sendermac
    memcpy(eth->ether_shost, eth_tmac, sizeof(eth_tmac)); //targetmac is 0x00 * 6
    eth->ether_type = htons(0x0806); //ARP type == 0x0806
}// 14byte

void makeARP_header(struct arp_header *arph, uint16_t opcode){
    arph->arp_hw_type = htons(0x0001); //define type of net, ethernet is 0x0001
    arph->arp_protocol = htons(0x0800); //IPv4 is 0x0800
    arph->arp_hw_size = 0x6; // length of mac is 6
    arph->arp_protocol_size = 0x4; // length of ip is 4;
    arph->arp_opcode =htons(opcode); //ARP_request == 0x0001, ARP_reply ==0x0002
}

void makeARP_request_payload(struct arp_payload *apl, uint8_t *sendermac, char *senderip, char *targetIP){
    in_addr ip_addr; //in_addr changes str ip to ip which has long type
    int32_t sender_ip_arp;
    int32_t target_ip_arp;

    memcpy(apl->sender_mac, sendermac, sizeof (sendermac)); //in ARP sendermac is my mac
    inet_aton(senderip, &ip_addr); // change string ip to long type ip
    sender_ip_arp = ip_addr.s_addr;
    sender_ip_arp = ip_addr.s_addr;
    memcpy(apl->sender_ip, &sender_ip_arp, 4);// In ARP sender ip is my ip
    // In ARP_request, sender doesn't know target mac
    memset(apl->target_mac, 0, 6);
    inet_aton(targetIP, &ip_addr);
    target_ip_arp = ip_addr.s_addr;
    memcpy(apl->target_ip, &target_ip_arp, 4); //define target ip
}//arp protocol find mac use ip(sender can find target's mac by using ARP protocol with target's IP)
//define sender mac, ip / target mac, ip

int main()
{
    char device[20];
    uint8_t senderIP[4] = {0xc0,0xa8, 0x01, 0x0b}; //my ip 192.168.1.11
    uint8_t targetIP[4] = {0xc0,0xa8,0x00,0xfe}; //192.168.0.253
    uint8_t mymac[6] = {0x08,0x00,0x27,0xa1,0x1a,0x2c};
    u_char flush[42] = {0};
    char errbuf[1000];

    struct ethernet_header eth;
    struct arp_header arh;
    struct arp_payload arpl;
    struct ARP_PACKET arp_packet;

    //input ethernet header
    makeETH_request(&eth, mymac);
    memcpy(flush, &eth, sizeof (ethernet_header));
    //input arp header
    makeARP_header(&arh, ARPOP_REQUEST);
    memcpy(&flush[14], &arh, sizeof (arp_header));  
    memcpy(&flush[22], mymac, 6);
    memcpy(&flush[28], senderIP, 4);
    mempcpy(&flush[38], targetIP, 4);
    //input arp_payload


    for(int i = 1; sizeof(flush) >= i; i++){
        printf("%02X ", flush[i - 1]);
        if(i % 16 == 0){
            printf("\n");
        }
    }
    printf("End!\n!");
    pcap_t* handle = pcap_open_live("enp0s3",1000,1,1000,errbuf);
    pcap_inject(handle, (u_char*)flush, sizeof(flush));


//    for(int i = 0; sizeof(flush) > i; i++){
//        printf("02X", flush[i]);
//        if(i % 15 == 0){printf("\n");}
//    }

}
