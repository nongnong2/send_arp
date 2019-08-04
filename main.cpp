#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void print_ip(uint32_t ip){
    printf("%d.%d.%d.%d\n",
           (ntohl(ip) & 0xFF000000) >> 24,
           (ntohl(ip) & 0x00FF0000) >> 16,
           (ntohl(ip) & 0x0000FF00) >> 8,
           (ntohl(ip) & 0x000000FF)
           );
}

typedef struct ARP_HEADER{
    uint16_t HardwareType; //if Ethernet it is 0x0001
    uint16_t ProtocolType; //if IPv4, it is 0x0800
    uint8_t HwAddLength;   //define length of mac(Ethernet 6 byte)
    uint8_t IPAddLength;   //define length of IP(IPv4 is 4byte)
    uint16_t OPcode;       //ARP Request == 0x0001, ARP Reply == 0x0002
    uint8_t SenderHwAdd[6]; //Sender's Mac
    uint32_t SenderIPAdd;    //Sender's IP
    uint8_t TargetHwAdd[6]; //Target Mac
    uint32_t TargetIPAdd;    //Target IP
}ARP_HEADER;

typedef struct Ethernet{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
} Ethernet;

typedef struct ARP_PACKET
{
    Ethernet eth_hdr;
    ARP_HEADER arp_hdr;
};
using namespace std;


int main()
{
    ARP_PACKET arp_bc_packet;
    char device[100];
    uint8_t Mymacaddress[6];
//    uint8_t MyIP[4];
//    uint8_t TargetIP[20];
    uint8_t TargetMac[6];
//    uint8_t gatewayIP[20]; //for attacker

    //find my mac address
    int sock;
    struct ifreq ifr; //#include <net/if.h>
    struct sockaddr_in *sin; // 16byte, sa_family(2 byte): it divide type of address, sa_data(14byte): save real address

    sock = socket(AF_INET, SOCK_STREAM, 0); //int socket(int domain, int type, int protocol);
    if(sock < 0){
        printf("It is error!");
        return 0;
    }
    memcpy(device, "enp0s3", 7);
    strcpy(ifr.ifr_name, device); //get interface name

    //get MAC address
    if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0){
        printf("It is error!");
        return 0;
    }

    memcpy(Mymacaddress,ifr.ifr_hwaddr.sa_data, 6); // 08:00:27:00:67:41
    memset(TargetMac, 0xFF, 6);

    //ARP REQUEST#1 : make ethernet header & ARP header
    struct Ethernet bcEth;
    memcpy(bcEth.dst_mac, Mymacaddress, 6);
    memcpy(bcEth.src_mac, TargetMac, 6);
    bcEth.type = htons(0x0806);

    //ARP Header
    struct ARP_HEADER bcARP;
    bcARP.HardwareType = htons(0x0001);
    bcARP.ProtocolType = htons(0x800);
    bcARP.HwAddLength = 0x06;
    bcARP.IPAddLength = 0x04;
    bcARP.OPcode = htons(0x0001); //ARP Request
    memcpy(bcARP.SenderHwAdd, Mymacaddress, 6);
    bcARP.SenderIPAdd = ntohl(0xc0a80129); //Sender IP is 192.168.1.41 0xc0a80129
    memset(bcARP.TargetHwAdd, 0, 6);
    bcARP.TargetIPAdd = ntohl(0xc0a802c4); //targetip is 192.168.2.196 0xc0a802c4


    memcpy(&arp_bc_packet.arp_hdr, &bcEth, sizeof(Ethernet));






/*
    //get IP address
    if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0){
        printf("It is error!");
        return 0;
    }; //ioctl function order to move and close
    sin = (struct sockaddr_in*)&ifr.ifr_addr; //get address
    (uint32_t)sin->sin_addr.s_addr; //get sender ip from structure sockaddr_in
*/
}
