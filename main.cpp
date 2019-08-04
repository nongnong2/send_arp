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

typedef struct ARP_HEADER{
    uint16_t HardwareType; //if Ethernet it is 0x0001
    uint16_t ProtocolType; //if IPv4, it is 0x0800
    uint8_t HwAddLength;   //define length of mac(Ethernet 6 byte)
    uint8_t IPAddLength;   //define length of IP(IPv4 is 4byte)
    uint16_t OPcode;       //ARP Request == 0x0001, ARP Reply == 0x0002
    uint8_t SenderHwAdd[6]; //Sender's Mac
    uint8_t SenderIPAdd[4];    //Sender's IP
    uint8_t TargetHwAdd[6]; //Target Mac
    uint8_t TargetIPAdd[4];    //Target IP
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
    char errbuf[100];
    uint8_t Mymacaddress[6];
//    uint8_t MyIP[4];
//    uint8_t TargetIP[20];
    uint8_t TargetMac[6];
//    uint8_t gatewayIP[20]; //for attacker

    //find my mac address
    int sock;
    struct ifreq ifr; //#include <net/if.h>
    struct sockaddr_in *sin; // 16byte, sa_family(2 byte): it divide type of address, sa_data(14byte): save real address
    u_char flush[50];
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

    memcpy(Mymacaddress,ifr.ifr_hwaddr.sa_data, 6); //  my mac 08:00:27:00:67:41
    memset(TargetMac, 0xFF, 6);

    //ARP REQUEST#1 : make ethernet header & ARP header
    struct Ethernet bcEth;
    memcpy(bcEth.src_mac, Mymacaddress, 6);
    memcpy(bcEth.dst_mac, TargetMac, 6);

    bcEth.type = htons(0x0806);

    //ARP Header
    struct ARP_HEADER ARP_request;
    ARP_request.HardwareType = htons(0x0001);
    ARP_request.ProtocolType = htons(0x800);
    ARP_request.HwAddLength = 0x06;
    ARP_request.IPAddLength = 0x04;
    ARP_request.OPcode = htons(0x0001); //ARP Request
    memcpy(ARP_request.SenderHwAdd, Mymacaddress, 6);
    //Sender IP is 192.168.1.41 0xc0a80129
    uint32_t s = ntohl(0xc0a80102);
    memcpy(ARP_request.SenderIPAdd, &s, 4);
    memset(ARP_request.TargetHwAdd, 0x00, 6);
    s = ntohl(0xc0a800fe); //targetip is 192.168.2.196 0xc0a802c4
    memcpy(ARP_request.TargetIPAdd, &s, 4);
    memcpy(&arp_bc_packet.eth_hdr, &bcEth, sizeof(Ethernet));
    memcpy(&arp_bc_packet.arp_hdr, &ARP_request, sizeof(ARP_HEADER));

    memcpy(flush, &arp_bc_packet, sizeof(ARP_PACKET));

    for (int i = 0; sizeof(ARP_PACKET) > i; i++) {
        if(i == 0 ){
            printf("%02x ",flush[i]);
            continue;
        }
        if(i % 15 == 0)printf("\n");
        printf("%02x ",flush[i]);
    }

    pcap_t* handle = pcap_open_live(device, 1000, 1, 1000, errbuf);
    pcap_inject(handle, (u_char*)flush, sizeof(flush));



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
