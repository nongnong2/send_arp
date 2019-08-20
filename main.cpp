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

void *t_function(void *data){
    pid_t pid;
    pthread_t tid;
    pid = getpid();
    tid = pthread_self();
    char* thread_name = (char*)data;
}

int main(int argc, char* argv[])
{
    char device[20];
    uint8_t attackerIP[4];
    uint8_t attackerMAC[6];
    uint8_t senderMAC[6];
    uint8_t senderIP[6];
    uint8_t targetIP[6];
    char dev[10];
    strncpy(dev, argv[1],strlen(argv[1]));
    local_info_setting(dev, attackerIP, attackerMAC);
    ip_change(argv[2], senderIP);
    ip_change(argv[3], targetIP);

    Get_senderMAC(dev, senderIP, senderMAC);
    inject_ARP_sender(dev,senderIP,targetIP,senderMAC);
}
