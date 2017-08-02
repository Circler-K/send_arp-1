#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <pcap/pcap.h>
#include <string.h>
#include <stdlib.h>
#define MAC_STRING_LENGTH 13

u_char packet[61];

char *getmac(char *iface)
{
    char *ret = malloc(MAC_STRING_LENGTH);
    struct ifreq s;
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(s.ifr_name, iface);
    if(fd>=0 && ret && 0 == ioctl(fd, SIOCGIFHWADDR, &s))
    {
        int i;
        for (i=0;i<6;++i){
            packet[i+6]=s.ifr_addr.sa_data[i]; // Source MAC
            packet[i+22]=s.ifr_addr.sa_data[i]; // Sender MAC Address
            printf(" %02x",(unsigned char) s.ifr_addr.sa_data[i]);
        }
        printf("\n");
    }
    else
    {
        perror("malloc/socket/ioctl failed");
        exit(1);
    }
    return(ret);
}
typedef struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
}SSS;

struct sniff_ip {
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    struct in_addr ip_src, ip_dst;
};
#define IP_HL(ip)
#define IP_V(ip)
#define SIZE_ETHERNET 14
int main(int argc, char *argv[])
{
    int i;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    struct sniff_ip *ip;
    const u_char *pkt_data;
    int data;
    SSS *ethernet;
    if(argc < 4)
    {
        printf("usage ./filename [network device][sender ip][target ip]\n");
        return EXIT_SUCCESS;
    }
    char *mac = getmac(argv[1]);
    //broadcast
    for (i=0;i<6;i++)
        packet[i]=0xff;
    free(mac);

    //ETHERTYPE_ARP
    packet[12]=0x08;
    packet[13]=0x06;
    packet[14]=0x00;
    packet[15]=0x01;
    packet[16]=0x08;
    packet[17]=0x00;
    packet[18]=0x06;
    packet[19]=0x04;
    packet[20]=0x00;
    packet[21]=0x01;
    packet[28]=0x00;
    packet[29]=0x00;
    packet[30]=0x00;
    packet[31]=0x00;
    packet[32]=0x00;
    packet[33]=0x00;
    packet[34]=0x00;
    packet[35]=0x00;
    packet[36]=0x00;
    packet[37]=0x00;
    // target IP
    packet[38]=0xc0;
    packet[39]=0xa8;
    packet[40]=0xff;
    packet[41]=0x88;
    printf("sender ip : %s\n",argv[2]); // sender ip
    printf("target ip : %s\n",argv[3]); // target ip
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 100,errbuf);
    if(handle == NULL) {
        fprintf(stderr, "Couldn't open device %s : %s", argv[1],errbuf);
    }
    if(pcap_sendpacket(handle,packet,42)!=0)
    {
        fprintf(stderr,"\nError sending the packet: %s",pcap_geterr(handle));
        return 0;
    }
    u_char target_mac[6];
    while(1){
    data = pcap_next_ex(handle, &header, &pkt_data);
    ethernet = (struct sniff_ethernet*)(pkt_data);
    ip = (struct sniff_ip*)(pkt_data+SIZE_ETHERNET);
    //if(pkt_data[20]==0x20){
        if(ntohs(ethernet -> ether_type)==ETHERTYPE_ARP){
            for(i=0;i<42;i++){
                printf(" %02x",pkt_data[i]);
                if(i>22 && i<=27){
                    target_mac[i-22]+=pkt_data[i];
                }
            }
            printf("\n");
            printf("target_mac : ");
            for(i=0;i<6;i++)
                printf(" %02x",target_mac[i]);
            printf("\n");
            break;
        }

    //}
    //if(data==-1||data==-2)
    //        break;
    //    if(data==0)
    //        continue;
    }
    return 0;
}
