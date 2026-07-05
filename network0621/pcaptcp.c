#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "mytcpheader.h"


void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) != 0x0800){ // IPv4
    return;
  }
  
  else {
    struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 
    if (ip->iph_protocol != IPPROTO_TCP)
        return;

    int ip_header_len = ip->iph_ihl * 4;

    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;

    const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

    //print tcp
    printf("TCP PACKET found\n\n");

    printf("<Ethernet Header>\n");
    printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);

    printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    printf("<IP Header>\n");
    printf("src ip: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("dst ip: %s\n\n", inet_ntoa(ip->iph_destip));

    printf("<TCP Header>\n");
    printf("src port: %d\n", ntohs(tcp->tcp_sport));
    printf("dst port: %d\n\n", ntohs(tcp->tcp_dport));

    printf("<HTTP Message>\n");
    if (payload_len > 0) {
    for (int i = 0; i < payload_len; i++) {
        printf("%c", payload[i]);
    }
    }

    printf("\n\n");
  }
    
}


int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp port 80"; //print tcp and http protocol only
  bpf_u_int32 net=0;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "pcap_open_live error: %s\n", errbuf);
    return 1;
  }

  // Step 2: Compile filter_exp into BPF psuedo-code
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    pcap_perror(handle, "pcap_compile error");
    return 1;
  }

  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }
  
  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}
