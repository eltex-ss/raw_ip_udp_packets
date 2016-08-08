#include "common.h"
/*====================================*/
/*                                    */
/*  Constants.                        */
/*                                    */
#define PSEUDO_UDP_PACKET_SIZE 60
#define IP_UDP_PACKET_SIZE 68

/*====================================*/
/*                                    */
/*  Structures.                       */
/*                                    */

/*  Udp header under IPv4.
 *  For details see https://en.wikipedia.org/wiki/User_Datagram_Protocol. */
struct UdpPseudoHeader {
  uint32_t ip_s;
  uint32_t ip_d;
  uint8_t nulls;
  uint8_t protocol;
  uint16_t udp_l; 
};

struct UdpHeader {
  uint16_t port_s;
  uint16_t port_d;
  uint16_t length;
  uint16_t checksum;
};

struct UdpPacket {
  struct UdpHeader header;
  uint8_t data[MESSAGE_SIZE];
};

/*  IPv4 header. For details see https://www.wikipedia.org/wiki/IPv4. */
struct IPv4Header {
  uint8_t length:4;
  uint8_t version:4;
  uint8_t dscp:6;
  uint8_t ecn:2;
  uint16_t packet_length;
  uint16_t id;
  uint8_t flags:3;
  uint16_t offset:13;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  uint32_t ip_s;
  uint32_t ip_d;
};

struct IPv4Packet {
  struct IPv4Header header;
  struct UdpPacket data;
};

/*====================================*/
/*                                    */
/*  Global variables.                 */
/*                                    */
static int sock;

/*====================================*/
/*                                    */
/*  Functions.                        */
/*                                    */
void CloseSocket(void)
{
  close(sock);
}

uint16_t CalcCheckSum(uint16_t bytes[], size_t size)
{
  uint32_t sum = 0;
  while (size > 1) {
    sum += *(uint16_t *) bytes++;
    size -= 2;
  }
  if (size > 0)
    sum += *(uint8_t *) bytes;
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);
  return ~sum;
}

int main(int argc, char **argv)
{
  struct sockaddr_in server_address;
  socklen_t server_length;
  char *destination_ip;

  struct IPv4Header *ip_header;
  struct IPv4Packet *ip_packet;
  struct UdpPseudoHeader *pseudo_header;
  struct UdpHeader *udp_header;
  struct UdpPacket *udp_packet;
  char *message;  /*  Udp data buffer. */
  
  uint8_t ip_buffer[IP_UDP_PACKET_SIZE];  /*  Receiving package. */
  uint8_t pseudo_ip_udp_packet[PSEUDO_UDP_PACKET_SIZE]; /*  Udp package buf.*/

  int flag = 1; /*  For setsockopt(,,IP_HDR_INCL,,). */

  /*================================*/
  /*                                */
  /*  Input data check.             */
  /*                                */
  if (argc == 2) {
    destination_ip = argv[1];
    if (!IsAddressCorrect(destination_ip)) {
      printf("Incorrect address\n");
      exit(1);
    }
  } else {
    printf("Incorrect usage\n");
    printf("Should be: ./client ip_destination\n");
    printf("Example: ./client 127.0.0.1\n");
    exit(1);
  }

  /*================================*/
  /*                                */
  /*  Data initialization.          */
  /*                                */
  memset(ip_buffer, 0, IP_UDP_PACKET_SIZE);
  memset(pseudo_ip_udp_packet, 0, PSEUDO_UDP_PACKET_SIZE);
  ip_packet = (struct IPv4Packet *) ip_buffer;
  ip_header = (struct IPv4Header *) ip_packet;

  pseudo_header = (struct UdpPseudoHeader *) pseudo_ip_udp_packet;
  udp_packet = (struct UdpPacket *)
                (pseudo_ip_udp_packet + sizeof(struct UdpPseudoHeader));
  udp_header = (struct UdpHeader *)
               (pseudo_ip_udp_packet + sizeof(struct UdpPseudoHeader));
  message = (char *)(udp_packet->data);

  /*  Create raw socket. */
  sock = CreateSocket(RAW_SOCK);
  atexit(CloseSocket);

  memset(message, 0, MESSAGE_SIZE);
  sprintf(message, "Hello!");
  server_length = sizeof(struct sockaddr_in);

  /*================================*/
  /*                                */
  /*  IPv4 package.                 */
  /*                                */
  ip_header->version = 4;
  ip_header->length = 5;
  ip_header->dscp = 0;
  ip_header->ecn = 0;
  ip_header->packet_length = htons(IP_UDP_PACKET_SIZE);
  ip_header->id = 0;
  ip_header->flags = 0;
  ip_header->offset = 0;
  ip_header->ttl = 64; /*  Default. */
  ip_header->protocol = 17; /*  Udp. */
  ip_header->checksum = 0;
  ip_header->ip_s = inet_addr(sourceIp);
  ip_header->ip_d = inet_addr(destination_ip);
  ip_header->checksum = CalcCheckSum((uint16_t *) ip_buffer, 20);

  /*================================*/
  /*                                */
  /*  Udp package.                  */
  /*                                */

  /*  Filling pseudo header of udp package. */ 
  pseudo_header->ip_s = inet_addr(sourceIp);
  pseudo_header->ip_d = inet_addr(destination_ip);
  pseudo_header->nulls = 0;
  pseudo_header->protocol = 17;
  pseudo_header->udp_l = htons(UDP_PACKET_SIZE);

  /*  Filling udp header. */
  udp_header->port_s = htons((uint16_t)(SERVER_PORT + 1));
  udp_header->port_d = htons((uint16_t)SERVER_PORT);
  udp_header->length = htons((uint16_t)UDP_PACKET_SIZE);
  udp_header->checksum = 0;
  udp_header->checksum = CalcCheckSum((uint16_t *)pseudo_ip_udp_packet,
                                       PSEUDO_UDP_PACKET_SIZE);
  /* udp_header->checksum = htons(ntohs(udp_header->checksum) + 6); */
  printf("Checksum: 0x%x\n", ntohs(udp_header->checksum));
  memmove(&ip_packet->data, (void *) udp_packet,
          sizeof(struct UdpPacket));
  /*  Filling server address structure. */
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(SERVER_PORT);
  server_address.sin_addr.s_addr = inet_addr(destination_ip);
  
  if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(int)) < 0) {
    perror("setsockopt IP_HDRINCL error");
    exit(1);
  }
  if (sendto(sock, ip_packet, IP_UDP_PACKET_SIZE, 0,
             (struct sockaddr *) &server_address, server_length) < 0) {
    perror("sendto error");
    exit(1);
  }
  while (1) {
    uint8_t header_size;
    uint8_t first_octet;
    uint16_t port_d;
    size_t udp_offset = 0;
    
    if (recvfrom(sock, ip_buffer, IP_UDP_PACKET_SIZE, 0,
                 (struct sockaddr *) &server_address, &server_length) < 0) {
      perror("recvfrom error");
      exit(1);
    }

    memmove(&first_octet, ip_buffer, 1); /*  Read first byte. */
    header_size = first_octet & 0xf; /* 0xf = 00001111b */
    udp_offset = (header_size > 5) ? 24 : 20; 

    memmove(&port_d, ip_buffer + udp_offset + 2, 2);
    port_d = ntohs(port_d);
    printf("Port d: %d\n", port_d);
    if (port_d == 9999) {
      sprintf(message, "%s", ip_buffer + udp_offset + 8);
      printf("%s\n", message);
      break;
    }
  }

  return 0;
}
