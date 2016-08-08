#pragma once

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <string.h>
#include <stdint.h>

#define SERVER_PORT 10000

#define UDP_PACKET_SIZE 48
#define MESSAGE_SIZE 40

/*  Available socket types. */
#define TCP_SOCK 0
#define UDP_SOCK 1
#define RAW_SOCK 2

const char *sourceIp = "192.168.2.44";

/*  Return socket file descriptor. */
int CreateSocket(int socket_type)
{
  int sock;

  switch (socket_type) {
    case TCP_SOCK:
      sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      break;
    case UDP_SOCK:
      sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      break;
    case RAW_SOCK:
      sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
      break;
    default:
      printf("unknown type of socket");
      exit(1);
  }
  if (sock < 0) {
    perror("socket error");
    exit(1);
  }
  return sock;
}

/*  Check validation of ip address. */
int IsAddressCorrect(char *ip_address)
{
  struct sockaddr_in net_address;
  int result;
  result = inet_pton(AF_INET, ip_address, &net_address);
  return result == 1;
}
