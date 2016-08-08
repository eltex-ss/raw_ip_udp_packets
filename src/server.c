#include "common.h"

static int sock;

void CloseSocket(void)
{
  close(sock);
}

int main(int argc, char **argv)
{
  char message[MESSAGE_SIZE];
  struct sockaddr_in server_address,
                     client_address;
  socklen_t client_length;
  char *server_ip;

  if (argc == 2) {
    server_ip = argv[1];
    if (!IsAddressCorrect(server_ip)) {
      printf("Incorrect ip");
      exit(1);
    }
  } else {
    printf("Incorrect usage\n");
    printf("Should be: ./server ip\n");
    printf("Example: ./server 127.0.0.1\n");
    exit(1);
  }

  /*  Create udp socket. */
  sock = CreateSocket(UDP_SOCK);
  atexit(CloseSocket);

  /*  Fiiling server address. */
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(SERVER_PORT);
  server_address.sin_addr.s_addr = inet_addr(server_ip);

  client_length = sizeof(struct sockaddr_in);
  if (bind(sock, (struct sockaddr *) &server_address,
           sizeof(struct sockaddr)) < 0) {
    perror("bind error");
    exit(1);
  }
  /*  Get message "Hello!". */
  if (recvfrom(sock, message, MESSAGE_SIZE, 0,
               (struct sockaddr *) &client_address, &client_length) < 0) {
    perror("recvfrom error");
    exit(1);
  }
  printf("Got message: %s\n", message);

  memset(message, 0, MESSAGE_SIZE);
  sprintf(message, "Hi!");
  client_address.sin_port = htons(9999);
  if (sendto(sock, message, MESSAGE_SIZE, 0,
             (struct sockaddr *) &client_address, client_length) < 0) {
    perror("sendto error");
    exit(1);
  }

  return 0;
}
