#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

char *strfind(const char *string, char character) {
  char *ptr;

  for(ptr = (char *) string; *ptr != '\0'; ptr++) {
    if(*ptr == character) {
      return ptr;
    }
  }

  return NULL;
}

void range_scan(const char *range, unsigned int *first, unsigned int *last) {
  if(strfind(range, '-') != NULL) {
    sscanf(range, "%u-%u", first, last);
  } else {
    sscanf(range, "%u", first);
    *last = *first;
  }
}

void scan_port(const char *address, unsigned int port) {
  int sock;
  struct sockaddr_in addr;

  sock = socket(AF_INET, SOCK_STREAM, 0);

  if(sock < 0) {
    perror("socket");
    return;
  }

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(address);  
  memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

  if(connect(sock, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) < 0) {
    perror("connect");
    return;
  }
}

int main(int argc, const char *argv[]) {
  char range[32], address[32];
  unsigned int addr[3];
  unsigned int first_addr, last_addr, first_port, last_port, count, total, i, j;

  if(argc != 3) {
    fprintf(stdout, "Uso: %s <address range> <port range>\n", argv[0]);
    return 0;
  }

  sscanf(argv[1], "%u.%u.%u.%s", &addr[0], &addr[1], &addr[2], range);
  range_scan(range, &first_addr, &last_addr);
  range_scan(argv[2], &first_port, &last_port);

  total = (last_addr - first_addr + 1) * (last_port - first_port + 1);
  for(i = first_addr; i <= last_addr; ++i) {
    for(j = first_port; j <= last_port; ++j) {
      snprintf(address, sizeof address, "%u.%u.%u.%u", addr[0], addr[1], addr[2], i);
      fprintf(stdout, "\rScanning %s:%u (%.2f%%)", address, j, ((double) count / (double) total) * 100);
      scan_port(address, j);
      ++count;
    }
  }

  fprintf(stdout, "\rScanning complete!                           \n");
  return 0;
}
