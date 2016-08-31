#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/* Buffer length */
#define BUFFER_LENGTH     256

/* Request string */
#define MAGIC_STRING      "HEAD / HTTP/1.1\n\n"

/* Connect timeout (seconds) */
#define CONNECT_TIMEOUT   800

/* Recv timeout (seconds) */
#define RECV_TIMEOUT      2

/* Scan table */
struct scan_table {
  char address[32];
  char banner[64];
  unsigned int port;
  struct scan_table *next;
};

/* Pseudo header for checksum calculation */
struct pseudo_header {
  unsigned int source_address;
  unsigned int dest_address;
  unsigned char placeholder;
  unsigned char protocol;
  unsigned short tcp_length;
};

in_addr_t get_interface_address(const char *interface) {
  int fd;
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  ifr.ifr_addr.sa_family = AF_INET;

  if(interface != NULL) {
    strncpy(ifr.ifr_name, interface, strlen(interface));
  } else {
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
  }

  ioctl(fd, SIOCGIFADDR, &ifr);
  close(fd);
  return ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;
}

char *strfind(const char *string, char character) {
  char *ptr;

  for(ptr = (char *) string; *ptr != '\0'; ptr++) {
    if(*ptr == character) {
      return ptr;
    }
  }

  return NULL;
}

unsigned short csum(unsigned short *data, unsigned int length) {
  unsigned int i, sum = 0;

  for(i = 0; i < length; ++i, ++data) {
    sum += *data;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

void range_scan(const char *range, unsigned int *first, unsigned int *last) {
  if(strfind(range, '-') != NULL) {
    sscanf(range, "%u-%u", first, last);
  } else {
    sscanf(range, "%u", first);
    *last = *first;
  }
}

void scan_port(const char *interface, const char *address, unsigned int port, unsigned char use_raw_socket, unsigned char verbose, struct scan_table **table) {
  char buffer[BUFFER_LENGTH];
  char pseudo_buffer[BUFFER_LENGTH];
  char banner[64];
  fd_set fdset;
  int sock, sock_error, flags, got_banner = 0, one = 1;
  unsigned int i;
  struct sockaddr_in addr;
  struct scan_table *entry;
  struct iphdr *ip;
  struct tcphdr *tcp;
  struct pseudo_header *phdr;
  struct timeval connect_timeout, recv_timeout;
  socklen_t sockaddr_len;
  socklen_t sock_length = sizeof sock_error;

  recv_timeout.tv_sec = RECV_TIMEOUT;
  recv_timeout.tv_usec = 0;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(address);  
  memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

  if(use_raw_socket == 1) {
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if(sock < 0) {
      perror("socket");
      return;
    }

    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(int)) < 0) {
      perror("setsockopt");
      close(sock);
      return;
    }

    if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof recv_timeout) == -1) {
      perror("setsockopt (recv timeout)");
      close(sock);
      return;
    }

    ip = (struct iphdr *) buffer;
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip->id = htonl(rand()); 
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0;
    ip->saddr = get_interface_address(interface);
    ip->daddr = addr.sin_addr.s_addr;

    tcp = (struct tcphdr *)(buffer + sizeof(struct iphdr));
    tcp->source = htons(rand() % 65536);
    tcp->dest = htons(port);
    tcp->seq = rand();
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->fin = 0;
    tcp->syn = 1;
    tcp->rst = 0;
    tcp->psh = 0;
    tcp->ack = 0;
    tcp->urg = 0;
    tcp->window = htons(29200);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    phdr = (struct pseudo_header *) pseudo_buffer;
    phdr->source_address = ip->saddr;
    phdr->dest_address = ip->daddr;
    phdr->placeholder = 0;
    phdr->protocol = IPPROTO_TCP;
    phdr->tcp_length = htons(sizeof(struct tcphdr));

    memcpy(pseudo_buffer + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));
    tcp->check = csum((unsigned short *) pseudo_buffer, (sizeof(struct pseudo_header) + sizeof(struct tcphdr)) >> 1);
    ip->check = csum((unsigned short *) buffer, ip->tot_len >> 1);

    if(verbose != 0) {
      fprintf(stdout, "Scanning %s:%u (sending SYN packet)...\n", address, port);
    }

    if(sendto(sock, buffer, ip->tot_len, 0, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) < 0) {
      perror("sendto");
      close(sock);
      return;
    }

    if(verbose != 0) {
      fprintf(stdout, "Scanning %s:%u (waiting for answer)...\n", address, port);
    }

    if(recvfrom(sock, buffer, sizeof buffer, 0, (struct sockaddr *) &addr, &sockaddr_len) <= 0) {
      perror("recv");
      close(sock);
      return;
    }

    if(tcp->rst == 1 || tcp->syn == 0 || tcp->ack == 0) {
      close(sock);
      return;
    }
  } else {
    sock = socket(AF_INET, SOCK_STREAM, 0);

    if(sock < 0) {
      perror("socket");
      return;
    }

    if((flags = fcntl(sock, F_GETFL)) < 0) {
      perror("fcntl");
      close(sock);
      return;
    }

    if(fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
      perror("fcntl");
      close(sock);
      return;
    }

    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    connect_timeout.tv_sec = 0;
    connect_timeout.tv_usec = CONNECT_TIMEOUT;

    connect(sock, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));

    if(verbose != 0) {
      fprintf(stdout, "Scanning %s:%u (connecting)...\n", address, port);
    }

    if(select(sock + 1, NULL, &fdset, NULL, &connect_timeout) > 0) {
      getsockopt(sock, SOL_SOCKET, SO_ERROR, &sock_error, &sock_length);

      if(sock_error != 0) {
        close(sock);
        return;
      }
    } else {
      close(sock);
      return;
    }

    if(fcntl(sock, F_SETFL, flags & ~O_NONBLOCK) < 0) {
      perror("fcntl");
      close(sock);
      return;
    }

    if(verbose != 0) {
      fprintf(stdout, "Scanning %s:%u (retrieving banner)...\n", address, port);
    }

    if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof recv_timeout) == -1) {
      perror("setsockopt (recv timeout)");
      close(sock);
      return;
    }

    if(write(sock, MAGIC_STRING, strlen(MAGIC_STRING)) > 0) {
      if(read(sock, banner, sizeof banner) > 0) {
        for(i = 0; i < sizeof banner; ++i) {
          if(banner[i] == '\n') {
            banner[i] = '\0';
            break;
          }
        }

        got_banner = 1;
      }
    }
  }

  entry = (struct scan_table *) malloc(sizeof(struct scan_table));

  if(entry != NULL) {
    entry->port = port;
    entry->next = *table;
    entry->banner[0] = '\0';
    strncpy(entry->address, address, sizeof entry->address);

    if(got_banner != 0) {
      strncpy(entry->banner, banner, sizeof entry->banner);
    }

    *table = entry;
  }

  close(sock);
}

int main(int argc, char *argv[]) {
  struct scan_table *table, *entry;
  char range[32], address[32];
  char *interface = NULL;
  int opt;
  unsigned int addr[3];
  unsigned int first_addr, last_addr, first_port, last_port, count, total, i, j;
  unsigned char use_raw_socket = 0, verbose = 0;
  time_t now;


  table = NULL;
  count = 0;
  time(&now);
  srand(time(NULL));

  if(argc < 2) {
    fprintf(stdout, "Uso: %s [-sv] [-i interface] <address range> [port range]\n", argv[0]);
    return 0;
  }

  while((opt = getopt(argc, argv, "svi:")) != -1) {
    switch(opt) {
      case 's':
        use_raw_socket = 1;
        break;
      case 'v':
        verbose = 1;
        break;
      case 'i':
        interface = strdup(optarg);
        break;
      default:
        fprintf(stdout, "Uso: %s [-sv] [-i interface] <address range> [port range]\n", argv[0]);
        exit(0);
    }
  }

  fprintf(stdout, "Varredura iniciada em %s", ctime(&now));
  fprintf(stdout, "IP: %s\n", argv[optind]);
  fprintf(stdout, "Portas: %s\n", (argc < optind + 2) ? ("*") : argv[optind + 1]);
  fprintf(stdout, "---\n");

  if(argc < optind + 2) {
    first_port = 0;
    last_port = 65535;
  } else {
    range_scan(argv[optind + 1], &first_port, &last_port);
  }

  sscanf(argv[optind], "%u.%u.%u.%s", &addr[0], &addr[1], &addr[2], range);
  range_scan(range, &first_addr, &last_addr);

  total = (last_addr - first_addr + 1) * (last_port - first_port + 1);
  for(i = first_addr; i <= last_addr; ++i) {
    for(j = first_port; j <= last_port; ++j) {
      snprintf(address, sizeof address, "%u.%u.%u.%u", addr[0], addr[1], addr[2], i);
      scan_port(interface, address, j, use_raw_socket, verbose, &table);
      ++count;
    }
  }

  for(entry = table; entry != NULL; entry = entry->next) {
    fprintf(stdout, "%s\t%u", entry->address, entry->port);

    if(entry->banner[0] != '\0') {
      fprintf(stdout, "\t%s", entry->banner);
    }

    fprintf(stdout, "\n");
  }

  while(table != NULL) {
    entry = table;
    table = table->next;
    free(entry);
  }

  if(verbose != 0) {
    fprintf(stdout, "%u ports scanned in total!\n", total);
  }

  if(interface != NULL) {
    free(interface);
  }

  return 0;
}
