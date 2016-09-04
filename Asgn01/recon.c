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
#define CONNECT_TIMEOUT   2

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

/* Returns interface address */
in_addr_t get_interface_address(const char *interface) {
  int fd;
  struct ifreq ifr;

  /* Creates a socket and binds it to interface */
  fd = socket(AF_INET, SOCK_DGRAM, 0);
  ifr.ifr_addr.sa_family = AF_INET;

  /* If interface is null, uses "eth0" as default */
  if(interface != NULL) {
    strncpy(ifr.ifr_name, interface, strlen(interface));
  } else {
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
  }

  /* Retrieves address and stores it in the interface structure */
  ioctl(fd, SIOCGIFADDR, &ifr);
  close(fd);

  /* Returns the address */
  return ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;
}

/* Returns first character's found position, null if not found */
char *strfind(const char *string, char character) {
  char *ptr;

  /* Percorre a string e retorna o caractere se encontrá-lo */
  for(ptr = (char *) string; *ptr != '\0'; ptr++) {
    if(*ptr == character) {
      return ptr;
    }
  }

  return NULL;
}

/* Checksum calculation */
unsigned short csum(unsigned short *data, unsigned int length) {
  unsigned int i, sum = 0;

  /* Sum all data bytes and store in sum variable */
  for(i = 0; i < length; ++i, ++data) {
    sum += *data;
  }

  /* Sum all in the least significant 16 bits (2 bytes) */
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

/* Scan a range, it may be like "[0-9]+" or "[0-9]+-[0-9]+" */
void range_scan(const char *range, unsigned int *first, unsigned int *last) {
  /* If there is a dash in the range, scans the limits separated by it */
  if(strfind(range, '-') != NULL) {
    sscanf(range, "%u-%u", first, last);
  /* Otherwise there's just one number, so the limits are the same */
  } else {
    sscanf(range, "%u", first);
    *last = *first;
  }
}

/* Scans a specific port at a specific address */ 
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
  struct timeval tv;
  socklen_t sockaddr_len;
  socklen_t sock_length = sizeof sock_error;

  /* Address structure */
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(address);  
  memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

  /* Raw sockets may be used for SYN scan, so the TCP "Three Way Handshake"
     connection is not finished, this can improve performance and makes
     harder to detect the scan, but requires root privileges */
  if(use_raw_socket == 1) {
    /* Creates the raw socket */
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    /* Checks for errors */
    if(sock < 0) {
      perror("socket");
      return;
    }

    /* Tells the system (OS) that the packets in this socket will
       be sent including the TCP/IP headers */
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(int)) < 0) {
      perror("setsockopt");
      close(sock);
      return;
    }

    /* IP header definition */
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

    /* TCP header definition */
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

    /* Pseudo-header definition (used for TCP checksum calculation) */
    phdr = (struct pseudo_header *) pseudo_buffer;
    phdr->source_address = ip->saddr;
    phdr->dest_address = ip->daddr;
    phdr->placeholder = 0;
    phdr->protocol = IPPROTO_TCP;
    phdr->tcp_length = htons(sizeof(struct tcphdr));

    /* Copies TCP header to pseudo buffer */
    memcpy(pseudo_buffer + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));
    /* Calculates TCP checksum using the pseudo buffer */
    tcp->check = csum((unsigned short *) pseudo_buffer, (sizeof(struct pseudo_header) + sizeof(struct tcphdr)) >> 1);
    /* Calculates the IP checksum using TCP/IP headers */
    ip->check = csum((unsigned short *) buffer, ip->tot_len >> 1);

    if(verbose != 0) {
      fprintf(stdout, "Scanning %s:%u (sending SYN packet)...\n", address, port);
    }

    /* Finally, sends the packet through the socket */
    if(sendto(sock, buffer, ip->tot_len, 0, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) < 0) {
      perror("sendto");
      close(sock);
      return;
    }

    if(verbose != 0) {
      fprintf(stdout, "Scanning %s:%u (waiting for answer)...\n", address, port);
    }

    /* Waits for response */
    if(recvfrom(sock, buffer, sizeof buffer, 0, (struct sockaddr *) &addr, &sockaddr_len) <= 0) {
      perror("recv");
      close(sock);
      return;
    }

    /* If the answer has a RST flag, the port is not open, also,
       if neither SYN and ACK flags are set in the answer, it's
       much likely that the host can be unavaiable or the port is
       filtered by a firewall */
    if(tcp->rst == 1 || tcp->syn == 0 || tcp->ack == 0) {
      close(sock);
      return;
    }
  /* High level socket method (performing connections */
  } else {
    /* Creates the socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);

    /* Checks for errors */
    if(sock < 0) {
      perror("socket");
      return;
    }

    /* Get socket's flags */
    if((flags = fcntl(sock, F_GETFL)) < 0) {
      perror("fcntl");
      close(sock);
      return;
    }

    /* Set socket as non-blocking (for timeout controlling) */
    if(fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
      perror("fcntl");
      close(sock);
      return;
    }

    /* Creates a file descriptor set containing only the socket */
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    tv.tv_sec = CONNECT_TIMEOUT;
    tv.tv_usec = 0;

    /* Performs the non-blocking connection */
    connect(sock, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));

    if(verbose != 0) {
      fprintf(stdout, "Scanning %s:%u (connecting)...\n", address, port);
    }

    /* Uses select on the file descriptor set (the socket), when
       it's writable (connection worked) or the timeout occurred,
       perform the necessary procedures */
    if(select(sock + 1, NULL, &fdset, NULL, &tv) > 0) {
      getsockopt(sock, SOL_SOCKET, SO_ERROR, &sock_error, &sock_length);

      if(sock_error != 0) {
        close(sock);
        return;
      }
    } else {
      close(sock);
      return;
    }

    /* Set socket back to blocking mode */
    if(fcntl(sock, F_SETFL, flags & ~O_NONBLOCK) < 0) {
      perror("fcntl");
      close(sock);
      return;
    }

    if(verbose != 0) {
      fprintf(stdout, "Scanning %s:%u (retrieving banner)...\n", address, port);
    }

    /* Writes the magic string on the socket, and then reads
       the banner that should be sent to it */
    if(write(sock, MAGIC_STRING, strlen(MAGIC_STRING)) > 0) {
      if(read(sock, banner, sizeof banner) > 0) {
        for(i = 0; i < sizeof banner; ++i) {
          if(banner[i] == '\n') {
            banner[i] = '\0';
            break;
          }
        }

        /* If the read is ok, then sets the variable for posterior checking */
        got_banner = 1;
      }
    }
  }

  /* Allocates a entry in the scan table for the host:port */
  entry = (struct scan_table *) malloc(sizeof(struct scan_table));

  /* If there weren't problems on allocation */
  if(entry != NULL) {
    /* Sets entry properties */
    entry->port = port;
    entry->next = *table;
    entry->banner[0] = '\0';
    strncpy(entry->address, address, sizeof entry->address);

    /* If there's a banner, copies it to the entry */
    if(got_banner != 0) {
      strncpy(entry->banner, banner, sizeof entry->banner);
    }

    /* The entry now is on the table head */
    *table = entry;
  }

  /* Closes the socket */
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

  /* Variables initialization */
  table = NULL;
  count = 0;
  time(&now);
  srand(time(NULL));

  /* Program options processing */

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

  /* Prints the program header */

  fprintf(stdout, "Varredura iniciada em %s", ctime(&now));
  fprintf(stdout, "IP: %s\n", argv[optind]);
  fprintf(stdout, "Portas: %s\n", (argc < optind + 2) ? ("*") : argv[optind + 1]);
  fprintf(stdout, "---\n");

  /* Scan the options (address and port ranges) */

  if(argc < optind + 2) {
    first_port = 0;
    last_port = 65535;
  } else {
    range_scan(argv[optind + 1], &first_port, &last_port);
  }

  sscanf(argv[optind], "%u.%u.%u.%s", &addr[0], &addr[1], &addr[2], range);
  range_scan(range, &first_addr, &last_addr);

  /* Total ports to be scanned */
  total = (last_addr - first_addr + 1) * (last_port - first_port + 1);

  /* Performs scan at each specified port inside the range, feeding the table */
  for(i = first_addr; i <= last_addr; ++i) {
    for(j = first_port; j <= last_port; ++j) {
      snprintf(address, sizeof address, "%u.%u.%u.%u", addr[0], addr[1], addr[2], i);
      scan_port(interface, address, j, use_raw_socket, verbose, &table);
      ++count;
    }
  }

  /* Prints all table entries */
  for(entry = table; entry != NULL; entry = entry->next) {
    fprintf(stdout, "%s\t%u", entry->address, entry->port);

    if(entry->banner[0] != '\0') {
      fprintf(stdout, "\t%s", entry->banner);
    }

    fprintf(stdout, "\n");
  }

  /* Free table memory space */
  while(table != NULL) {
    entry = table;
    table = table->next;
    free(entry);
  }

  if(verbose != 0) {
    fprintf(stdout, "%u ports scanned in total!\n", total);
  }

  /* Free interface memory space */
  if(interface != NULL) {
    free(interface);
  }

  return 0;
}
