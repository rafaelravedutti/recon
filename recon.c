#include <stdio.h>

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

int main(int argc, const char *argv[]) {
  char range[32];
  unsigned int addr[3];
  unsigned int first_addr, last_addr, first_port, last_port, i, j;

  if(argc != 3) {
    fprintf(stdout, "Uso: %s <address range> <port range>\n", argv[0]);
    return 0;
  }

  sscanf(argv[1], "%u.%u.%u.%s", &addr[0], &addr[1], &addr[2], range);
  range_scan(range, &first_addr, &last_addr);
  range_scan(argv[2], &first_port, &last_port);

  for(i = first_addr; i <= last_addr; ++i) {
    for(j = first_port; j <= last_port; ++j) {
      fprintf(stdout, "Scanning %u.%u.%u.%u:%u\n", addr[0], addr[1], addr[2], i, j);
    }
  }

  return 0;
}
