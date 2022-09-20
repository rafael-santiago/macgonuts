#ifndef MACGONUTS_ETHERCONV_H
#define MACGONUTS_ETHERCONV_H 1

int macgonuts_check_ether_addr(const char *ether, const size_t ether_size);

void macgonuts_getrandom_ether_addr(char *ether, const size_t ether_size);

#endif
