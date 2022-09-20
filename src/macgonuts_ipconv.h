#ifndef MACGONUTS_IPCONV_H
#define MACGONUTS_IPCONV_H 1

#include <macgonuts_types.h>

int macgonuts_get_ip_version(const char *ip, const size_t ip_size);

int macgonuts_check_ip_addr(const char *ip, const size_t ip_size);

int macgonuts_check_ip_range(const char *ip, const size_t ip_size);

#endif
