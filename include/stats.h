#ifndef STATS_H
#define STATS_H

#include <stdint.h>
#include <stddef.h>

int stats_increment(const char *iface, const char *ip);
uint64_t stats_get_count(const char *iface, const char *ip);
uint64_t stats_get_total_count(const char *ip);

int stats_save(const char *path);
int stats_load(const char *path);

int stats_format_all(char *buf, size_t size);
int stats_format_iface(const char *iface, char *buf, size_t size);

void stats_cleanup(void);

#endif