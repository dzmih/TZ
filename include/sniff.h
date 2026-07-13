#ifndef SNIFF_H
#define SNIFF_H

int sniff_open(const char *iface);
void sniff_close(void);
int sniff_fd(void);
int sniff_handle_packet(void);

#endif
