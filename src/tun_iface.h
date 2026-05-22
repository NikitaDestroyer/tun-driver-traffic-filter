#ifndef TUN_IFACE_H
#define TUN_IFACE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define TUN_NAME_DEFAULT "tun0"
#define TUN_IP_DEFAULT   "10.0.0.1"
#define TUN_MASK_DEFAULT "255.255.255.0"

typedef struct {
    int  fd;
    char name[16];
} tun_device_t;

int tun_create(tun_device_t *dev, const char *name);
void tun_close(tun_device_t *dev);
ssize_t tun_read_packet(tun_device_t *dev, uint8_t *buf, size_t buflen);
ssize_t tun_write_packet(tun_device_t *dev, const uint8_t *buf, size_t len);

#endif
