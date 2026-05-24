#include "tun_iface.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* См. объявление в tun_iface.h */
int tun_create(tun_device_t *dev, const char *name)
{
    memset(dev, 0, sizeof(*dev));

    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
        return -errno;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        int err = -errno;
        close(fd);
        return err;
    }

    dev->fd = fd;
    snprintf(dev->name, sizeof(dev->name), "%s", ifr.ifr_name);
    return 0;
}

/* См. объявление в tun_iface.h */
void tun_close(tun_device_t *dev)
{
    if (dev->fd >= 0)
        close(dev->fd);
    dev->fd = -1;
}

/* См. объявление в tun_iface.h */
ssize_t tun_read_packet(tun_device_t *dev, uint8_t *buf, size_t buflen)
{
    return read(dev->fd, buf, buflen);
}

/* См. объявление в tun_iface.h */
ssize_t tun_write_packet(tun_device_t *dev, const uint8_t *buf, size_t len)
{
    return write(dev->fd, buf, len);
}
