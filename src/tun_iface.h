#ifndef TUN_IFACE_H
#define TUN_IFACE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define TUN_NAME_DEFAULT "tun0"
#define TUN_IP_DEFAULT   "10.0.0.1"
#define TUN_MASK_DEFAULT "255.255.255.0"

/** Дескриптор открытого TUN-устройства и имя созданного интерфейса. */
typedef struct {
    int  fd;
    char name[16];
} tun_device_t;

/**
 * Открывает /dev/net/tun и создаёт виртуальный интерфейс (IFF_TUN | IFF_NO_PI).
 *
 * @param dev   Выход: заполняется fd и фактическим именем интерфейса.
 * @param name  Запрашиваемое имя (например "tun0").
 * @return 0 при успехе, отрицательный -errno при ошибке open/ioctl.
 */
int tun_create(tun_device_t *dev, const char *name);

/**
 * Закрывает file descriptor TUN-устройства.
 *
 * @param dev  Устройство; после вызова fd = -1.
 */
void tun_close(tun_device_t *dev);

/**
 * Читает один IP-пакет из TUN (без PI-заголовка).
 *
 * @param dev     Открытое TUN-устройство.
 * @param buf     Буфер для данных пакета.
 * @param buflen  Размер буфера.
 * @return Число прочитанных байт, 0 при EOF, -1 при ошибке (см. errno).
 */
ssize_t tun_read_packet(tun_device_t *dev, uint8_t *buf, size_t buflen);

/**
 * Записывает IP-пакет в TUN для передачи в сетевой стек.
 *
 * @param dev  Открытое TUN-устройство.
 * @param buf  Raw IPv4-пакет.
 * @param len  Длина пакета в байтах.
 * @return Число записанных байт или -1 при ошибке (см. errno).
 */
ssize_t tun_write_packet(tun_device_t *dev, const uint8_t *buf, size_t len);

#endif
