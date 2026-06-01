# Минимальная сборка: userspace + kernel module

CC      ?= gcc
CFLAGS  := -Wall -Wextra -O2 -std=c11 -D_GNU_SOURCE
LDFLAGS := -lpthread

BUILD_DIR := build
SRC_DIR   := src
USERSPACE_SRCS := \
	$(SRC_DIR)/main.c \
	$(SRC_DIR)/tun_iface.c \
	$(SRC_DIR)/packet_parser.c \
	$(SRC_DIR)/filter.c \
	$(SRC_DIR)/log_queue.c

KERNEL_DIR := kernel
KMOD_NAME  := tun_vpn_detect

.PHONY: all clean load-kmod unload-kmod start stop test

all: $(BUILD_DIR)/tund $(BUILD_DIR)/$(KMOD_NAME).ko

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/tund: $(USERSPACE_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) $(USERSPACE_SRCS) -o $@ $(LDFLAGS)

# Сборка модуля ядра (нужны linux-headers)
$(BUILD_DIR)/$(KMOD_NAME).ko: $(KERNEL_DIR)/$(KMOD_NAME).c $(KERNEL_DIR)/Makefile | $(BUILD_DIR)
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(CURDIR)/$(KERNEL_DIR) modules
	cp $(KERNEL_DIR)/$(KMOD_NAME).ko $(BUILD_DIR)/

load-kmod:
	sudo insmod $(BUILD_DIR)/$(KMOD_NAME).ko

unload-kmod:
	-sudo rmmod $(KMOD_NAME)

start:
	sudo ./scripts/start.sh

stop:
	sudo ./scripts/stop.sh

test:
	sudo ./scripts/test_all.sh

clean:
	rm -rf $(BUILD_DIR)
	-$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(CURDIR)/$(KERNEL_DIR) clean 2>/dev/null
