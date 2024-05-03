#!/bin/bash

# Compile the driver
make > /dev/null

# Insert the module
sudo insmod driver.ko > /dev/null

# Create device file
sudo mknod /dev/ioctl_device c 100 0

sudo chmod +666 /dev/ioctl_device

# Cleanup
# sudo rmmod driver.ko
# make clean >/dev/null
# sudo rm /dev/ioctl_device
