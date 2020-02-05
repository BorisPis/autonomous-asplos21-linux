#!/bin/bash

echo 'Removing nvme-tcp'
sudo modprobe -vr nvme-tcp

echo 'Reloading nvme-tcp from `pwd`'
sudo insmod drivers/nvme/host/nvme-fabrics.ko
sudo insmod drivers/nvme/host/nvme-tcp.ko

lsmod | grep nvme
