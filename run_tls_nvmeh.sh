#!/bin/bash
source /var/local.sh
sudo modprobe -v nvme_tcp
echo 1 | sudo tee /sys/module/nvme_tcp/parameters/nvmeotcp_tls_rx
sudo nvme connect-all -t tcp -a $ip2 -s 4420 -G --nr-io-queues=1
