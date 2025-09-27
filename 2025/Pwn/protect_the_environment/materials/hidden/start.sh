#!/bin/sh
# Add your startup script

export FLAG=$(cat /home/ctf/flag.txt)

# DO NOT DELETE
/etc/init.d/xinetd start;
sleep infinity;
