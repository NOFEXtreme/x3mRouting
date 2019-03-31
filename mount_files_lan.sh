#!/bin/sh
####################################################################################################
# Script: mount_files_ipset.sh
# Version 1.0
# Author: Xentrk
# Date: 31-March-2019
#
# Grateful:
# Thank you to @Martineau on snbforums.com for educating myself and others on Selective
# Routing techniques using Asuswrt-Merlin firmware.
#
#####################################################################################################
# Script Description:
#  This script is called from /jffs/scripts/init-start.
#  The script will mount files used by the Asuswrt-Merlin-Selective Routing project to override
#  the firmware files.
#
#####################################################################################################
if [ "$(df | grep -c "/usr/sbin/vpnrouting.sh")" -eq 0 ]; then
  mount -o bind /jffs/scripts/vpnrouting.sh /usr/sbin/vpnrouting.sh
fi
if [ "$(df | grep -c "/usr/sbin/updown.sh")" -eq 0 ]; then
  mount -o bind /jffs/scripts/updown.sh /usr/sbin/updown.sh
fi
