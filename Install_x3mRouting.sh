#!/bin/sh
mkdir -p /jffs/addons/x3mRouting && /usr/sbin/curl --retry 3 https://x3mtek.com/install_x3mRouting -o /jffs/addons/x3mRouting/x3mRouting_Menu.sh && chmod 755 /jffs/addons/x3mRouting/x3mRouting_Menu.sh && rm /opt/bin/x3mRouting 2>/dev/null && ln -s /jffs/addons/x3mRouting/x3mRouting_Menu.sh /opt/bin/x3mRouting && x3mRouting || ln -s /jffs/addons/x3mRouting/x3mRouting_Menu.sh /opt/bin/x3mRouting && x3mRouting
