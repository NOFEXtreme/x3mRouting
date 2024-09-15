#!/bin/sh
####################################################################################################
# Script: x3mRouting.sh
# VERSION=2.3.12
# Author: Xentrk
# Date: 18-May-2021
#
# Modified by NOFEXtream: https://github.com/NOFEXtreme/x3mRouting/blob/master/x3mRouting.sh
# Added WireGuard support and limited the script to handling only HTTP and HTTPS traffic.
# Currently not working with WireGuard:
#  - VPN Server to VPN Client Routing
# Date: 15-September-2024
#
# Grateful:
#   Thank you to @Martineau on snbforums.com for sharing his Selective Routing expertise,
#   on-going support and collaboration on this project!
#
#   Chk_Entware function and code to process the passing of params written by Martineau
#
#   Thanks to Addamm00, author of Skynet, for the Check_Lock and Kill_Lock functions to prevent concurrent processing.
#   Source code can be found at https://github.com/Adamm00/IPSet_ASUS
#
####################################################################################################
# shellcheck disable=SC2031 # IPSET_NAME was modified in a subshell. That change might be lost.
# shellcheck disable=SC2068 # Double quote array expansions to avoid re-splitting elements.
# shellcheck disable=SC2030 # Modification of IPSET_NAME is local (to subshell caused by pipeline).
#_____________________________________________________________________________________________________________
#
# Required parameters are listed inside the braces: { }
# Optional parameters are listed inside of the brackets [ ]
# Valid parameter values are listed in parenthesis ( )
#
# Create IPSET List with Routing Rules:
#
# x3mRouting {src iface} (ALL|1|2|3|4|5|11|12|13|14|15)
#            {dst iface} (0|1|2|3|4|5|11|12|13|14|15)
#            ** src/dst NOTES Start **
#              Valid SRC and DST Combinations
#              1) VPN Client Routing
#                 - Use this SRC and DST combination to route all IPSET list traffic to a VPN Client:
#                   ALL 1, ALL 2, ALL 3, ALL 4, ALL 5, ALL 11, ALL 12, ALL 13, ALL 14, ALL 15
#              2) VPN Bypass Routing
#                 - Use this SRC and DST combination to bypass the VPN Client for an IPSET list and
#                   route to the WAN interface:
#                   1 0, 2 0, 3 0, 4 0, 5 0, 11 0, 12 0, 13 0, 14 0, 15 0
#            ** src/dst NOTES End **
#            {ipset_name}
#            ['autoscan='keyword1[,keyword2]...] # Scans for keywords and creates IPSET list using
# 	                                             # the dnsmasq method
#            ['asnum='asnum[,asnum]...] # ASN method
#            ['aws_region='US[,EU]...]  # Amazon method
#            ['dnsmasq='domain[,domain]...] # dnsmasq method
#            ['dnsmasq_file='/path/to/file] # dnsmasq method
#            ['ip='ip[,ip][,cidr]...] # Equivalent to manual method
#            ['src='src_ip]
#            ['src_range='from_ip-to_ip]
#            ['dir='save_restore_location] # if 'dir' not specified, defaults to /opt/tmp
#            ['del'] # Delete IPSET list and all configuration settings.
#                    # **Will prompt** for permission to delete any files if only a shebang exists
#            ['del=force'] # Force delete the IPSET list and all configuration settings if only
#                          # a shebang exists. **Will not** prompt for permission before deleting a
#                          # file if only a shebang exists.
#            ['protocol=udp|tcp'] # Set protocol to 'udp', 'tcp' or other supported by the system
#            ['port=port] # Set port destination
#            ['ports=port[,port]...] # Set ports destination
#
#_____________________________________________________________________________________________________________
#
# Create IPSET List with no Routing Rules:
#
# x3mRouting {ipset_name=}
#            ['autoscan='keyword1[,keyword2]...] # Scans for keywords and creates IPSET list using
# 	                                             # the dnsmasq method
#            ['asnum='asnum[,asnum]...] # ASN method
#            ['aws_region='US[,EU]...]  # Amazon method
#            ['dnsmasq='domain[,domain]...] # dnsmasq method
#            ['dnsmasq_file='/path/to/file] # dnsmasq method
#            ['ip='ip[,ip][,cidr]...] # Equivalent to manual method
#            ['dir='save_restore_location] # if 'dir' not specified, defaults to /opt/tmp
#            ['del'] # Delete IPSET list and all configuration settings.
#                    # **Will prompt** for permission to delete any files if only a shebang exists
#            ['del=force'] # Force delete the IPSET list and all configuration settings if only
#                          # a shebang exists. **Will not** prompt for permission before deleting a
#                          # file if only a shebang exists.
#
#____________________________________________________________________________________________________________
#
# VPN Server to VPN Client Routing:
#
# x3mRouting {'server='1|2|all} {'client='1|2|3|4|5} ['del'] ['del=force']
#
# TODO: Fix Server-to-client routing functionality for WireGuard clients in the VPN_Server_to_VPN_Client() function.
#
#_____________________________________________________________________________________________________________
#
# VPN Server to existing LAN routing rules for one or more IPSET lists
#
# x3mRouting {'server='1|2|3|all} {'ipset_name='IPSET[,IPSET]...} ['protocol=udp|tcp'] ['port=port] ['ports=port[,port]...] ['del'] ['del=force']
#_____________________________________________________________________________________________________________

# Print between line beginning with '#__' to first blank line inclusive (source: Martineau)
ShowHelp() {
  awk '/^#__/{f=1} f{print; if (!NF) exit}' "$0" | more
}

# Need assistance!???
if [ "$1" = "help" ] || [ "$1" = "-h" ]; then
  ShowHelp
  exit 0
fi

VPN_IDS="1 2 3 4 5 11 12 13 14 15"
COLOR_RED='\033[0;31m'
COLOR_WHITE='\033[0m'
COLOR_GREEN='\e[0;32m'

# Find x3mRouting script directory
SCR_NAME=$(basename "$0" | sed 's/.sh//')
SCR_DIR="$(cd "$(dirname "$0")" && pwd)"
LOCK_FILE="/tmp/x3mRouting.lock"
NAT_START="/jffs/scripts/nat-start"           # - NAT initialization (e.g., firewall restart).
WG_START="/jffs/scripts/wgclient-start" # - WireGuard client startup.
WAN_EVENT="/jffs/scripts/wan-event"           # - WAN events (e.g., IP changes).

log_info() {
    logger -st "($(basename "$0"))" "$$ $*"
}

Kill_Lock() {
  if [ -f "$LOCK_FILE" ] && [ -d "/proc/$(sed -n '2p' $LOCK_FILE)" ]; then
    log_info "Killing Locked Processes ($(sed -n '1p' $LOCK_FILE)) (pid=$(sed -n '2p' $LOCK_FILE))"
    log_info "$(ps | awk -v pid="$(sed -n '2p' $LOCK_FILE)" '$1 == pid')"
    kill "$(sed -n '2p' $LOCK_FILE)"
    rm -rf $LOCK_FILE
    echo
  fi
}

Check_Lock() {
  TRIES=0
  MAX_TRIES=60
  while [ "$TRIES" -lt "$MAX_TRIES" ]; do
    if [ -f "$LOCK_FILE" ]; then
      log_info "x3mRouting Lock File in use by PID $(sed -n '2p' $LOCK_FILE) - wait time $(((MAX_TRIES * 3) - (TRIES * 3) - 3)) secs left"
      sleep 3
      TRIES=$((TRIES + 1))
      [ "$TRIES" -eq $((MAX_TRIES - 1)) ] && Kill_Lock # automatically kill lock once MAX_TRIES is reached
    else
      echo "$@" >$LOCK_FILE
      echo "$$" >>$LOCK_FILE
      date +%s >>$LOCK_FILE
      lockx3mRouting="true"
      TRIES="$MAX_TRIES"
    fi
  done
}

release_lock() {
    [ -f "$LOCK_FILE" ] && rm -f "$LOCK_FILE"
}

Error_Exit() {
  if [ "$lockx3mRouting" = "true" ]; then release_lock; fi
  log_info "ERROR! $*"
  exit 1
}

Exit_Routine() {
  if [ "$lockx3mRouting" = "true" ]; then release_lock; fi
  log_info "Completed Script Execution"
  exit 0
}

Chk_Entware() {

  # ARGS [wait attempts] [specific_entware_utility]
  READY=1          # Assume Entware Utilities are NOT available
  ENTWARE_UTILITY= # Specific Entware utility to search for
  MAX_TRIES=30

  if [ -n "$2" ] && [ "$2" -eq "$2" ] 2>/dev/null; then
    MAX_TRIES="$2"
  elif [ -z "$2" ] && [ "$1" -eq "$1" ] 2>/dev/null; then
    MAX_TRIES="$1"
  fi

  if [ -n "$1" ] && ! [ "$1" -eq "$1" ] 2>/dev/null; then
    ENTWARE_UTILITY="$1"
  fi

  # Wait up to (default) 30 seconds to see if Entware utilities available.....
  TRIES="0"

  while [ "$TRIES" -lt "$MAX_TRIES" ]; do
    if [ -f "/opt/bin/opkg" ]; then
      if [ -n "$ENTWARE_UTILITY" ]; then # Specific Entware utility installed?
        if [ -n "$(opkg list-installed "$ENTWARE_UTILITY")" ]; then
          READY="0" # Specific Entware utility found
        else
          # Not all Entware utilities exists as a stand-alone package e.g. 'find' is in package 'findutils'
          if [ -d /opt ] && [ -n "$(find /opt/ -name "$ENTWARE_UTILITY")" ]; then
            READY="0" # Specific Entware utility found
          fi
        fi
      else
        READY="0" # Entware utilities ready
      fi
      break
    fi
    sleep 1
    log_info "Entware $ENTWARE_UTILITY not available - wait time $((MAX_TRIES - TRIES - 1)) secs left"
    TRIES=$((TRIES + 1))
  done
  return "$READY"
}

# Define fwmark/bitmask to route traffic through the interfaces below.
Set_Fwmark_Params() {
  FWMARK_WAN="0x8000/0xf000"    # Main WAN connection
  FWMARK_OVPNC1="0x1000/0xf000" # OpenVPN connection 1
  FWMARK_OVPNC2="0x2000/0xf000" # OpenVPN connection 2
  FWMARK_OVPNC3="0x4000/0xf000" # OpenVPN connection 3
  FWMARK_OVPNC4="0x7000/0xf000" # OpenVPN connection 4
  FWMARK_OVPNC5="0x3000/0xf000" # OpenVPN connection 5
  FWMARK_WGC1="0xa000/0xf000"   # WireGuard connection 1
  FWMARK_WGC2="0xb000/0xf000"   # WireGuard connection 2
  FWMARK_WGC3="0xc000/0xf000"   # WireGuard connection 3
  FWMARK_WGC4="0xd000/0xf000"   # WireGuard connection 4
  FWMARK_WGC5="0xe000/0xf000"   # WireGuard connection 5
}

Set_IP_Rule() {
  vpn_id="$1"

  case "$vpn_id" in
  0) priority=9980 ;; # WAN
  1) priority=9999 ;; # OVPNC1
  2) priority=9998 ;; # OVPNC2
  3) priority=9997 ;; # OVPNC3
  4) priority=9996 ;; # OVPNC4
  5) priority=9995 ;; # OVPNC5
  11) priority=9994 ;; # WGC1
  12) priority=9993 ;; # WGC2
  13) priority=9992 ;; # WGC3
  14) priority=9991 ;; # WGC4
  15) priority=9990 ;; # WGC5
  *) Error_Exit "$vpn_id should be 0-WAN or 1/2/3/4/5 for OPENVPN Client or 11/12/13/14/15 for WireGuard Client" ;;
  esac

  if ! ip rule | grep -q "$TAG_MARK"; then
    ip rule add from 0/0 fwmark "$TAG_MARK" table "$ROUTE_TABLE" prio "$priority" && log_info "Created fwmark $TAG_MARK"
    ip route flush cache
  fi
}

Create_Ipset_List() {

  IPSET_NAME=$1
  METHOD=$2

  Chk_Entware 120
  if [ "$READY" -eq 1 ]; then Error_Exit "Entware not ready. Unable to access ipset save/restore location"; fi
  if [ "$(ipset list -n "$IPSET_NAME" 2>/dev/null)" != "$IPSET_NAME" ]; then # does ipset list exist?
    if [ -s "$DIR/$IPSET_NAME" ]; then                                       # does ipset restore file exist?
      if [ "$METHOD" = "DNSMASQ" ]; then
        ipset restore -! <"$DIR/$IPSET_NAME"
        log_info "IPSET restored: $IPSET_NAME from $DIR/$IPSET_NAME"
      else
        ipset create "$IPSET_NAME" hash:net family inet hashsize 1024 maxelem 65536
        log_info "IPSET created: $IPSET_NAME"
      fi
    else                                                                          # method = ASN, MANUAL or AWS
      ipset create "$IPSET_NAME" hash:net family inet hashsize 1024 maxelem 65536 # No restore file, so create ipset list from scratch
      log_info "IPSET created: $IPSET_NAME hash:net family inet hashsize 1024 maxelem 65536"
    fi
  fi

}

# Function to add an entry to a file, creating the file with shebang if it doesn't exist
add_entry_to_file() {
  file="$1"
  entry="$2"

  if [ ! -f "$file" ]; then
    echo '#!/bin/sh' > "$file" && chmod 755 "$file"
  fi
  if ! grep -Fq "$entry" "$file"; then
    echo "$entry # x3mRouting for ipset name $IPSET_NAME" >> "$file"
    log_info "$entry added to $file"
  fi
}

# Function to delete an entry from a file
delete_entry_from_file() {
  FILE="$1"
  PATTERN="$2"
  if [ -s "$FILE" ]; then
    sed -i "\~\b$PATTERN\b~d" "$FILE"
    log_info "Entry matching '$PATTERN' deleted from $FILE"
    Check_For_Shebang "$FILE"
  fi
}

# Route IPSET to target WAN or VPN
Create_Routing_Rules() {
  IPSET_NAME=$1

  eval "iptables -t mangle -D PREROUTING -i br0 -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK 2>/dev/null"
  log_info "Selective Routing Rule via $TARGET_DESC deleted for $IPSET_NAME fwmark $TAG_MARK"

#  iptables -t mangle -A PREROUTING -i br0 -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK
  eval "iptables -t mangle -A PREROUTING -i br0 -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK"
  log_info "Selective Routing Rule via $TARGET_DESC created for $IPSET_NAME fwmark $TAG_MARK"
}

set_wg_rp_filter() {
    # Check if $ROUTE_TABLE starts with 'wgc'
    if [ "${ROUTE_TABLE#wgc}" != "$ROUTE_TABLE" ]; then
      # Here we set the reverse path filtering mode for the interface 'wgc*'.
      # This setting is only necessary for WireGuard. OpenVPN on Asuswrt-Merlin defaults to '0'.
      # 0 - Disables reverse path filtering, accepting all packets without verifying the source route.
      # 1 - Enables strict mode, accepting packets only if the route to the source IP matches the incoming interface.
      # 2 - Enables loose mode, allowing packets to be accepted on any interface as long as a route to the source IP exists.
      rp_filter="echo 2 >/proc/sys/net/ipv4/conf/$ROUTE_TABLE/rp_filter"
      eval "$rp_filter"

      # Ensure 'rp_filter' is applied persistently across reboots.
      add_entry_to_file "$NAT_START" "$rp_filter"
      add_entry_to_file "$WAN_EVENT" "$rp_filter"
      add_entry_to_file "$WG_START" "$rp_filter"
    fi
}

Check_For_Shebang() {
  CLIENTX_FILE=$1
  SHEBANG_COUNT=0
  EMPTY_LINE_COUNT=0
  NOT_EMPTY_LINE_COUNT=0

  if [ -f "$CLIENTX_FILE" ]; then # file exists
    while read -r LINE || [ -n "$LINE" ]; do
      if [ "$LINE" = "#!/bin/sh" ]; then
        SHEBANG_COUNT=$((SHEBANG_COUNT + 1))
        continue
      fi

      if [ -z "$LINE" ]; then
        EMPTY_LINE_COUNT=$((EMPTY_LINE_COUNT + 1))
      else
        NOT_EMPTY_LINE_COUNT=$((NOT_EMPTY_LINE_COUNT + 1))
      fi

    done <"$CLIENTX_FILE"
  else
    return
  fi

  if [ "$NOT_EMPTY_LINE_COUNT" -eq 0 ]; then
    if [ "$DEL_FLAG" = "del" ]; then
      printf '\n\n%s\n' "$CLIENTX_FILE has $SHEBANG_COUNT shebang entry and $EMPTY_LINE_COUNT empty lines."
      printf '%s\n' "Would you like to remove $CLIENTX_FILE?"
      printf '%b[1]%b  --> Yes\n' "${COLOR_GREEN}" "${COLOR_WHITE}"
      printf '%b[2]%b  --> No\n' "${COLOR_GREEN}" "${COLOR_WHITE}"
      echo
      printf '[1-2]: '
      read -r "OPTION"
      case "$OPTION" in
      1)
        rm "$CLIENTX_FILE"
        echo "$CLIENTX_FILE file deleted"
        return
        ;;
      2) return ;;
      *) echo "[*] $OPTION Isn't An Option!" ;;
      esac
    elif [ "$DEL_FLAG" = "FORCE" ]; then # force delete file w/o prompt
      rm "$CLIENTX_FILE"
      echo "$CLIENTX_FILE file deleted"
    fi
  fi

}

Check_Nat_Start_For_Entries() {
  IPSET_NAME=$1
  OPT1=$2
  DIR=$3

  if [ "$(echo "$OPT1" | grep -c "Manual")" -ge 1 ]; then # 1 parm passed
    SCRIPT_ENTRY="sh $SCR_DIR/x3mRouting.sh ipset_name=$IPSET_NAME"
  else # OPT1 parm passed e.g. dnsmasq=, aws_region=, asnum=, ip=
    SCRIPT_ENTRY="sh $SCR_DIR/x3mRouting.sh ipset_name=$IPSET_NAME $OPT1"
  fi

  if [ "$DIR" != "/opt/tmp" ]; then
    if [ "$(echo "$@" | grep -c 'asnum=')" -eq 0 ]; then
      SCRIPT_ENTRY="$SCRIPT_ENTRY dir=$DIR"
    fi
  fi

  add_entry_to_file "$NAT_START" "$SCRIPT_ENTRY"
}

Check_Files_For_Entries() {
  SRC_IFACE=$1
  DST_IFACE=$2
  IPSET_NAME=$3
  OPT1=$4
  DIR=$5

  if [ "$(echo "$OPT1" | grep -c "Manual")" -ge 1 ]; then # 1 parm passed
    SCRIPT_ENTRY="sh $SCR_DIR/x3mRouting.sh $SRC_IFACE $DST_IFACE $IPSET_NAME"
  else # OPT1 parm passed e.g. dnsmasq=, aws_region=, asnum=, ip=
    SCRIPT_ENTRY="sh $SCR_DIR/x3mRouting.sh $SRC_IFACE $DST_IFACE $IPSET_NAME $OPT1"
  fi

  if [ "$DIR" != "/opt/tmp" ]; then
    SCRIPT_ENTRY="$SCRIPT_ENTRY dir=$DIR"
  fi

  if [ "$SRC_IFACE" = "ALL" ]; then
    VPNID=$DST_IFACE
  else
    VPNID=$SRC_IFACE
  fi

  IPTABLES_DEL_ENTRY="iptables -t mangle -D PREROUTING -i br0 -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK 2>/dev/null"
  IPTABLES_ADD_ENTRY="iptables -t mangle -A PREROUTING -i br0 -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK"
  VPNC_UP_FILE="$SCR_DIR/vpnclient${VPNID}-route-up"
  VPNC_DOWN_FILE="$SCR_DIR/vpnclient${VPNID}-route-pre-down"

  for IPTABLES_ENTRY in "$IPTABLES_DEL_ENTRY" "$IPTABLES_ADD_ENTRY"; do
    add_entry_to_file "$VPNC_UP_FILE" "$IPTABLES_ENTRY"
  done
  add_entry_to_file "$VPNC_DOWN_FILE" "$IPTABLES_DEL_ENTRY"
  add_entry_to_file "$NAT_START" "$SCRIPT_ENTRY"
}

Process_Src_Option() {
  SRC_IFACE=$1
  DST_IFACE=$2
  IPSET_NAME=$3
  SRC=$(echo "$@" | sed -n "s/^.*src=//p" | awk '{print $1}')
  SRC_RANGE=$(echo "$@" | sed -n "s/^.*src_range=//p" | awk '{print $1}')
  if [ "$(echo "$@" | grep -c 'dir=')" -gt 0 ]; then
    DIR=$(echo "$@" | sed -n "s/^.*dir=//p" | awk '{print $1}') # v1.2 Mount point/directory for backups
  else
    DIR="/opt/tmp"
  fi

  if [ "$(echo "$@" | grep -c 'asnum=')" -gt 0 ]; then
    ASN=$(echo "$@" | sed -n "s/^.*asnum=//p" | awk '{print $1}')
    X3M_METHOD="asnum=${ASN}"
  elif [ "$(echo "$@" | grep -c 'aws_region=')" -gt 0 ]; then
    AWS_REGION=$(echo "$@" | sed -n "s/^.*aws_region=//p" | awk '{print $1}')
    X3M_METHOD="aws_region=${AWS_REGION}"
  elif [ "$(echo "$@" | grep -c 'dnsmasq=')" -gt 0 ]; then
    DOMAINS=$(echo "$@" | sed -n "s/^.*dnsmasq=//p" | awk '{print $1}')
    X3M_METHOD="dnsmasq=${DOMAINS}"
  elif [ "$(echo "$@" | grep -c 'dnsmasq_file=')" -gt 0 ]; then
    DNSMASQ_FILE=$(echo "$@" | sed -n "s/^.*dnsmasq_file=//p" | awk '{print $1}')
    X3M_METHOD="dnsmasq_file=${DNSMASQ_FILE}"
  else
    X3M_METHOD="Manual"
  fi

  # Create the IPSET list first!
  while true; do
    # Check for 'dnsmasq=' parm
    if [ "$(echo "$@" | grep -c 'dnsmasq=')" -gt 0 ] || [ "$(echo "$@" | grep -c 'dnsmasq_file=')" -gt 0 ]; then
      DNSMASQ_Parm $@
      break
    fi
    # Check for 'autoscan=' parm
    if [ "$(echo "$@" | grep -c 'autoscan=')" -gt 0 ]; then
      Dnsmasq_Log_File
      Harvest_Domains $@
      break
    fi
    # check if 'asnum=' parm
    if [ "$(echo "$@" | grep -c 'asnum=')" -gt 0 ]; then
      ASNUM_Parm $@
      break
    fi
    # check if 'aws_region=' parm
    if [ "$(echo "$@" | grep -c 'aws_region=')" -gt 0 ]; then
      AWS_Region_Parm $@
      break
    fi
    # Manual Method
    if [ "$X3M_METHOD" = "Manual" ]; then
      Manual_Method $@
      break
    fi
  done

  # Manual Method to create ipset list if IP address specified
  if [ -n "$SRC" ]; then
    if [ "$X3M_METHOD" = "Manual" ]; then #
      SCRIPT_ENTRY="sh $SCR_DIR/x3mRouting.sh $SRC_IFACE $DST_IFACE $IPSET_NAME src=${SRC}"
      [ "$DIR" != "/opt/tmp" ] && SCRIPT_ENTRY="sh $SCR_DIR/x3mRouting.sh $SRC_IFACE $DST_IFACE $IPSET_NAME src=${SRC} dir=${DIR}"
      Manual_Method $@
    else
      SCRIPT_ENTRY="sh $SCR_DIR/x3mRouting.sh $SRC_IFACE $DST_IFACE $IPSET_NAME $X3M_METHOD src=${SRC}"
      [ "$DIR" != "/opt/tmp" ] && SCRIPT_ENTRY="sh $SCR_DIR/x3mRouting.sh $SRC_IFACE $DST_IFACE $IPSET_NAME $X3M_METHOD src=${SRC} dir=${DIR}"
    fi
    IPTABLES_DEL_ENTRY="iptables -t mangle -D PREROUTING -i br0 --src $SRC -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK 2>/dev/null"
    IPTABLES_ADD_ENTRY="iptables -t mangle -A PREROUTING -i br0 --src $SRC -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK"
    # Create routing rules
    eval "$IPTABLES_DEL_ENTRY"
    eval "$IPTABLES_ADD_ENTRY"
  fi

  if [ -n "$SRC_RANGE" ]; then
    if [ "$X3M_METHOD" = "Manual" ]; then
      SCRIPT_ENTRY="sh $SCR_DIR/x3mRouting.sh $SRC_IFACE $DST_IFACE $IPSET_NAME src_range=${SRC_RANGE}"
      [ "$DIR" != "/opt/tmp" ] && SCRIPT_ENTRY="sh $SCR_DIR/x3mRouting.sh $SRC_IFACE $DST_IFACE $IPSET_NAME src_range=${SRC_RANGE} dir=${DIR}"
      Manual_Method $@
    else
      SCRIPT_ENTRY="sh $SCR_DIR/x3mRouting.sh $SRC_IFACE $DST_IFACE $IPSET_NAME $X3M_METHOD src_range=${SRC_RANGE}"
      [ "$DIR" != "/opt/tmp" ] && SCRIPT_ENTRY="sh $SCR_DIR/x3mRouting.sh $SRC_IFACE $DST_IFACE $IPSET_NAME $X3M_METHOD src_range=${SRC_RANGE} dir=${DIR}"
    fi
    IPTABLES_DEL_ENTRY="iptables -t mangle -D PREROUTING -i br0 -m iprange --src-range $SRC_RANGE -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK 2>/dev/null"
    IPTABLES_ADD_ENTRY="iptables -t mangle -A PREROUTING -i br0 -m iprange --src-range $SRC_RANGE -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK"
    # Create routing rules
    eval "$IPTABLES_DEL_ENTRY"
    eval "$IPTABLES_ADD_ENTRY"
  fi

  if [ "$SRC_IFACE" = "ALL" ]; then
    VPNID=$DST_IFACE
  else
    VPNID=$SRC_IFACE
  fi

  VPNC_UP_FILE="$SCR_DIR/vpnclient${VPNID}-route-up"
  VPNC_DOWN_FILE="$SCR_DIR/vpnclient${VPNID}-route-pre-down"

  for IPTABLES_ENTRY in "$IPTABLES_DEL_ENTRY" "$IPTABLES_ADD_ENTRY"; do
    add_entry_to_file "$VPNC_UP_FILE" "$IPTABLES_ENTRY"
  done
  add_entry_to_file "$VPNC_DOWN_FILE" "$IPTABLES_DEL_ENTRY"
  add_entry_to_file "$NAT_START" "$SCRIPT_ENTRY"
}

Process_DNSMASQ() {
  IPSET_NAME=$1
  dnsmasq_entry="ipset=$2"
  DIR=$3

  if [ -f "/jffs/configs/dnsmasq.conf.add" ]; then
    if ! grep -qw "$dnsmasq_entry" /jffs/configs/dnsmasq.conf.add; then
      echo "$dnsmasq_entry" >>/jffs/configs/dnsmasq.conf.add
      log_info "Added $dnsmasq_entry to dnsmasq.conf.add"
    fi
  else
    echo "$dnsmasq_entry" > /jffs/configs/dnsmasq.conf.add # if dnsmasq.conf.add does not exist, create dnsmasq.conf.add
    log_info "Created dnsmasq.conf.add with $dnsmasq_entry"
  fi
  service restart_dnsmasq >/dev/null 2>&1 && log_info "Restart dnsmasq service"

  Create_Ipset_List "$IPSET_NAME" "DNSMASQ"

  if [ -d "$DIR" ]; then
    if [ "$(find "$DIR" -name "$IPSET_NAME" -mtime +1 -print 2>/dev/null)" = "$DIR/$IPSET_NAME" ]; then
      ipset save "$IPSET_NAME" >"$DIR/$IPSET_NAME"
    fi
  fi

  cru l | grep "$IPSET_NAME" || cru a "$IPSET_NAME" "0 2 * * * ipset save $IPSET_NAME > $DIR/$IPSET_NAME" >/dev/null 2>&1 && log_info "CRON schedule created: #$IPSET_NAME# '0 2 * * * ipset save $IPSET_NAME'"
}

Download_ASN_Ipset_List() {
  IPSET_NAME=$1
  ASN=$2

  curl -fsL --retry 3 --connect-timeout 3 "https://api.bgpview.io/asn/$ASN/prefixes" | grep -oE '.{20}([0-9]{1,3}\.){3}[0-9]{1,3}\\/[0-9]{1,2}' | grep -vF "parent" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}\\/[0-9]{1,2}' | tr -d "\\" | awk '{printf "add '"$IPSET_NAME"' %s\n", $1 }' | awk '!x[$0]++' | ipset restore -!
}

Load_MANUAL_Ipset_List() {
  IPSET_NAME=$1
  DIR=$2

  if [ "$(ipset list -n "$IPSET_NAME" 2>/dev/null)" = "$IPSET_NAME" ]; then #does ipset list exist?
    [ -s "$DIR/$IPSET_NAME" ] && awk '{print "add '"$IPSET_NAME"' " $1}' "$DIR/$IPSET_NAME" | ipset restore -!
  fi
}

# Download Amazon AWS json file
Download_AMAZON() {
  DIR=$1

  if [ -s "$DIR/ip-ranges.json" ]; then
    if [ "$(find "$DIR" -name "ip-ranges.json" -mtime +7 -print)" = "$DIR/ip-ranges.json" ]; then
      STATUS=$(curl --retry 3 -sL -o "$DIR/ip-ranges.json" -w '%{http_code}' "https://ip-ranges.amazonaws.com/ip-ranges.json")
      if [ "$STATUS" -eq 200 ]; then
        log_info "Download of https://ip-ranges.amazonaws.com/ip-ranges.json successful."
      else
        log_info "Download of https://ip-ranges.amazonaws.com/ip-ranges.json failed. Using existing file."
      fi
    fi
  else
    STATUS=$(curl --retry 3 -sL -o "$DIR/ip-ranges.json" -w '%{http_code}' "https://ip-ranges.amazonaws.com/ip-ranges.json")
    if [ "$STATUS" -eq 200 ]; then
      log_info "Download of https://ip-ranges.amazonaws.com/ip-ranges.json successful."
    else
      Error_Exit "Download of https://ip-ranges.amazonaws.com/ip-ranges.json failed."
    fi
  fi
}

Load_AWS_Ipset_List() {
  IPSET_NAME=$1
  REGION=$2
  DIR=$3

  Download_AMAZON "$DIR"

  if [ ! -s "$DIR/$IPSET_NAME" ]; then
    true >"$DIR/$IPSET_NAME"
  fi

  # don't quote the parameter so it is treated like an array!
  for REGION in $REGION; do
    jq '.prefixes[] | select(.region=='\""$REGION"\"') | .ip_prefix' <"$DIR/ip-ranges.json" | sed 's/"//g' >>"$DIR/$IPSET_NAME"
  done
  sort -gt '/' -k 1 "$DIR/$IPSET_NAME" | sort -ut '.' -k 1,1n -k 2,2n -k 3,3n -k 4,4n >"$DIR/${IPSET_NAME}_tmp"
  mv "$DIR/${IPSET_NAME}_tmp" "$DIR/$IPSET_NAME"
  awk '{print "add '"$IPSET_NAME"' " $1}' "$DIR/$IPSET_NAME" | ipset restore -!
}

Delete_Ipset_List() {

  IPSET_NAME=$1
  DIR=$2

  # Check /jffs/configs/dnsmasq.conf.add for IPSET entry and remove if found
  if [ -s /jffs/configs/dnsmasq.conf.add ]; then
    delete_entry_from_file "/jffs/configs/dnsmasq.conf.add" "$IPSET_NAME"
    service restart_dnsmasq >/dev/null 2>&1 && log_info "Restart dnsmasq service"
  fi

  delete_entry_from_file "$NAT_START" "$IPSET_NAME"
  delete_entry_from_file "$WG_START" "$IPSET_NAME"
  delete_entry_from_file "$WAN_EVENT" "$IPSET_NAME"

  for VPNID in $VPN_IDS; do
    VPNC_UP_FILE="$SCR_DIR/vpnclient${VPNID}-route-up"
    VPNC_DOWN_FILE="$SCR_DIR/vpnclient${VPNID}-route-pre-down"
    delete_entry_from_file "$VPNC_UP_FILE" "$IPSET_NAME"
    delete_entry_from_file "$VPNC_DOWN_FILE" "$IPSET_NAME"
  done

  #Check_Cron_Job
  log_info "Checking crontab..."
  if cru l | grep "$IPSET_NAME" 2>/dev/null; then
    cru d "$IPSET_NAME" "0 2 * * * ipset save $IPSET_NAME" 2>/dev/null
    log_info "CRON schedule deleted: #$IPSET_NAME# '0 2 * * * ipset save $IPSET_NAME'"
  fi

  log_info "Checking PREROUTING iptables rules..."
  # Extract the last field (fwmark) from the iptables rule that matches the IP set name.
  FWMARKS=$(iptables -nvL PREROUTING -t mangle --line | grep -w "$IPSET_NAME" | awk '{print $(NF)}')

  if [ -n "$FWMARKS" ]; then
    # Delete PREROUTING Rules for Normal IPSET routing
    iptables -nvL PREROUTING -t mangle --line | grep "br0" | grep "$IPSET_NAME " | grep "match-set" | awk '{print $1, $12}' | sort -nr | while read -r CHAIN_NUM IPSET_NAME; do
      iptables -t mangle -D PREROUTING "$CHAIN_NUM" && log_info "Deleted PREROUTING Chain $CHAIN_NUM for IPSET List $IPSET_NAME"
    done
    # Delete the fwmark priority if no IPSET lists are using it
    for FWMARK in $FWMARKS; do
      if ! iptables -nvL PREROUTING -t mangle --line | grep -m 1 -w "$FWMARK"; then
        ip rule del fwmark "$FWMARK" 2>/dev/null && log_info "Deleted fwmark $FWMARK"
      fi
    done
  fi

  # Delete PREROUTING Rule for VPN Server to IPSET & POSTROUTING Rule
  log_info "Checking POSTROUTING iptables rules..."
  for SERVER_TUN in tun21 tun22 wgs1; do
    SERVER=$(echo "$SERVER_TUN" | awk '{print substr($0, length($0), 1)}')
    TUN="$(iptables -nvL PREROUTING -t mangle --line | grep "$SERVER_TUN" | grep "$IPSET_NAME" | grep "match-set" | awk '{print $7}')"
    if [ -n "$TUN" ]; then
      Define_IFACE "$IPSET_NAME"
      VPN_CLIENT_INSTANCE=$(echo "$IFACE" | awk '{print substr($0, length($0), 1)}')
      VPN_Server_to_IPSET "$SERVER" "$VPN_CLIENT_INSTANCE" "$IFACE" "$IPSET_NAME" "$TAG_MARK" "del"
    fi
  done

  # Destroy the IPSET list
  log_info "Checking if IPSET list $IPSET_NAME exists..."
  if [ "$(ipset list -n "$IPSET_NAME" 2>/dev/null)" = "$IPSET_NAME" ]; then
    if ipset destroy "$IPSET_NAME"; then
      log_info "IPSET $IPSET_NAME deleted!"
    else
      Error_Exit "attempting to delete IPSET $IPSET_NAME!"
    fi
  fi

  log_info "Checking if IPSET backup file exists..."
  if [ -s "$DIR/$IPSET_NAME" ]; then
    if [ "$DEL_FLAG" = "del" ]; then
      while true; do
        printf '\n%b%s%b\n' "$COLOR_RED" "DANGER ZONE!" "$COLOR_WHITE"
        printf '\n%s%b%s%b\n' "Delete the backup file in " "$COLOR_GREEN" "$DIR/$IPSET_NAME" "$COLOR_WHITE"
        printf '%b[1]%b  --> Yes\n' "$COLOR_GREEN" "$COLOR_WHITE"
        printf '%b[2]%b  --> No\n' "$COLOR_GREEN" "$COLOR_WHITE"
        echo
        printf '[1-2]: '
        read -r "CONFIRM_DEL"
        case "$CONFIRM_DEL" in
        1)
          rm "$DIR/$IPSET_NAME" && printf '\n%b%s%b%s\n' "$COLOR_GREEN" "$DIR/$IPSET_NAME" "$COLOR_WHITE" " file deleted."
          echo
          return
          ;;
        *) return ;;
        esac
      done
    elif [ "$DEL_FLAG" = "FORCE" ]; then
      rm "$DIR/$IPSET_NAME" && printf '\n%b%s%b%s\n' "$COLOR_GREEN" "$DIR/$IPSET_NAME" "$COLOR_WHITE" " file deleted."
    fi
  fi

}

DNSMASQ_Parm() {

  if [ "$(echo "$@" | grep -c "dnsmasq_file=")" -eq 1 ]; then
    DNSMASQ_FILE=$(echo "$@" | sed -n "s/^.*dnsmasq_file=//p" | awk '{print $1}')
    if [ -s "$DNSMASQ_FILE" ]; then
      while read -r DOMAINS; do
        COMMA_DOMAINS_LIST="$COMMA_DOMAINS_LIST,$DOMAINS"
      done <"$DNSMASQ_FILE"
      DOMAINS="$(echo "$COMMA_DOMAINS_LIST" | sed 's/^,*//;')"
    fi
    if [ -s "/jffs/configs/dnsmasq.conf.add" ]; then
      sed -i "\~ipset=.*$IPSET_NAME~d" /jffs/configs/dnsmasq.conf.add
    fi
  fi
  if [ "$(echo "$@" | grep -c "dnsmasq=")" -eq 1 ]; then
    DOMAINS=$(echo "$@" | sed -n "s/^.*dnsmasq=//p" | awk '{print $1}')
  fi
  DOMAINS_LIST=$(echo "$DOMAINS" | sed 's/,$//' | tr ',' '/')
  DNSMASQ_ENTRY="/$DOMAINS_LIST/$IPSET_NAME"
  Process_DNSMASQ "$IPSET_NAME" "$DNSMASQ_ENTRY" "$DIR"

}

ASNUM_Parm() {

  ASN=$(echo "$@" | sed -n "s/^.*asnum=//p" | awk '{print $1}' | tr ',' ' ')

  for ASN in $ASN; do
    PREFIX=$(printf '%-.2s' "$ASN")
    NUMBER="$(echo "$ASN" | sed 's/^AS//')"
    if [ "$PREFIX" = "AS" ]; then
      # Check for valid Number and skip if bad
      A=$(echo "$NUMBER" | grep -oE '^\-?[0-9]+$')
      if [ -z "$A" ]; then
        echo "Skipping invalid ASN: $NUMBER"
      else
        Create_Ipset_List "$IPSET_NAME" "ASN"
        Download_ASN_Ipset_List "$IPSET_NAME" "$ASN"
      fi
    else
      Error_Exit "Invalid Prefix specified: $PREFIX. Valid value is 'AS'"
    fi
  done

}

AWS_Region_Parm() {

  AWS_REGION=$(echo "$@" | sed -n "s/^.*aws_region=//p" | awk '{print $1}' | tr ',' ' ')
  for AWS_REGION in $AWS_REGION; do
    case "$AWS_REGION" in
    AP) REGION="ap-east-1 ap-northeast-1 ap-northeast-2 ap-northeast-3 ap-south-1 ap-southeast-1 ap-southeast-2" ;;
    CA) REGION="ca-central-1" ;;
    CN) REGION="cn-north-1 cn-northwest-1" ;;
    EU) REGION="eu-central-1 eu-north-1 eu-west-1 eu-west-2 eu-west-3" ;;
    SA) REGION="sa-east-1" ;;
    US) REGION="us-east-1 us-east-2 us-west-1 us-west-2" ;;
    GV) REGION="us-gov-east-1 us-gov-west-1" ;;
    GLOBAL) REGION="GLOBAL" ;;
    *) Error_Exit "Invalid AMAZON region specified: $AWS_REGION. Valid values are: AP CA CN EU SA US GV GLOBAL" ;;
    esac
    Create_Ipset_List "$IPSET_NAME" "AWS"
    Load_AWS_Ipset_List "$IPSET_NAME" "$REGION" "$DIR"
  done

}

Manual_Method() {

  Chk_Entware 60
  if [ "$READY" -eq 1 ]; then Error_Exit "Entware not ready. Unable to access ipset save/restore location"; fi
  ############## Special Processing for 'ip=' parameter
  if [ "$(echo "$@" | grep -c 'ip=')" -gt 0 ]; then
    IP=$(echo "$@" | sed -n "s/^.*ip=//p" | awk '{print $1}')
    [ -s "$DIR/$IPSET_NAME" ] || true >"/opt/tmp/$IPSET_NAME"
    true >"/opt/tmp/${SCR_NAME}" # create tmp file for loop processing
    for IPv4 in $(echo "$IP" | tr ',' '\n'); do
      awk -v A="$IPv4" 'BEGIN {print A}' >>"/opt/tmp/${SCR_NAME}"
      while read -r IPv4; do
        # check for IPv4 format
        A=$(echo "$IPv4" | grep -oE "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
        if [ -z "$A" ]; then # If null, then didn't pass check for IPv4 Format.
          # Check for IPv4 CIDR Format https://unix.stackexchange.com/questions/505115/regex-expression-for-ip-address-cidr-in-bash
          A=$(echo "$IPv4" | grep -oE "^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}/([0-9]|[12][0-9]|3[012])$")
          if [ -z "$A" ]; then
            printf '"%s" is not a valid CIDR address. Skipping entry.\n' "$IPv4"
          else
            printf '%s\n' "$IPv4" >>"$DIR/$IPSET_NAME" && printf '%s\n' "Successfully added CIDR $IPv4"
          fi
        else
          printf '%s\n' "$IPv4" >>"$DIR/$IPSET_NAME" && printf '%s\n' "Successfully added $IPv4"
        fi
      done <"/opt/tmp/${SCR_NAME}"
      rm "/opt/tmp/${SCR_NAME}"
      # remove any duplicate entries that may have gotten added
      sort -gt '/' -k 1 "$DIR/$IPSET_NAME" | sort -ut '.' -k 1,1n -k 2,2n -k 3,3n -k 4,4n >"$DIR/${IPSET_NAME}_tmp"
      mv "$DIR/${IPSET_NAME}_tmp" "$DIR/$IPSET_NAME"
    done
  fi
  ############## End of Special Processing for 'ip=' parameter

  if [ -s "$DIR/$IPSET_NAME" ]; then
    if grep -q "create" "$DIR/$IPSET_NAME"; then
      Error_Exit "$DIR/$IPSET_NAME save/restore file is in dnsmasq format. The Manual Method requires IPv4 format."
    fi
    Create_Ipset_List "$IPSET_NAME" "MANUAL"
    Load_MANUAL_Ipset_List "$IPSET_NAME" "$DIR"
  else
    Error_Exit "The save/restore file $DIR/$IPSET_NAME does not exist."
  fi
}

VPN_Server_to_VPN_Client() {
  VPN_SERVER_INSTANCE=$1
  IFACE=$2
  VPN_CLIENT_INSTANCE=$3
  DEL_FLAG=$4
  SERVER="server=$VPN_SERVER_INSTANCE"
  CLIENT="client=$VPN_CLIENT_INSTANCE"
  SCRIPT_ENTRY="sh $SCRIPT_DIR/x3mRouting.sh $SERVER $CLIENT"
  VPN_SERVER_SUBNET="$(nvram get vpn_server"${VPN_SERVER_INSTANCE}"_sn)/24"
  IPTABLES_DEL_ENTRY="iptables -t nat -D POSTROUTING -s \"\$(nvram get vpn_server${VPN_SERVER_INSTANCE}_sn)\"/24 -o $IFACE -p tcp -m multiport --dports 80,443 -j MASQUERADE 2>/dev/null"
  IPTABLES_ADD_ENTRY="iptables -t nat -A POSTROUTING -s \"\$(nvram get vpn_server${VPN_SERVER_INSTANCE}_sn)\"/24 -o $IFACE -p tcp -m multiport --dports 80,443 -j MASQUERADE"
  VPNC_UP_FILE="$SCRIPT_DIR/vpnclient${VPN_CLIENT_INSTANCE}-route-up"
  VPNC_DOWN_FILE="$SCRIPT_DIR/vpnclient${VPN_CLIENT_INSTANCE}-route-pre-down"
  POLICY_RULE_WITHOUT_NAME="${VPN_SERVER_SUBNET}>>VPN"
  POLICY_RULE="<VPN Server ${VPN_SERVER_INSTANCE}>${VPN_SERVER_SUBNET}>>VPN"

  VPN_IP_LIST="$(nvram get vpn_client"$VPN_CLIENT_INSTANCE"_clientlist)"
  for n in $VPN_IDS; do
    VPN_IP_LIST="${VPN_IP_LIST}$(nvram get vpn_client"$VPN_CLIENT_INSTANCE"_clientlist"${n}")"
  done

  if [ -z "$DEL_FLAG" ]; then # add entry if DEL_FLAG is null
    eval "$IPTABLES_DEL_ENTRY"
    eval "$IPTABLES_ADD_ENTRY"
    # vpnclientX-route-up File
    if [ -s "$VPNC_UP_FILE" ]; then
      # Check if an existing entry exists
      for IPTABLES_ENTRY in "$IPTABLES_DEL_ENTRY" "$IPTABLES_ADD_ENTRY"; do
        if [ "$(grep -cw "$IPTABLES_ENTRY" "$VPNC_UP_FILE")" -eq 0 ]; then # if true, add entry
          echo "$IPTABLES_ENTRY" >>"$VPNC_UP_FILE"
          # Implement routing rules
          iptables -t nat -D POSTROUTING -s "$VPN_SERVER_SUBNET" -o "$IFACE" -p tcp -m multiport --dports 80,443 -j MASQUERADE 2>/dev/null
          iptables -t nat -A POSTROUTING -s "$VPN_SERVER_SUBNET" -o "$IFACE" -p tcp -m multiport --dports 80,443 -j MASQUERADE
        fi
      done
    else # vpnclientX-route-up file does not exist
      true >"$VPNC_UP_FILE"
      {
        echo "#!/bin/sh"
        echo "$IPTABLES_DEL_ENTRY"
        echo "$IPTABLES_ADD_ENTRY"
      } >>"$VPNC_UP_FILE"
      # Implement routing rules
      iptables -t nat -D POSTROUTING -s "$VPN_SERVER_SUBNET" -o "$IFACE" -p tcp -m multiport --dports 80,443 -j MASQUERADE 2>/dev/null
      iptables -t nat -A POSTROUTING -s "$VPN_SERVER_SUBNET" -o "$IFACE" -p tcp -m multiport --dports 80,443 -j MASQUERADE
    fi
    # vpnclientX-route-pre-down File
    if [ -s "$VPNC_DOWN_FILE" ]; then
      #Check if an existing entry exists
      if [ "$(grep -cw "$IPTABLES_DEL_ENTRY" "$VPNC_DOWN_FILE")" -eq 0 ]; then # entry does not exist, add entry
        echo "$IPTABLES_DEL_ENTRY" >>"$VPNC_DOWN_FILE"
      fi
    else # # vpnclientX-route-pre-down file does not exist, add entry
      echo "#!/bin/sh" >"$VPNC_DOWN_FILE"
      echo "$IPTABLES_DEL_ENTRY" >>"$VPNC_DOWN_FILE"
    fi

    # nat-start File
    if [ -s "$NAT_START" ]; then
      if [ "$(grep -cw "$SCRIPT_ENTRY" "$NAT_START")" -eq 0 ]; then # if true, then no lines exist, add entry
        echo "$SCRIPT_ENTRY # x3mRouting" >>"$NAT_START"
        logger -st "($(basename "$0"))" $$ "$SCRIPT_ENTRY added to $NAT_START"
      fi
    else # nat-start file does not exist,create it
      true >"$NAT_START"
      {
        printf '%s\n' "#!/bin/sh"
        printf '%s\n' "$SCRIPT_ENTRY # x3mRouting" # file does not exist, create VPNC_UP_FILE
      } >"$NAT_START"
      logger -st "($(basename "$0"))" $$ "$SCRIPT_ENTRY added to $NAT_START"
    fi

    # Add nvram entry to vpn_client"${VPN_CLIENT_INSTANCE}"_clientlist
    if [ "$(echo "$VPN_IP_LIST" | grep -c "$POLICY_RULE_WITHOUT_NAME")" -eq 0 ]; then
      VPN_IP_LIST="${VPN_IP_LIST}${POLICY_RULE}"
      if [ "$(uname -m)" = "aarch64" ]; then
        low=0
        max=255
        for n in "" $VPN_IDS; do
          nvram set vpn_client"${VPN_CLIENT_INSTANCE}"_clientlist"${n}"="$(echo "$VPN_IP_LIST" | cut -b $low-$max)"
          low=$((max + 1))
          max=$((low + 254))
        done
      else
        nvram set vpn_client"${VPN_CLIENT_INSTANCE}"_clientlist="$VPN_IP_LIST"
      fi
      nvram commit
      logger -st "($(basename "$0"))" $$ "Restarting VPN Client ${VPN_CLIENT_INSTANCE} to add policy rule for VPN Server ${VPN_SERVER_INSTANCE}"
      service restart_vpnclient"${VPN_CLIENT_INSTANCE}"
    else # if the VPN Server entry exists in nvram using the 'vpnserverX' name created by the prior version, convert it to the new name
      if [ "$(echo "$VPN_IP_LIST" | grep -c "vpnserver${VPN_SERVER_INSTANCE}")" -ge 1 ]; then
        VPN_IP_LIST="$(echo "$VPN_IP_LIST" | sed "s/<vpnserver${VPN_SERVER_INSTANCE}>/<VPN Server ${VPN_SERVER_INSTANCE}>/")"
        if [ "$(uname -m)" = "aarch64" ]; then
          low=0
          max=255
          for n in "" $VPN_IDS; do
            nvram set vpn_client"${VPN_CLIENT_INSTANCE}"_clientlist"${n}"="$(echo "$VPN_IP_LIST" | cut -b $low-$max)"
            low=$((max + 1))
            max=$((low + 254))
          done
        else
          nvram set vpn_client"${VPN_CLIENT_INSTANCE}"_clientlist="$VPN_IP_LIST"
        fi
        nvram commit
        logger -st "($(basename "$0"))" $$ "Restarting vpnclient ${VPN_CLIENT_INSTANCE} for policy rule for VPN Server ${VPN_SERVER_INSTANCE} to take effect"
        service restart_vpnclient"${VPN_CLIENT_INSTANCE}"
      fi
    fi
  else # 'del' or 'del=force' parameter passed. Delete routing and routing rules in vpn server up down scripts.
    iptables -t nat -D POSTROUTING -s "$VPN_SERVER_SUBNET" -o "$IFACE" -p tcp -m multiport --dports 80,443 -j MASQUERADE 2>/dev/null

    # vpnserverX-up file
    if [ -s "$VPNC_UP_FILE" ]; then #file exists
      # POSTROUTING
      CMD="awk '\$5 == \"POSTROUTING\" && \$9 == \"vpn_server${VPN_SERVER_INSTANCE}_sn)\\\"/24\"  && \$11 == \"$IFACE\" && \$13 == \"MASQUERADE\" {next} {print \$0}' \"$VPNC_UP_FILE\" > \"$VPNC_UP_FILE.tmp\" && mv \"$VPNC_UP_FILE.tmp\" \"$VPNC_UP_FILE\""
      eval "$CMD"
      logger -st "($(basename "$0"))" $$ "iptables entry for VPN Client ${VPN_CLIENT_INSTANCE} deleted from $VPNC_UP_FILE"
      Check_For_Shebang "$VPNC_UP_FILE"
    fi

    # vpnserverX-down file
    if [ -s "$VPNC_DOWN_FILE" ]; then #file exists
      # POSTROUTING
      CMD="awk '\$5 == \"POSTROUTING\" && \$9 == \"vpn_server${VPN_SERVER_INSTANCE}_sn)\\\"/24\"  && \$11 == \"$IFACE\" && \$13 == \"MASQUERADE\" {next} {print \$0}' \"$VPNC_DOWN_FILE\" > \"$VPNC_DOWN_FILE.tmp\" && mv \"$VPNC_DOWN_FILE.tmp\" \"$VPNC_DOWN_FILE\""
      eval "$CMD"
      logger -st "($(basename "$0"))" $$ "iptables entry deleted VPN Client ${VPN_CLIENT_INSTANCE} from $VPNC_DOWN_FILE"
      Check_For_Shebang "$VPNC_DOWN_FILE"
    fi

    # nat-start File
    if [ -s "$NAT_START" ]; then
      sed "/$SERVER $CLIENT/d" "$NAT_START" >"$NAT_START.tmp" && mv "$NAT_START.tmp" "$NAT_START"
      logger -t "($(basename "$0"))" $$ "$SCRIPT_ENTRY entry deleted from $NAT_START"
      Check_For_Shebang "$NAT_START"
    fi

    # nvram get vpn_client"${VPN_CLIENT_INSTANCE}"_clientlist
    if [ "$(echo "$VPN_IP_LIST" | grep -c "$POLICY_RULE")" -eq "1" ]; then
      VPN_IP_LIST="$(echo "$VPN_IP_LIST" | sed "s,<VPN Server ${VPN_SERVER_INSTANCE}>${VPN_SERVER_SUBNET}>>VPN,,")"
      if [ "$(uname -m)" = "aarch64" ]; then
        low=0
        max=255
        for n in "" $VPN_IDS; do
          nvram set vpn_client"${VPN_CLIENT_INSTANCE}"_clientlist"${n}"="$(echo "$VPN_IP_LIST" | cut -b $low-$max)"
          low=$((max + 1))
          max=$((low + 254))
        done
      else
        nvram set vpn_client"${VPN_CLIENT_INSTANCE}"_clientlist="$VPN_IP_LIST"
      fi
      nvram commit
      logger -st "($(basename "$0"))" $$ "Restarting vpnclient ${VPN_CLIENT_INSTANCE} to remove policy rule for VPN Server ${VPN_SERVER_INSTANCE}"
      service restart_vpnclient"${VPN_CLIENT_INSTANCE}"
    fi
  fi

  # set permissions for each file
  [ -s "$VPNC_UP_FILE" ] && chmod 755 "$VPNC_UP_FILE"
  [ -s "$VPNC_DOWN_FILE" ] && chmod 755 "$VPNC_DOWN_FILE"
  [ -s "$NAT_START" ] && chmod 755 "$NAT_START"

}

VPN_Server_to_IPSET() {

  VPN_SERVER_INSTANCE=$1
  VPN_CLIENT_INSTANCE=$2
  IFACE=$3
  IPSET_NAME=$4
  TAG_MARK=$5
  DEL_FLAG=$6

  case "$VPN_SERVER_INSTANCE" in
  1) VPN_SERVER_TUN="tun21"
     VPN_SERVER_SUBNET="$(nvram get vpn_server1_sn)/24" # Get VPN Server IP
  ;;
  2) VPN_SERVER_TUN="tun22"
     VPN_SERVER_SUBNET="$(nvram get vpn_server2_sn)/24"
  ;;
  3) VPN_SERVER_TUN="wgs1"
     VPN_SERVER_SUBNET="$(nvram get wgs_addr)" # Already includes the subnet mask
  ;;
  *) Error_Exit "VPN Server instance $VPN_SERVER_INSTANCE should be a 1, 2 for OpenVPN or 3 for WireGuard" ;;
  esac

  # POSTROUTING CHAIN
  IPTABLES_POSTROUTING_DEL_ENTRY="iptables -t nat -D POSTROUTING -s $VPN_SERVER_SUBNET -o $IFACE $PROTOCOL_PORT_RULE -j MASQUERADE 2>/dev/null"
  IPTABLES_POSTROUTING_ADD_ENTRY="iptables -t nat -A POSTROUTING -s $VPN_SERVER_SUBNET -o $IFACE $PROTOCOL_PORT_RULE -j MASQUERADE"

  # PREROUTING CHAIN
  IPTABLES_PREROUTING_DEL_ENTRY="iptables -t mangle -D PREROUTING -i $VPN_SERVER_TUN -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK 2>/dev/null"
  IPTABLES_PREROUTING_ADD_ENTRY="iptables -t mangle -A PREROUTING -i $VPN_SERVER_TUN -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK"

  # VPN Client Up/Down files
  VPNC_UP_FILE="$SCR_DIR/vpnclient${VPN_CLIENT_INSTANCE}-route-up"
  VPNC_DOWN_FILE="$SCR_DIR/vpnclient${VPN_CLIENT_INSTANCE}-route-pre-down"

  if [ -z "$DEL_FLAG" ]; then       # add entry
    if [ -s "$VPNC_UP_FILE" ]; then # file exists
      #Check if an existing entry exists
      for IPTABLES_ENTRY in "$IPTABLES_POSTROUTING_DEL_ENTRY" "$IPTABLES_POSTROUTING_ADD_ENTRY" "$IPTABLES_PREROUTING_DEL_ENTRY" "$IPTABLES_PREROUTING_ADD_ENTRY"; do
        if [ "$(grep -cw "$IPTABLES_ENTRY" "$VPNC_UP_FILE")" -eq 0 ]; then # if true, add entry
          echo "$IPTABLES_ENTRY" >>"$VPNC_UP_FILE" && log_info "iptables entry added to $VPNC_UP_FILE"
        fi
      done
      eval "iptables -t nat -D POSTROUTING -s $VPN_SERVER_SUBNET -o $IFACE $PROTOCOL_PORT_RULE -j MASQUERADE 2>/dev/null"
      eval "iptables -t nat -A POSTROUTING -s $VPN_SERVER_SUBNET -o $IFACE $PROTOCOL_PORT_RULE -j MASQUERADE"
      eval "iptables -t mangle -D PREROUTING -i $VPN_SERVER_TUN -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK 2>/dev/null"
      eval "iptables -t mangle -A PREROUTING -i $VPN_SERVER_TUN -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK"
    else # file does not exist
      true >"$VPNC_UP_FILE"
      {
        echo "#!/bin/sh"
        echo "$IPTABLES_POSTROUTING_DEL_ENTRY"
        echo "$IPTABLES_POSTROUTING_ADD_ENTRY"
        echo "$IPTABLES_PREROUTING_DEL_ENTRY"
        echo "$IPTABLES_PREROUTING_ADD_ENTRY"
      } >>"$VPNC_UP_FILE"
      eval "iptables -t nat -D POSTROUTING -s $VPN_SERVER_SUBNET -o $IFACE $PROTOCOL_PORT_RULE -j MASQUERADE 2>/dev/null"
      eval "iptables -t nat -A POSTROUTING -s $VPN_SERVER_SUBNET -o $IFACE $PROTOCOL_PORT_RULE -j MASQUERADE"
      eval "iptables -t mangle -D PREROUTING -i $VPN_SERVER_TUN -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK 2>/dev/null"
      eval "iptables -t mangle -A PREROUTING -i $VPN_SERVER_TUN -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK"
    fi

    if [ -s "$VPNC_DOWN_FILE" ]; then
      # Check if an existing entry exists
      for IPTABLES_ENTRY in "$IPTABLES_POSTROUTING_DEL_ENTRY" "$IPTABLES_PREROUTING_DEL_ENTRY"; do
        if [ "$(grep -cw "$IPTABLES_ENTRY" "$VPNC_DOWN_FILE")" -eq 0 ]; then # if true, then add entry
          echo "$IPTABLES_ENTRY" >>"$VPNC_DOWN_FILE" && log_info "iptables entry added to $VPNC_DOWN_FILE"
        fi
      done
    else # file does not exist
      true >"$VPNC_DOWN_FILE"
      {
        echo "#!/bin/sh"
        echo "$IPTABLES_POSTROUTING_DEL_ENTRY"
        echo "$IPTABLES_PREROUTING_DEL_ENTRY"
      } >>"$VPNC_DOWN_FILE"
      log_info "iptables entry added to $VPNC_DOWN_FILE"
    fi
  else # 'del' or 'del=force' option specified.
    eval "iptables -t mangle -D PREROUTING -i $VPN_SERVER_TUN -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK 2>/dev/null"
    eval "iptables -t nat -D POSTROUTING -s $VPN_SERVER_SUBNET -o $IFACE $PROTOCOL_PORT_RULE -j MASQUERADE 2>/dev/null"

    if [ -s "$VPNC_UP_FILE" ]; then
      eval "awk '\$5 == \"POSTROUTING\" && \$7 == \"$VPN_SERVER_SUBNET\" && \$9 == \"$IFACE\" && /MASQUERADE/ {next} {print}' \"$VPNC_UP_FILE\" > \"$VPNC_UP_FILE.tmp\" && mv \"$VPNC_UP_FILE.tmp\" \"$VPNC_UP_FILE\""
      eval "awk '\$5 == \"PREROUTING\" && \$7 == \"$VPN_SERVER_TUN\" && \$11 == \"$IPSET_NAME\" {next} {print}' \"$VPNC_UP_FILE\" > \"$VPNC_UP_FILE.tmp\" && mv \"$VPNC_UP_FILE.tmp\" \"$VPNC_UP_FILE\""
      log_info "iptables entry deleted from $VPNC_UP_FILE"
      Check_For_Shebang "$VPNC_UP_FILE"
    fi

    # VPN Client route-pre-down File
    if [ -s "$VPNC_DOWN_FILE" ]; then
      eval "awk '\$5 == \"POSTROUTING\" && \$7 == \"$VPN_SERVER_SUBNET\" && \$9 == \"$IFACE\" && /MASQUERADE/ {next} {print}' \"$VPNC_DOWN_FILE\" > \"$VPNC_DOWN_FILE.tmp\" && mv \"$VPNC_DOWN_FILE.tmp\" \"$VPNC_DOWN_FILE\""
      eval "awk '\$5 == \"PREROUTING\" && \$7 == \"$VPN_SERVER_TUN\" && \$11 == \"$IPSET_NAME\" {next} {print}' \"$VPNC_DOWN_FILE\" > \"$VPNC_DOWN_FILE.tmp\" && mv \"$VPNC_DOWN_FILE.tmp\" \"$VPNC_DOWN_FILE\""
      log_info "iptables entry deleted from $VPNC_DOWN_FILE"
      Check_For_Shebang "$VPNC_DOWN_FILE"
    fi
  fi

  # set permissions for each file
  [ -s "$VPNC_UP_FILE" ] && chmod 755 "$VPNC_UP_FILE"
  [ -s "$VPNC_DOWN_FILE" ] && chmod 755 "$VPNC_DOWN_FILE"

}

Harvest_Domains() {

  SCAN_SPACE_LIST=$(echo "$@" | sed -n "s/^.*autoscan=//p" | awk '{print $1}' | tr ',' ' ')

  true >/opt/tmp/DOMAIN_LIST

  for TOP_LEVEL_DOMAIN in $SCAN_SPACE_LIST; do
    SCAN_LIST=$(grep "$TOP_LEVEL_DOMAIN" "/opt/var/log/dnsmasq.log" | grep query | awk '{print $(NF-2)}' | awk -F\. '{print $(NF-1) FS $NF}' | sort | uniq)
    [ -n "$SCAN_LIST" ] && echo "$SCAN_LIST" >>/opt/tmp/DOMAIN_LIST && log_info "Added $SCAN_LIST during autoscan"
  done

  DOMAIN_LIST=$(awk '{ print $1 }' "/opt/tmp/DOMAIN_LIST" | sort -u | tr '\n' '/' | sed -n 's/\/$/\n/p')
  NAT_ENTRY=$(echo "$DOMAIN_LIST" | sed 's|/|,|g')

  rm /opt/tmp/DOMAIN_LIST

  if [ -z "$DOMAIN_LIST" ]; then
    Error_Exit "No domain names were harvested from $DNSMASQ_LOG_FILE"
  else
    DNSMASQ_ENTRY="/$DOMAIN_LIST/$IPSET_NAME"
    Process_DNSMASQ "$IPSET_NAME" "$DNSMASQ_ENTRY" "$DIR"
  fi
}

Dnsmasq_Log_File() {

  if [ -s "/opt/var/log/dnsmasq.log" ]; then
    DNSMASQ_LOG_FILE="/opt/var/log/dnsmasq.log"
  elif [ -s "/tmp/var/log/dnsmasq.log" ]; then
    DNSMASQ_LOG_FILE="/tmp/var/log/dnsmasq.log"
  elif [ -n "$(find / -name "dnsmasq.log")" ]; then
    DNSMASQ_LOG_FILE=$(find / -name "dnsmasq.log")
  else
    Error_Exit "dnsmasq.log file NOT found!"
  fi
}

Check_Second_Parm() {
  if [ "$(echo "$2" | grep -c 'client=')" -eq 0 ] || [ "$(echo "$2" | grep -c 'ipset_name=')" -eq 0 ]; then
    Error_Exit "Expecting first parameter to be 'server=' or 'ipset_name='"
  fi
}

Define_IFACE() {
  ### Define interface/bitmask to route traffic to. Use existing PREROUTING rule for IPSET to determine FWMARK.
  TAG_MARK=$(iptables -nvL PREROUTING -t mangle --line | grep -w "$IPSET_NAME" | awk '{print $(NF)}' | head -n 1)
  [ -z "$TAG_MARK" ] && Error_Exit "Mandatory PREROUTING rule for IPSET name $IPSET_NAME does not exist."
  FWMARK_SUBSTR=$(echo "$TAG_MARK" | cut -c 3-6)

  case "$FWMARK_SUBSTR" in
    8000) IFACE="br0" ;;
    1000) IFACE="tun11" ;;
    2000) IFACE="tun12" ;;
    4000) IFACE="tun13" ;;
    7000) IFACE="tun14" ;;
    3000) IFACE="tun15" ;;
    a000) IFACE="wgc1" ;;
    b000) IFACE="wgc2" ;;
    c000) IFACE="wgc3" ;;
    d000) IFACE="wgc4" ;;
    e000) IFACE="wgc5" ;;
    *) Error_Exit "$1 should be 1/2/3/4/5 for OPENVPN Client or 11/12/13/14/15 for WireGuard Client" ;;
  esac
}
 
parse_protocol_and_ports() {
  args="$*"

  if echo "$args" | grep -Fq "protocol="; then
    protocols=$(awk '{print tolower($1)}' /etc/protocols | grep -v '^#' | tr '\n' ' ')
    protocol=$(echo "$args" | sed -n 's/.*protocol=\([^ ]*\).*/\1/p' | awk '{print tolower($0)}')
    if ! echo "$protocols" | grep -qw "$protocol"; then
      Error_Exit "Unsupported protocol: '$protocol'."
    fi

    if echo "$args" | grep -Fq "port="; then
      PORT=$(echo "$args" | sed -n 's/.*port=\([^ ]*\).*/\1/p')
      if echo "$PORT" | grep -Eq '^[0-9]+$'; then
        if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
          Error_Exit "Port number in 'port=' must be between 1 and 65535."
        fi
      else
        Error_Exit "The 'port=' parameter should contain only digits."
      fi
    fi

    if echo "$args" | grep -Fq "ports="; then
      PORTS=$(echo "$args" | sed -n 's/.*ports=\([^ ]*\).*/\1/p')
      if echo "$PORTS" | grep -Eq '^[0-9]+(,[0-9]+)*$'; then
        port_list=$(echo "$PORTS" | tr ',' ' ')
        for port in $port_list; do
          if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
            Error_Exit "Port numbers in 'ports=' must be between 1 and 65535."
          fi
        done
      else
        Error_Exit "The 'ports=' parameter should contain only digits and commas."
      fi
    fi

    if { [ -n "$PORT" ] || [ -n "$PORTS" ]; } && ! echo "tcp udp udplite sctp dccp" | grep -qw "$protocol"; then
      Error_Exit "Unsupported protocol '$protocol' for port parameter. Accept only TCP, UDP, UDPLITE, SCTP, DCCP."
    elif [ -n "$PORTS" ]; then
      PROTOCOL_PORT_RULE="-p $protocol -m multiport --dports $PORTS"
    elif [ -n "$PORT" ]; then
      PROTOCOL_PORT_RULE="-p $protocol --dport $PORT"
    else
      PROTOCOL_PORT_RULE="-p $protocol"
    fi
  fi
}

#==================== End of Functions  =====================================
## Begin ##
log_info "Starting Script Execution" "$@"
Check_Lock "$@"

# Set DEL_FLAG if user specified 'del=force' parameter
if [ "$(echo $@ | grep -cw 'del=force')" -ge 1 ]; then
  DEL_FLAG="FORCE"
elif [ "$(echo $@ | grep -cw 'del')" -ge 1 ]; then
  DEL_FLAG="del"
else
  DEL_FLAG=
fi

# Check if user specified 'dir=' parameter
if [ "$(echo "$@" | grep -c 'dir=')" -gt 0 ]; then
  if [ "$(echo "$@" | grep -c 'asnum=')" -gt 0 ]; then
    log_info "ASN Method stores IPv4 addresses in memory. Ignoring 'dir=' parm" location.
    # set DIR to default location and ignore when writing to nat-start in Check_Nat_Start_For_Entries function
    DIR="/opt/tmp"
  else
    DIR=$(echo "$@" | sed -n "s/^.*dir=//p" | awk '{print $1}') # v1.2 Mount point/directory for backups
  fi
else
  DIR="/opt/tmp"
fi

#######################################################################
# Check if 'server=' parameter specified
#######################################################################

if [ "$(echo "$@" | grep -c 'server=')" -gt 0 ]; then
  SERVER=$(echo "$@" | sed -n "s/^.*server=//p" | awk '{print $1}')
  case "$SERVER" in
  1 | 2 | 3 | all) ;;
  *) Error_Exit "Invalid Server '$SERVER' specified." ;;
  esac

  if [ "$(echo "$@" | grep -c 'client=')" -eq 0 ] && [ "$(echo "$@" | grep -c 'ipset_name=')" -eq 0 ]; then
    Error_Exit "Expecting second parameter to be either 'client=' or 'ipset_name='"
  fi

  ### Process server when 'client=' specified
  if [ "$(echo "$@" | grep -c 'client=')" -gt 0 ]; then
    VPN_CLIENT_INSTANCE=$(echo "$@" | sed -n "s/^.*client=//p" | awk '{print $1}')
    case "$VPN_CLIENT_INSTANCE" in
    1) IFACE="tun11" ;;
    2) IFACE="tun12" ;;
    3) IFACE="tun13" ;;
    4) IFACE="tun14" ;;
    5) IFACE="tun15" ;;
    11) IFACE="wgc1" ;;
    12) IFACE="wgc2" ;;
    13) IFACE="wgc3" ;;
    14) IFACE="wgc4" ;;
    15) IFACE="wgc5" ;;
    *) Error_Exit "ERROR 'client=$VPN_CLIENT_INSTANCE' reference should be 1/2/3/4/5 for OPENVPN Client or 11/12/13/14/15 for WireGuard Client" ;;
    esac

    # Delete VPN Server to VPN Client rules?
    if [ "$(echo $@ | grep -cw 'del')" -ge 1 ] || [ "$(echo $@ | grep -cw 'del=force')" -ge 1 ]; then
      if [ "$SERVER" = "all" ]; then
        for SERVER in 1 2 3; do
          VPN_Server_to_VPN_Client "$SERVER" "$IFACE" "$VPN_CLIENT_INSTANCE" "$DEL_FLAG"
        done
      else
        VPN_Server_to_VPN_Client "$SERVER" "$IFACE" "$VPN_CLIENT_INSTANCE" "$DEL_FLAG"
      fi
    else
      if [ "$SERVER" = "all" ]; then
        for SERVER in 1 2 3; do
          VPN_Server_to_VPN_Client "$SERVER" "$IFACE" "$VPN_CLIENT_INSTANCE"
        done
      else
        VPN_Server_to_VPN_Client "$SERVER" "$IFACE" "$VPN_CLIENT_INSTANCE"
      fi
    fi
    Exit_Routine
  fi

  #### Process server when 'ipset_name=' specified
  if [ "$(echo "$@" | grep -c 'ipset_name=')" -ge 1 ]; then
    IPSET_NAME=$(echo "$@" | sed -n "s/^.*ipset_name=//p" | awk '{print $1}' | tr ',' ' ')
    for IPSET_NAME in $IPSET_NAME; do
      # Check if IPSET list exists
      if [ -n "$IPSET_NAME" ]; then
        if [ "$(ipset list -n "$IPSET_NAME" 2>/dev/null)" != "$IPSET_NAME" ]; then
          Error_Exit "IPSET name $IPSET_NAME does not exist."
        fi
      fi
    done

    parse_protocol_and_ports "$@"

    IPSET_NAME=$(echo "$@" | sed -n "s/^.*ipset_name=//p" | awk '{print $1}' | tr ',' ' ')
    for IPSET_NAME in $IPSET_NAME; do
      Define_IFACE "$IPSET_NAME"

      case "$IFACE" in
      tun11) VPN_CLIENT_INSTANCE=1 ;;
      tun12) VPN_CLIENT_INSTANCE=2 ;;
      tun13) VPN_CLIENT_INSTANCE=3 ;;
      tun14) VPN_CLIENT_INSTANCE=4 ;;
      tun15) VPN_CLIENT_INSTANCE=5 ;;
      wgc1) VPN_CLIENT_INSTANCE=11 ;;
      wgc2) VPN_CLIENT_INSTANCE=12 ;;
      wgc3) VPN_CLIENT_INSTANCE=13 ;;
      wgc4) VPN_CLIENT_INSTANCE=14 ;;
      wgc5) VPN_CLIENT_INSTANCE=15 ;;
      esac

      if [ "$(echo $@ | grep -cw 'del')" -ge 1 ] || [ "$(echo $@ | grep -cw 'del=force')" -ge 1 ]; then
        if [ "$SERVER" = "all" ]; then
          for SERVER in 1 2 3; do
            VPN_Server_to_IPSET "$SERVER" "$VPN_CLIENT_INSTANCE" "$IFACE" "$IPSET_NAME" "$TAG_MARK" "$DEL_FLAG"
          done
        else
          VPN_Server_to_IPSET "$SERVER" "$VPN_CLIENT_INSTANCE" "$IFACE" "$IPSET_NAME" "$TAG_MARK" "$DEL_FLAG"
        fi
      else
        if [ "$SERVER" = "all" ]; then
          for SERVER in 1 2 3; do
            VPN_Server_to_IPSET "$SERVER" "$VPN_CLIENT_INSTANCE" "$IFACE" "$IPSET_NAME" "$TAG_MARK"
          done
        else
          VPN_Server_to_IPSET "$SERVER" "$VPN_CLIENT_INSTANCE" "$IFACE" "$IPSET_NAME" "$TAG_MARK"
        fi
      fi
    done
    # nat-start File
    SCRIPT_ENTRY="sh $SCR_DIR/x3mRouting.sh $1 $2"
    if [ "$(echo $@ | grep -cw 'del')" -eq 0 ] || [ "$(echo $@ | grep -cw 'del=force')" -eq 0 ]; then
      add_entry_to_file "$NAT_START" "$SCRIPT_ENTRY"
    else
      delete_entry_from_file "$NAT_START" "$1 $2"
    fi
    Exit_Routine
  fi
fi
######################################################################
# End of special processing for VPN Server
######################################################################

#######################################################################
# Check if 'ipset_name=' parameter specified
# This section creates IPSET list with no routing rules
#######################################################################
if [ "$(echo "$@" | grep -c 'ipset_name=')" -gt 0 ]; then
  IPSET_NAME=$(echo "$@" | sed -n "s/^.*ipset_name=//p" | awk '{print $1}') # ipset name

  if [ "$(echo $@ | grep -cw 'del')" -ge 1 ] || [ "$(echo $@ | grep -cw 'del=force')" -ge 1 ]; then
    Delete_Ipset_List "$IPSET_NAME" "$DIR"
    Exit_Routine
  fi

  # Error_Exit if 'src=' parm specified
  if [ "$(echo "$@" | grep -c 'src=')" -gt 0 ]; then
    Error_Exit "The 'src=' parameter can't be used with the 'ipset_name=' parameter"
  fi

  # Error_Exit if 'src_range=' parm specified
  if [ "$(echo "$@" | grep -c 'src_range=')" -gt 0 ]; then
    Error_Exit "The 'src_range=' parameter can't be used with the 'ipset_name=' parameter"
  fi

  # Check for 'dnsmasq=' parm
  if [ "$(echo "$@" | grep -c 'dnsmasq=')" -gt 0 ]; then
    DNSMASQ_Parm $@
    Check_Nat_Start_For_Entries "$IPSET_NAME" "dnsmasq=$DOMAINS" "$DIR"
    Exit_Routine
  fi

  # Check for 'dnsmasq_file=' parm
  if [ "$(echo "$@" | grep -c 'dnsmasq_file=')" -gt 0 ]; then
    DNSMASQ_Parm $@
    Check_Nat_Start_For_Entries "$IPSET_NAME" "dnsmasq_file=$DNSMASQ_FILE" "$DIR"
    Exit_Routine
  fi

  # Check for 'autoscan=' parm
  if [ "$(echo "$@" | grep -c 'autoscan=')" -gt 0 ]; then
    Dnsmasq_Log_File
    Harvest_Domains $@
    Check_Nat_Start_For_Entries "$IPSET_NAME" "dnsmasq=$NAT_ENTRY" "$DIR"
    Exit_Routine
  fi

  # check if 'asnum=' parm
  if [ "$(echo "$@" | grep -c 'asnum=')" -gt 0 ]; then
    ASNUM_Parm $@
    ASN=$(echo "$@" | sed -n "s/^.*asnum=//p" | awk '{print $1}')
    Check_Nat_Start_For_Entries "$IPSET_NAME" "asnum=$ASN" "$DIR"
    Exit_Routine
  fi

  # check if 'aws_region=' parm
  if [ "$(echo "$@" | grep -c 'aws_region=')" -gt 0 ]; then
    AWS_Region_Parm $@
    AWS_REGION=$(echo "$@" | sed -n "s/^.*aws_region=//p" | awk '{print $1}')
    Check_Nat_Start_For_Entries "$IPSET_NAME" "aws_region=$AWS_REGION" "$DIR"
    Exit_Routine
  fi

  # Manual Method to create ipset list if IP address specified
  if [ -z "$2" ] || [ "$(echo "$@" | grep -c 'ip=')" -gt 0 ]; then
    Manual_Method $@
    Check_Nat_Start_For_Entries "$IPSET_NAME" "Manual" "$DIR"
    Exit_Routine
  fi

  # Manual Method to create ipset list if IP address specified
  if [ -s "$DIR/$IPSET_NAME" ]; then
    Manual_Method $@
    Check_Nat_Start_For_Entries "$IPSET_NAME" "Manual" "$DIR"
    Exit_Routine
  else
    Error_Exit "The save/restore file $DIR/$IPSET_NAME does not exist."
  fi
fi
##############################################################################################
# End of Special Processing for 'ipset_name=' parm
##############################################################################################

##############################################################################################
# Start of Processing for Routing Rules
##############################################################################################

# Validate SRC_IFACE
SRC_IFACE="$1"
case "$SRC_IFACE" in
ALL | [1-5] | 1[1-5]) ;;
*) Check_Second_Parm $@ ;;
esac

# Check for DST_IFACE
if [ -n "$2" ]; then
  DST_IFACE=$2
  if [ "$SRC_IFACE" = "ALL" ]; then
    case "$DST_IFACE" in
    [1-5] | 1[1-5]) ;;
    *) Error_Exit "Invalid Source '$SRC_IFACE' and Destination ($DST_IFACE) combination." ;;
    esac
  fi
  if echo "$VPN_IDS" | grep -qw "$SRC_IFACE"; then
    case "$DST_IFACE" in
    0) ;;
    *) Error_Exit "Invalid Source '$SRC_IFACE' and Destination ($DST_IFACE) combination." ;;
    esac
  fi
  Set_Fwmark_Params
else
  Error_Exit "missing arg2 'dst_iface'"
fi

# Check for IPSET list name parm
if [ -n "$3" ]; then
  IPSET_NAME=$3
else
  Error_Exit "missing arg3 'ipset_name'"
fi

# Validate DST_IFACE and set destination TAG_MARK
case "$DST_IFACE" in
0)
  TAG_MARK="$FWMARK_WAN"
  TARGET_DESC="WAN"
  ROUTE_TABLE=254
  ;;
1)
  TAG_MARK="$FWMARK_OVPNC1"
  TARGET_DESC="OVPN Client 1"
  ROUTE_TABLE=ovpnc1
  ;;
2)
  TAG_MARK="$FWMARK_OVPNC2"
  TARGET_DESC="OVPN Client 2"
  ROUTE_TABLE=ovpnc2
  ;;
3)
  TAG_MARK="$FWMARK_OVPNC3"
  TARGET_DESC="OVPN Client 3"
  ROUTE_TABLE=ovpnc3
  ;;
4)
  TAG_MARK="$FWMARK_OVPNC4"
  TARGET_DESC="OVPN Client 4"
  ROUTE_TABLE=ovpnc4
  ;;
5)
  TAG_MARK="$FWMARK_OVPNC5"
  TARGET_DESC="OVPN Client 5"
  ROUTE_TABLE=ovpnc5
  ;;
11)
  TAG_MARK="$FWMARK_WGC1"
  TARGET_DESC="WG Client 1"
  ROUTE_TABLE=wgc1
  ;;
12)
  TAG_MARK="$FWMARK_WGC2"
  TARGET_DESC="WG Client 2"
  ROUTE_TABLE=wgc2
  ;;
13)
  TAG_MARK="$FWMARK_WGC3"
  TARGET_DESC="WG Client 3"
  ROUTE_TABLE=wgc3
  ;;
14)
  TAG_MARK="$FWMARK_WGC4"
  TARGET_DESC="WG Client 4"
  ROUTE_TABLE=wgc4
  ;;
15)
  TAG_MARK="$FWMARK_WGC5"
  TARGET_DESC="WG Client 5"
  ROUTE_TABLE=wgc5
  ;;
*)
  Error_Exit "$DST_IFACE should be 0-WAN or 1/2/3/4/5 for OPENVPN Client or 11/12/13/14/15 for WireGuard Client"
  ;;
esac

Set_IP_Rule "$DST_IFACE"

parse_protocol_and_ports "$@"

# Check if delete option specified
if [ "$(echo $@ | grep -cw 'del')" -ge 1 ] || [ "$(echo $@ | grep -cw 'del=force')" -ge 1 ]; then
  Delete_Ipset_List "$IPSET_NAME" "$DIR"
  Exit_Routine
fi

# 'src=' or 'src_range=' params require exception processing
if [ "$(echo "$@" | grep -c 'src=')" -gt 0 ] || [ "$(echo "$@" | grep -c 'src_range=')" -gt 0 ]; then
  Process_Src_Option $@
  Exit_Routine
fi

# Check for 'dnsmasq' parm which indicates DNSMASQ method & make sure 'autoscan' parm is not passed!
if [ "$(echo "$@" | grep -c 'dnsmasq=')" -gt 0 ]; then
  DNSMASQ_Parm $@
  Create_Routing_Rules "$IPSET_NAME"
  set_wg_rp_filter
  Check_Files_For_Entries "$SRC_IFACE" "$DST_IFACE" "$IPSET_NAME" "dnsmasq=$DOMAINS" "$DIR"
  Exit_Routine
fi

# Check for 'dnsmasq_file' parm
if [ "$(echo "$@" | grep -c 'dnsmasq_file=')" -gt 0 ]; then
  DNSMASQ_Parm $@
  Create_Routing_Rules "$IPSET_NAME"
  set_wg_rp_filter
  Check_Files_For_Entries "$SRC_IFACE" "$DST_IFACE" "$IPSET_NAME" "dnsmasq_file=$DNSMASQ_FILE" "$DIR"
  Exit_Routine
fi

# autoscan method
if [ "$(echo "$@" | grep -c 'autoscan')" -gt 0 ]; then
  Dnsmasq_Log_File $@
  Harvest_Domains $@
  Create_Routing_Rules "$IPSET_NAME"
  set_wg_rp_filter
  Check_Files_For_Entries "$SRC_IFACE" "$DST_IFACE" "$IPSET_NAME" "dnsmasq=$NAT_ENTRY" "$DIR"
  Exit_Routine
fi

# ASN Method
if [ "$(echo "$@" | grep -c 'asnum=')" -gt 0 ]; then
  ASNUM_Parm $@
  Create_Routing_Rules "$IPSET_NAME"
  set_wg_rp_filter
  ASN=$(echo "$@" | sed -n "s/^.*asnum=//p" | awk '{print $1}')
  Check_Files_For_Entries "$SRC_IFACE" "$DST_IFACE" "$IPSET_NAME" "asnum=$ASN" "$DIR"
  Exit_Routine
fi

# Amazon Method
if [ "$(echo "$@" | grep -c 'aws_region=')" -gt 0 ]; then
  AWS_Region_Parm $@
  Create_Routing_Rules "$IPSET_NAME"
  set_wg_rp_filter
  AWS_REGION=$(echo "$@" | sed -n "s/^.*aws_region=//p" | awk '{print $1}')
  Check_Files_For_Entries "$SRC_IFACE" "$DST_IFACE" "$IPSET_NAME" "aws_region=$AWS_REGION" "$DIR"
  Exit_Routine
fi

# Manual Method to create ipset list if IP address specified
if [ -z "$4" ] || [ "$(echo "$@" | grep -c 'dir=')" -gt 0 ] || [ "$(echo "$@" | grep -c 'ip=')" -gt 0 ]; then
  Manual_Method $@
  Create_Routing_Rules "$IPSET_NAME"
  set_wg_rp_filter
  Check_Files_For_Entries "$SRC_IFACE" "$DST_IFACE" "$IPSET_NAME" "Manual" "$DIR"
  Exit_Routine
fi

# If I reached this point, I have encountered a value I don't expect
Error_Exit "Encountered an invalid parameter: " $@
##############################################################################################
# End of Processing for Routing Rules
##############################################################################################
