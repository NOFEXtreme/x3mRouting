#!/bin/sh
####################################################################################################
# Script: x3mRouting.sh
# VERSION=2.3.12
# Author: Xentrk
# Date: 18-May-2021
#
# Modified by NOFEXtream: https://github.com/NOFEXtreme/x3mRouting/blob/master/x3mRouting.sh
# Integrated WireGuard client/server and protocol/ports support.
# Currently not working with WireGuard:
#  - VPN Server to VPN Client Routing
# Last updated: 04-Oct-2024
#
# Grateful:
#   Thank you to @Martineau on snbforums.com for sharing his Selective Routing expertise,
#   on-going support and collaboration on this project!
#
#   chk_entware function and code to process the passing of params written by Martineau
#
#   Thanks to Addamm00, author of Skynet, for the Check_Lock and kill_lock functions to prevent concurrent processing.
#   Source code can be found at https://github.com/Adamm00/IPSet_ASUS
#
####################################################################################################
# shellcheck disable=SC2086 # Double quote to prevent globbing and word splitting on $PROTOCOL_PORT_RULE
#___________________________________________________________________________________________________
#
# Required parameters are listed inside the braces: { }
# Optional parameters are listed inside of the brackets [ ]
# Valid parameter values are listed in parenthesis ( )
#
# Create IPSET List with Routing Rules:
#
# x3mRouting {SRC_IFACE} (0|1|2|3|4|5|11|12|13|14|15)
#            {DST_IFACE} (0|1|2|3|4|5|11|12|13|14|15)
#            ** src/dst NOTES Start **
#              0 for WAN or 1-5 for WireGuard Client or 11-15 for OpenVPN Client
#              Valid SRC and DST Combinations
#              1) VPN Client Routing
#                 - Use this SRC and DST combination to route all IPSET list traffic to a VPN Client:
#                   0 1, 0 2, 0 3, 0 4, 0 5, 0 11, 0 12, 0 13, 0 14, 0 15
#              2) VPN Bypass Routing
#                 - Use this SRC and DST combination to bypass the VPN Client for an IPSET list and
#                   route to the WAN interface:
#                   1 0, 2 0, 3 0, 4 0, 5 0, 11 0, 12 0, 13 0, 14 0, 15 0
#            ** src/dst NOTES End **
#            {IPSET_NAME}
#            ['autoscan='keyword1[,keyword2]...] # Scans for keywords and creates IPSET list using the dnsmasq method
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
#            ['protocol='protocol] # Set protocol to 'udp', 'tcp' or other supported by the system
#            ['ports='port[,port]...] # Set the ports destination
#---------------------------------------------------------------------------------------------------
# Create IPSET List with no Routing Rules:
#
# x3mRouting {ipset_name=}
#            ['autoscan='keyword1[,keyword2]...] # Scans for keywords and creates IPSET list using the dnsmasq method
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
#---------------------------------------------------------------------------------------------------
# VPN Server to VPN Client Routing:
#
# x3mRouting {'server='1|2|all} {'client='1|2|3|4|5} ['del'] ['del=force']
#---------------------------------------------------------------------------------------------------
# VPN Server to existing LAN routing rules for one or more IPSET lists
#
# x3mRouting {'server='1|2|3|all} {'ipset_name='IPSET[,IPSET]...} ['protocol='] ['ports='] ['del'] ['del=force']
#___________________________________________________________________________________________________

SCR_NAME=$(basename "$0" | sed 's/.sh//')     # Script name without .sh
SCR_DIR="$(cd "$(dirname "$0")" && pwd)"      # Script directory (absolute path)
LOCK_FILE="/tmp/$SCR_NAME.lock"               # Lock file to prevent multiple instances
NAT_START="/jffs/scripts/nat-start"           # NAT initialization (e.g., firewall restart)
WG_START="/jffs/scripts/wgclient-start"       # WireGuard client startup
WAN_EVENT="/jffs/scripts/wan-event"           # WAN events (e.g., IP changes)
DNSMASQ_CONF="/jffs/configs/dnsmasq.conf.add" # dnsmasq configuration file

VPN_IDS="1 2 3 4 5 11 12 13 14 15"
IP_RE='([1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\.(0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])){3}'
IP_RE_PREFIX='([1-9]?[12][0-9]|3[0-2])'
CIDR_REGEX="$IP_RE/$IP_RE_PREFIX"

show_help() {
  # Print from line starting with '#__' to the first blank line (source: Martineau)
  awk '/^#__/{f=1} f{print; if (!NF) exit}' "$0" | more
}

log_info() {
  logger -st "${SCR_NAME}[$$]" "$*"
}

log_warning() {
  log_info "WARNING! $*"
}

exit_error() {
  [ "$LOCK_ACTIVE" = "true" ] && release_lock
  log_info "ERROR! $*"
  exit 1
}

exit_routine() {
  [ "$LOCK_ACTIVE" = "true" ] && release_lock
  log_info "Completed Script Execution"
  exit 0
}

release_lock() {
  [ -f "$LOCK_FILE" ] && rm -f "$LOCK_FILE"
}

check_lock() {
  tries=0
  max_tries=60

  while [ "$tries" -lt "$max_tries" ]; do
    if [ -f "$LOCK_FILE" ]; then
      pid=$(sed -n '2p' "$LOCK_FILE")

      if [ -d "/proc/$pid" ]; then
        log_info "$SCR_NAME lock file in use by PID $pid - wait time $(((max_tries - tries - 1) * 3)) secs left"
      else
        log_info "INFO! Stale lock file found (PID $pid is not running), removing the lock file."
        rm -f "$LOCK_FILE"
        continue
      fi

      sleep 3
      tries=$((tries + 1))
      [ "$tries" -ge "$max_tries" ] && kill_lock
    else
      echo "$@" >"$LOCK_FILE"
      echo "$$" >>"$LOCK_FILE"
      date +"%H:%M:%S %d-%b-%Y" >>"$LOCK_FILE"
      LOCK_ACTIVE="true"
      break
    fi
  done
}

kill_lock() {
  if [ -f "$LOCK_FILE" ]; then
    pid=$(sed -n '2p' "$LOCK_FILE")
    if [ -d "/proc/$pid" ]; then
      log_info "Killing locked processes ($(sed -n '1p' "$LOCK_FILE")) (pid=$pid)"
      log_info "$(ps | awk -v pid="$pid" '$1 == pid')"
      kill "$pid"
    else
      log_info "Process with PID $pid is not running, cleaning up lock file."
    fi
    rm -f "$LOCK_FILE"
  fi
}

check_entware() {
  max_tries="${1:-30}"
  tries=0

  while [ "$tries" -lt "$max_tries" ]; do
    if [ -f "/opt/bin/opkg" ]; then
      return 0 # Entware utilities ready
    fi
    sleep 1
    log_info "Entware not available - wait time $((max_tries - tries - 1)) secs left"
    tries=$((tries + 1))
  done

  return 1 # Entware utilities not available
}

get_param() {
  echo "$*" | sed -n "s/.*$1=\([^ ]*\).*/\1/p"
}

add_entry_to_file() {
  file="$1"
  entry="$2"

  if [ ! -f "$file" ]; then
    echo '#!/bin/sh' >"$file" && chmod 755 "$file"
  fi

  if ! grep -Fq "$entry" "$file"; then
    echo "$entry # $SCR_NAME for ipset name: $IPSET_NAME" >>"$file"
    log_info "$entry added to $file"
  fi
}

delete_entry_from_file() {
  file="$1"
  pattern="$2"

  if [ -f "$file" ]; then
    if grep -qw "$pattern" "$file"; then
      sed -i "\|\b$pattern\b|d" "$file" && log_info "Entry matching '$pattern' deleted from $file"
      [ "$file" = "$DNSMASQ_CONF" ] && service restart_dnsmasq >/dev/null 2>&1 && log_info "Restart dnsmasq service"
    fi
    check_if_empty "$file"
  fi
}

check_if_empty() {
  file="$1"

  if [ -f "$file" ]; then
    shebang_line=$(grep -c '^#!/bin/sh$' "$file")
    non_empty_lines=$(grep -cvE '^\s*$' "$file")
    non_empty_lines=$((non_empty_lines - shebang_line))
  fi

  if [ "$non_empty_lines" -eq 0 ]; then
    if [ "$DEL_FLAG" = "del" ]; then
      while true; do
        printf "NOTICE! '%s' is empty. Delete it? [Y/n]:" "$file"
        read -r "OPTION"
        case "$OPTION" in
          [yY][eE][sS] | [yY] | '') rm "$file" && log_info "File '$file' deleted." && break ;;
          [nN][oO] | [nN]) break ;;
          *) echo "Invalid option. File not deleted." ;;
        esac
      done
    elif [ "$DEL_FLAG" = "FORCE" ]; then
      rm "$file" && log_info "File '$file' deleted."
    fi
  fi
}

delete_Ipset_list() { # TODO: Refactor this function

  log_info "Checking files for entry..."
  for file in "$NAT_START" "$WG_START" "$WAN_EVENT" "$DNSMASQ_CONF" "$DIR/$IPSET_NAME"; do
    delete_entry_from_file "$file" "$IPSET_NAME"
  done

  log_info "Checking POSTROUTING iptables rules..." # Delete PREROUTING & POSTROUTING Rule for VPN Server to IPSET
  for server_tun in tun21 tun22 wgs1; do
    server=$(echo "$server_tun" | sed 's/tun21/1/; s/tun22/2/; s/wgs1/3/')
    tun="$(iptables -nvL PREROUTING -t mangle --line | grep "$server_tun" | grep "$IPSET_NAME" | grep "match-set" | awk '{print $7}')"
    if [ -n "$tun" ]; then
      define_iface "$IPSET_NAME"
      VPN_CLIENT_INSTANCE=$(echo "$IFACE" | awk '{print substr($0, length($0), 1)}')
      vpn_server_to_ipset "$server"
    fi
  done

  log_info "Checking PREROUTING iptables rules..."
  # Extract the last field (fwmark) from the iptables rule that matches the IP set name.
  fwmarks=$(iptables -nvL PREROUTING -t mangle --line | grep -w "$IPSET_NAME" | awk '{print $NF}')

  if [ -n "$fwmarks" ]; then
    iptables -nvL PREROUTING -t mangle --line |
      grep "br0" | grep "$IPSET_NAME" | grep "match-set" | awk '{print $1, $12}' | sort -nr |
      while read -r chain_num ipset_name; do
        iptables -t mangle -D PREROUTING "$chain_num" # Delete PREROUTING Rules for Normal IPSET routing
        log_info "Deleted PREROUTING Chain $chain_num for IPSET List $ipset_name"
      done

    # Delete the fwmark priority if no IPSET lists are using it
    for fwmark in $fwmarks; do
      if ! iptables -nvL PREROUTING -t mangle --line | grep -m 1 -w "$fwmark" >/dev/null; then
        ip rule del fwmark "$fwmark" 2>/dev/null && log_info "Deleted fwmark $fwmark"
      fi
    done
  fi

  log_info "Checking if IPSET list $IPSET_NAME exists..."
  if [ "$(ipset list -n "$IPSET_NAME" 2>/dev/null)" = "$IPSET_NAME" ]; then
    if ipset destroy "$IPSET_NAME"; then
      log_info "IPSET $IPSET_NAME deleted!"
    else
      exit_error "attempting to delete IPSET $IPSET_NAME!"
    fi
  fi

  log_info "Checking if IPSET backup file exists..."
  if [ -f "$DIR/$IPSET_NAME" ]; then
    non_empty_lines=$(grep -cvE '^\s*$' "$DIR/$IPSET_NAME")
    if [ "$DEL_FLAG" = "del" ]; then
      while true; do
        if [ "$non_empty_lines" -eq 0 ]; then
          printf "NOTICE! The backup '%s' is empty. Delete it? [Y/n]:" "$DIR/$IPSET_NAME" && default="y"
        else
          printf "WARNING! The backup '%s' is NOT empty. Delete it? [y/N]:" "$DIR/$IPSET_NAME" && default="n"
        fi
        read -r "OPTION"
        OPTION=${OPTION:-$default}
        case "$OPTION" in
          [yY][eE][sS] | [yY]) rm "$DIR/$IPSET_NAME" && log_info "File '$DIR/$IPSET_NAME' deleted." && break ;;
          [nN][oO] | [nN]) break ;;
          *) echo "Invalid option. File not deleted." ;;
        esac
      done
    elif [ "$DEL_FLAG" = "FORCE" ]; then
      rm "$DIR/$IPSET_NAME" && log_info "File '$DIR/$IPSET_NAME' deleted."
    fi
  fi
}

define_iface() {
  ### Define interface/bitmask to route traffic to. Use existing PREROUTING rule for IPSET to determine FWMARK.
  TAG_MARK=$(iptables -nvL PREROUTING -t mangle --line | grep -w "$IPSET_NAME" | awk '{print $(NF)}' | head -n 1)
  [ -z "$TAG_MARK" ] && exit_error "Mandatory PREROUTING rule for IPSET name $IPSET_NAME does not exist."
  fwmark_substr=$(echo "$TAG_MARK" | cut -c 3-6)

  case "$fwmark_substr" in
    8000) IFACE="br0" ;;
    a000) IFACE="wgc1" ;;
    b000) IFACE="wgc2" ;;
    c000) IFACE="wgc3" ;;
    d000) IFACE="wgc4" ;;
    e000) IFACE="wgc5" ;;
    1000) IFACE="tun11" ;;
    2000) IFACE="tun12" ;;
    4000) IFACE="tun13" ;;
    7000) IFACE="tun14" ;;
    3000) IFACE="tun15" ;;
    *) exit_error "$1 should be 1-5 for WireGuard Client or 11-15 for OpenVPN Client" ;;
  esac
}

server_param() { # TODO: Refactor this function (Special processing for VPN Server)
  server=$(get_param "server" "$@")
  case "$server" in
    1 | 2 | 3 | all) ;;
    *) exit_error "Invalid Server '$server' specified." ;;
  esac

  parse_protocol_and_ports "$@" # Sets PROTOCOL_PORT_RULE & PROTOCOL_PORT_PARAMS

  ### Process server when 'client=' specified
  if [ "$(echo "$@" | grep -c 'client=')" -gt 0 ]; then
    VPN_CLIENT_INSTANCE=$(get_param "client" "$@")
    case "$VPN_CLIENT_INSTANCE" in
      [1-5]) IFACE="wgc${VPN_CLIENT_INSTANCE}" ;;
      1[1-5]) IFACE="tun${VPN_CLIENT_INSTANCE}" ;;
      *) exit_error "'client=$VPN_CLIENT_INSTANCE' must be 1-5 for WireGuard client or 11-15 for OpenVPN client." ;;
    esac

    if [ "$server" = "all" ]; then
      for server in 1 2 3; do
        VPN_Server_to_VPN_Client "$server"
      done
    else
      VPN_Server_to_VPN_Client "$server"
    fi
    exit_routine
  fi

  #### Process server when 'ipset_name=' specified
  if [ "$(echo "$@" | grep -c 'ipset_name=')" -ge 1 ]; then
    IPSET_NAME=$(get_param "ipset_name" "$@" | tr ',' ' ')

    for IPSET_NAME in $IPSET_NAME; do
      if [ -n "$IPSET_NAME" ]; then # Check if IPSET list exists
        if [ "$(ipset list -n "$IPSET_NAME" 2>/dev/null)" != "$IPSET_NAME" ]; then
          exit_error "IPSET name $IPSET_NAME does not exist."
        fi
      fi

      define_iface "$IPSET_NAME"

      if [ "$server" = "all" ]; then
        for server in 1 2 3; do
          vpn_server_to_ipset "$server"
        done
      else
        vpn_server_to_ipset "$server"
      fi
    done

    script_entry="sh $SCR_DIR/$SCR_NAME.sh $1 $2 $PROTOCOL_PORT_PARAMS"
    if [ -z "$DEL_FLAG" ]; then
      add_entry_to_file "$NAT_START" "$script_entry"
    else
      delete_entry_from_file "$NAT_START" "$1 $2"
    fi
    exit_routine
  fi
}

VPN_Server_to_VPN_Client() { # TODO: Refactor this function (Work only with OpenVPN?)
  vpn_server_instance=$1
  script_entry="sh $SCRIPT_DIR/$SCR_NAME.sh server=$vpn_server_instance client=$VPN_CLIENT_INSTANCE"
  vpn_server_subnet="$(nvram get vpn_server"${vpn_server_instance}"_sn)/24"
  IPT_DEL_ENTRY="iptables -t nat -D POSTROUTING -s \"\$(nvram get vpn_server${vpn_server_instance}_sn)\"/24 -o $IFACE $PROTOCOL_PORT_PARAMS -j MASQUERADE 2>/dev/null"
  IPT_ADD_ENTRY="iptables -t nat -A POSTROUTING -s \"\$(nvram get vpn_server${vpn_server_instance}_sn)\"/24 -o $IFACE $PROTOCOL_PORT_PARAMS -j MASQUERADE"
  POLICY_RULE_WITHOUT_NAME="${vpn_server_subnet}>>VPN"
  POLICY_RULE="<VPN Server ${vpn_server_instance}>${vpn_server_subnet}>>VPN"

  VPN_IP_LIST="$(nvram get vpn_client"$VPN_CLIENT_INSTANCE"_clientlist)"
  for n in $VPN_IDS; do
    VPN_IP_LIST="${VPN_IP_LIST}$(nvram get vpn_client"$VPN_CLIENT_INSTANCE"_clientlist"${n}")"
  done

  if [ -z "$DEL_FLAG" ]; then # add entry if DEL_FLAG is null
    eval "$IPT_DEL_ENTRY"
    eval "$IPT_ADD_ENTRY"

    iptables -t nat -D POSTROUTING -s "$vpn_server_subnet" -o "$IFACE" $PROTOCOL_PORT_PARAMS -j MASQUERADE 2>/dev/null
    iptables -t nat -A POSTROUTING -s "$vpn_server_subnet" -o "$IFACE" $PROTOCOL_PORT_PARAMS -j MASQUERADE

    add_entry_to_file "$NAT_START" "$script_entry"

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
      logger -st "($(basename "$0"))" $$ "Restarting VPN Client ${VPN_CLIENT_INSTANCE} to add policy rule for VPN Server ${vpn_server_instance}"
      service restart_vpnclient"${VPN_CLIENT_INSTANCE}"
    else # if the VPN Server entry exists in nvram using the 'vpnserverX' name created by the prior version, convert it to the new name
      if [ "$(echo "$VPN_IP_LIST" | grep -c "vpnserver${vpn_server_instance}")" -ge 1 ]; then
        VPN_IP_LIST="$(echo "$VPN_IP_LIST" | sed "s/<vpnserver${vpn_server_instance}>/<VPN Server ${vpn_server_instance}>/")"
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
        logger -st "($(basename "$0"))" $$ "Restarting vpnclient ${VPN_CLIENT_INSTANCE} for policy rule for VPN Server ${vpn_server_instance} to take effect"
        service restart_vpnclient"${VPN_CLIENT_INSTANCE}"
      fi
    fi
  else # 'del' or 'del=force' parameter passed. Delete routing and routing rules in vpn server up down scripts.
    iptables -t nat -D POSTROUTING -s "$vpn_server_subnet" -o "$IFACE" -p tcp -m multiport --dports 80,443 -j MASQUERADE 2>/dev/null

    # nat-start File
    if [ -s "$NAT_START" ]; then
      sed "/server=$vpn_server_instance client=$VPN_CLIENT_INSTANCE/d" "$NAT_START" >"$NAT_START.tmp" && mv "$NAT_START.tmp" "$NAT_START"
      logger -t "($(basename "$0"))" $$ "$script_entry entry deleted from $NAT_START"
      check_if_empty "$NAT_START"
    fi

    # nvram get vpn_client"${VPN_CLIENT_INSTANCE}"_clientlist
    if [ "$(echo "$VPN_IP_LIST" | grep -c "$POLICY_RULE")" -eq "1" ]; then
      VPN_IP_LIST="$(echo "$VPN_IP_LIST" | sed "s,<VPN Server ${vpn_server_instance}>${vpn_server_subnet}>>VPN,,")"
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
      logger -st "($(basename "$0"))" $$ "Restarting vpnclient ${VPN_CLIENT_INSTANCE} to remove policy rule for VPN Server ${vpn_server_instance}"
      service restart_vpnclient"${VPN_CLIENT_INSTANCE}"
    fi
  fi

  [ -s "$NAT_START" ] && chmod 755 "$NAT_START" # set permissions for each file
}

vpn_server_to_ipset() { # TODO: Refactor this function
  vpn_server_instance=$1

  case "$vpn_server_instance" in
    1)
      vpn_server_tun="tun21"
      vpn_server_subnet="$(nvram get vpn_server1_sn)/24" # Get VPN Server IP
      ;;
    2)
      vpn_server_tun="tun22"
      vpn_server_subnet="$(nvram get vpn_server2_sn)/24"
      ;;
    3)
      vpn_server_tun="wgs1"
      vpn_server_subnet="$(nvram get wgs_addr)" # Already includes the subnet mask
      ;;
    *) exit_error "VPN Server instance $vpn_server_instance should be a 1, 2 for OpenVPN or 3 for WireGuard" ;;
  esac

  if [ -z "$DEL_FLAG" ]; then
    iptables -t nat -D POSTROUTING -s "$vpn_server_subnet" -o "$IFACE" "$PROTOCOL_PORT_RULE" -j MASQUERADE 2>/dev/null
    iptables -t nat -A POSTROUTING -s "$vpn_server_subnet" -o "$IFACE" $PROTOCOL_PORT_RULE -j MASQUERADE
    iptables -t mangle -D PREROUTING -i $vpn_server_tun -m set --match-set "$IPSET_NAME" dst $PROTOCOL_PORT_RULE -j MARK --set-mark "$TAG_MARK" 2>/dev/null
    iptables -t mangle -A PREROUTING -i $vpn_server_tun -m set --match-set "$IPSET_NAME" dst $PROTOCOL_PORT_RULE -j MARK --set-mark "$TAG_MARK"
  else # 'del' or 'del=force' option specified.
    iptables -nvL PREROUTING -t mangle --line | grep $vpn_server_tun | grep "$IPSET_NAME" | grep "match-set" | awk '{print $1}' | sort -nr | while read -r chain_num; do
      iptables -t mangle -D PREROUTING "$chain_num" && log_info "Deleted PREROUTING Chain $chain_num for IPSET List $IPSET_NAME on $vpn_server_tun"
    done

    iptables -nvL POSTROUTING -t nat --line | grep "${vpn_server_subnet%%/*}" | grep "$IFACE" | awk '{print $1}' | sort -nr | while read -r chain_num; do
      iptables -t nat -D POSTROUTING "$chain_num" && log_info "Deleted POSTROUTING Chain $chain_num for IPSET List $IPSET_NAME on $IFACE"
    done
  fi
}

dnsmasq_param() {
  dnsmasq_file=$(get_param "dnsmasq_file" "$@")
  domains=$(get_param "dnsmasq" "$@" | tr ',' '/' | sed 's|/$||')

  [ -z "$domains" ] && [ -s "$dnsmasq_file" ] && domains=$(tr '\n' '/' <"$dnsmasq_file" | sed 's|/$||')
  [ -z "$domains" ] && exit_error "No DNSMASQ parameter specified."

  update_dnsmasq_conf "$domains"
}

harvest_dnsmasq_queries() {
  scan_list=$(get_param "autoscan" "$@" | tr ',' '|')
  [ -z "$scan_list" ] && exit_error "'autoscan' parameter cannot be empty."

  for file in "/opt/var/log/dnsmasq.log" "/tmp/var/log/dnsmasq.log"; do
    [ -s "$file" ] && DNSMASQ_LOG="$file" && break
  done
  [ -z "$DNSMASQ_LOG" ] && DNSMASQ_LOG=$(find / -name "dnsmasq.log" -type f -print -quit 2>/dev/null)
  [ -z "$DNSMASQ_LOG" ] && exit_error "dnsmasq.log file NOT found!"

  domains=$(grep -E "$scan_list" "$DNSMASQ_LOG" | awk '/query/ {print $(NF-2)}' | sort -u | tr '\n' '/' | sed 's|/$||')

  if [ -n "$domains" ]; then
    update_dnsmasq_conf "$domains"
  else
    exit_error "No domain names were harvested from $DNSMASQ_LOG"
  fi
}

update_dnsmasq_conf() {
  domains="$1"

  [ -s "$DNSMASQ_CONF" ] && sed -i "\|ipset=.*$IPSET_NAME|d" "$DNSMASQ_CONF"
  echo "ipset=/$domains/$IPSET_NAME" >>"$DNSMASQ_CONF" && log_info "Added $domains to $DNSMASQ_CONF"
  service restart_dnsmasq >/dev/null 2>&1 && log_info "Restart dnsmasq service"
}

asnum_param() {
  asn=$(get_param "asnum" "$@" | tr ',' ' ')
  [ -z "$asn" ] && exit_error "'asnum' parameter cannot be empty."

  for asn in $asn; do
    prefix=$(printf '%-.2s' "$asn")
    number="$(echo "$asn" | sed 's/^AS//')"
    if [ "$prefix" = "AS" ]; then
      # Check for valid Number and skip if bad
      A=$(echo "$number" | grep -Eo '^[0-9]+$')
      if [ -z "$A" ]; then
        echo "Skipping invalid ASN: $number"
      else
        fetch_asn_to_ipset "$asn"
      fi
    else
      exit_error "Invalid Prefix specified: $prefix. Valid value is 'AS'"
    fi
  done
}

fetch_asn_to_ipset() {
  asn="$1"
  file="$DIR/$asn.json"
  url="https://api.bgpview.io/asn/$asn/prefixes" # https://stat.ripe.net/data/as-routing-consistency/data.json?resource=

  log_info "Fetching data from: $url"
  curl --retry 3 --connect-timeout 3 -sfL -o "$file" "$url" || exit_error "Fetching failed."
  tr -d "\\" <"$file" | grep -oE "$CIDR_REGEX" | sort -ut '.' -k1,1n -k2,2n -k3,3n -k4,4n -o "$DIR/$IPSET_NAME" && rm -f $file
}

aws_param() {
  aws_regions=$(get_param "aws_region" "$@" | tr ',' ' ' | awk '{print toupper($0)}')
  [ -z "$aws_regions" ] && exit_error "'aws_region' parameter cannot be empty."

  for aws_region in $aws_regions; do
    case "$aws_region" in
      AP) regions="ap-east-1 ap-northeast-1 ap-northeast-2 ap-northeast-3 ap-south-1 ap-southeast-1 ap-southeast-2" ;;
      CA) regions="ca-central-1" ;;
      CN) regions="cn-north-1 cn-northwest-1" ;;
      EU) regions="eu-central-1 eu-north-1 eu-west-1 eu-west-2 eu-west-3" ;;
      SA) regions="sa-east-1" ;;
      US) regions="us-east-1 us-east-2 us-west-1 us-west-2" ;;
      GV) regions="us-gov-east-1 us-gov-west-1" ;;
      GLOBAL) regions="GLOBAL" ;;
      *) exit_error "Invalid AMAZON region specified: $aws_region. Valid values are: AP CA CN EU SA US GV GLOBAL" ;;
    esac
    fetch_aws_to_ipset "$regions"
  done
}

fetch_aws_to_ipset() {
  regions=$1
  file="$DIR/aws-ip-ranges.json"
  url="https://ip-ranges.amazonaws.com/ip-ranges.json"

  if [ ! -s "$file" ] || [ -n "$(find "$file" -mtime +7)" ]; then
    log_info "Fetching data from: $url"
    if ! curl --retry 3 --connect-timeout 3 -sfL -o "$file" "$url"; then
      if [ -s "$file" ]; then
        log_warning "Fetching failed. Using existing $file."
      else
        exit_error "Fetching failed and no existing $file."
      fi
    fi
  fi

  for region in $regions; do
    grep -B 1 "\"region\": \"$region\"" "$file" | grep -oE "$CIDR_REGEX"
  done | sort -ut '.' -k1,1n -k2,2n -k3,3n -k4,4n -o "$DIR/$IPSET_NAME"
}

ip_param() {
  ips=$(get_param "ip" "$@" | tr ',' ' ')
  [ -z "$ips" ] && exit_error "'ip' parameter cannot be empty."

  [ -n "$ips" ] && for ip in $ips; do
    echo "$ip" | grep -oE "$IP_RE(/$IP_RE_PREFIX)?" || log_warning "$ip is an invalid IP or CIDR. Skipping entry." >&2
  done | sort -ut '.' -k1,1n -k2,2n -k3,3n -k4,4n -o "$DIR/$IPSET_NAME"
}

parse_protocol_and_ports() { # TODO: Refactor this function (protocols="tcp:80,443 udp:53 icmp")
  protocol=$(get_param "protocol" "$*" | awk '{print tolower($0)}')
  ports=$(get_param "ports" "$*")

  PROTOCOL_PORT_RULE=""
  PROTOCOL_PORT_PARAMS=""

  if [ -n "$protocol" ]; then
    protocols=$(awk '{print tolower($1)}' /etc/protocols | grep -v '^#' | tr '\n' ' ')

    echo "$protocols" | grep -qw "$protocol" || exit_error "Unsupported protocol: '$protocol'."

    if [ -n "$ports" ]; then
      if ! echo "$ports" | grep -Eq '^[0-9]+(,[0-9]+)*$'; then
        exit_error "The 'ports=' parameter should contain only digits and commas."
      elif ! echo "tcp udp udplite sctp dccp" | grep -qw "$protocol"; then
        exit_error "Unsupported protocol '$protocol' for port parameter. Accept only TCP, UDP, UDPLITE, SCTP, DCCP."
      else
        port_list=$(echo "$ports" | tr ',' ' ')
        for port in $port_list; do
          if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
            exit_error "Port numbers in 'ports=' must be between 1 and 65535."
          fi
        done
      fi
    fi

    if [ -n "$protocol" ] && [ -n "$ports" ]; then
      PROTOCOL_PORT_RULE="-p $protocol -m multiport --dports $ports"
      PROTOCOL_PORT_PARAMS="protocol=$protocol ports=$ports"
    elif [ -n "$protocol" ] && [ -z "$ports" ]; then
      PROTOCOL_PORT_RULE="-p $protocol"
      PROTOCOL_PORT_PARAMS="protocol=$protocol"
    fi
  fi
}

parse_src_option() {
  src=$(get_param "src" "$@")
  src_range=$(get_param "src_range" "$@")

  SRC_RULE=""
  SRC_PARAMS=""

  if [ -n "$src" ]; then
    echo "$src" | grep -qE "^$IP_RE$" || exit_error "'src=$src' not a valid IP address."

    SRC_RULE="--src $src"
    SRC_PARAMS="src=$src"
  fi

  if [ -n "$src_range" ]; then
    echo "$src_range" | grep -qE "^$IP_RE-$IP_RE$" || exit_error "'src_range=$src_range' not a valid IP range."

    ip_start=$(echo "$src_range" | awk -F '[-.]' '{print ($1 * 256^3) + ($2 * 256^2) + ($3 * 256) + $4}')
    ip_end=$(echo "$src_range" | awk -F '[-.]' '{print ($5 * 256^3) + ($6 * 256^2) + ($7 * 256) + $8}')
    [ "$ip_start" -gt "$ip_end" ] && exit_error "'src_range=$src_range' is not valid, start IP greater than end IP."

    SRC_RULE="--src-range $src_range"
    SRC_PARAMS="src_range=$src_range"
  fi
}

check_files_for_entries() {
  script_entry="sh $SCR_DIR/$SCR_NAME.sh"

  if [ -n "$SRC_IFACE" ] && [ -n "$DST_IFACE" ]; then
    script_entry="$script_entry $SRC_IFACE $DST_IFACE $IPSET_NAME $SRC_PARAMS $PROTOCOL_PORT_PARAMS"
  else
    script_entry="$script_entry ipset_name=$IPSET_NAME"
  fi

  [ "$DIR" != "/opt/tmp" ] && script_entry="$script_entry dir=$DIR"

  add_entry_to_file "$NAT_START" "$script_entry"
}

set_routing_tags() {
  case "$DST_IFACE" in
    0)
      TAG_MARK="0x8000/0xf000"
      ROUTE_TABLE=254
      priority=9980
      ;;
    1)
      TAG_MARK="0xa000/0xf000"
      ROUTE_TABLE=wgc1
      priority=9999
      ;;
    2)
      TAG_MARK="0xb000/0xf000"
      ROUTE_TABLE=wgc2
      priority=9998
      ;;
    3)
      TAG_MARK="0xc000/0xf000"
      ROUTE_TABLE=wgc3
      priority=9997
      ;;
    4)
      TAG_MARK="0xd000/0xf000"
      ROUTE_TABLE=wgc4
      priority=9996
      ;;
    5)
      TAG_MARK="0xe000/0xf000"
      ROUTE_TABLE=wgc5
      priority=9995
      ;;
    11)
      TAG_MARK="0x1000/0xf000"
      ROUTE_TABLE=ovpnc1
      priority=9994
      ;;
    12)
      TAG_MARK="0x2000/0xf000"
      ROUTE_TABLE=ovpnc2
      priority=9993
      ;;
    13)
      TAG_MARK="0x4000/0xf000"
      ROUTE_TABLE=ovpnc3
      priority=9992
      ;;
    14)
      TAG_MARK="0x7000/0xf000"
      ROUTE_TABLE=ovpnc4
      priority=9991
      ;;
    15)
      TAG_MARK="0x3000/0xf000"
      ROUTE_TABLE=ovpnc5
      priority=9990
      ;;
    *)
      exit_error "$DST_IFACE should be 0-WAN or 1-5 for WireGuard Client or 11-15 for OpenVPN Client"
      ;;
  esac
}

set_fwmark_ip_rule() {
  if ! ip rule | grep -q "$TAG_MARK"; then
    ip rule add from 0/0 fwmark "$TAG_MARK" table "$ROUTE_TABLE" prio "$priority" && log_info "Created fwmark $TAG_MARK"
    ip route flush cache
  fi
}

set_wg_rp_filter() {
  if [ "${ROUTE_TABLE#wgc}" != "$ROUTE_TABLE" ]; then # Check if $ROUTE_TABLE starts with 'wgc'
    # Here we set the reverse path filtering mode for the interface 'wgc*'.
    # This setting is only necessary for WireGuard. OpenVPN on Asuswrt-Merlin defaults to '0'.
    # 0 - Disables reverse path filtering, accepting all packets without verifying the source route.
    # 1 - Strict mode, accepting packets only if the route to the source IP matches the incoming interface.
    # 2 - Loose mode, allowing packets to be accepted on any interface as long as a route to the source IP exists.
    rp_filter="echo 2 >/proc/sys/net/ipv4/conf/$ROUTE_TABLE/rp_filter"

    if [ -f "/proc/sys/net/ipv4/conf/$ROUTE_TABLE/rp_filter" ]; then
      eval "$rp_filter"
    else
      log_info "rp_filter file not found, VPN server '$ROUTE_TABLE' likely disabled."
    fi

    for file in "$NAT_START" "$WG_START" "$WAN_EVENT"; do
      add_entry_to_file "$file" "$rp_filter" # Ensure 'rp_filter' is set across restart and reboot.
    done
  fi
}

setup_ipset_list() {
  if ! ipset list -n "$IPSET_NAME" >/dev/null 2>&1; then
    ipset create "$IPSET_NAME" hash:net family inet hashsize 1024 maxelem 65536 && touch "$DIR/$IPSET_NAME"
    log_info "Created IPSET: $IPSET_NAME and file: $DIR/$IPSET_NAME"
  fi

  if [ -s "$DIR/$IPSET_NAME" ]; then
    if grep -q "create" "$DIR/$IPSET_NAME"; then
      ipset restore -! <"$DIR/$IPSET_NAME"
      log_info "Restored IPSET: $IPSET_NAME from $DIR/$IPSET_NAME NOTE! File is in dnsmasq format."
    else
      sed "s/^/add $IPSET_NAME /" "$DIR/$IPSET_NAME" | ipset restore -!
      log_info "Restored IPSET: $IPSET_NAME from $DIR/$IPSET_NAME"
    fi
  fi
}

create_routing_rules() {
  iptables -t mangle -D PREROUTING -i br0 $SRC_RULE -m set --match-set "$IPSET_NAME" dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK 2>/dev/null
  log_info "Selective routing rule via $ROUTE_TABLE deleted for $IPSET_NAME fwmark $TAG_MARK"
  iptables -t mangle -A PREROUTING -i br0 $SRC_RULE -m set --match-set "$IPSET_NAME" dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK
  log_info "Selective routing rule via $ROUTE_TABLE created for $IPSET_NAME fwmark $TAG_MARK"
}

if [ "$1" = "help" ] || [ "$1" = "-h" ]; then
  show_help
  exit 0
fi

check_entware 120 || exit_error "Entware not ready. Unable to access ipset save/restore location"
log_info "Starting Script Execution $*"
check_lock "$@"

# Check if user specified 'dir=' parameter
DIR=$(case "$@" in
  *dir=*) get_param "dir" "$@" ;; # Mount point/directory for backups
  *) echo "/opt/tmp" ;;
esac)

# Set SRC_IFACE and DST_IFACE unless 'server=' or 'ipset_name=' are used
if echo "$1" | grep -q '^server='; then # TODO: Simplify logic
  if ! echo "$2" | grep -Eq '^(client=|ipset_name=)'; then
    exit_error "Second parameter must be 'client=' or 'ipset_name='."
  else
    IPSET_NAME=$(get_param "ipset_name" "$@")
    [ -z "$IPSET_NAME" ] && exit_error "'ipset_name' parameter cannot be empty."
  fi
elif echo "$1" | grep -Eq '^ipset_name='; then
  if echo "$2" | grep -Eq '^(src=|src_range=)'; then
    exit_error "'src=' or 'src_range=' cannot be used with 'ipset_name='."
  else
    IPSET_NAME=$(get_param "ipset_name" "$@")
    [ -z "$IPSET_NAME" ] && exit_error "'ipset_name' parameter cannot be empty."
  fi
elif echo "$1" | grep -Eq '^[0-5]|1[1-5]$'; then
  SRC_IFACE=$1
  DST_IFACE=$2
  IPSET_NAME=$3

  if [ -n "$DST_IFACE" ]; then
    if { [ "$SRC_IFACE" = 0 ] && ! echo "$DST_IFACE" | grep -Eq '^[1-5]|1[1-5]$'; } ||
      { echo "$VPN_IDS" | grep -qw "$SRC_IFACE" && [ "$DST_IFACE" != 0 ]; }; then
      exit_error "Invalid source '$SRC_IFACE' and destination '$DST_IFACE' combination."
    fi

    if [ -n "$IPSET_NAME" ]; then
      if ! echo "$IPSET_NAME" | grep -Eq '^[a-zA-Z0-9_-]{1,31}$'; then
        exit_error "$IPSET_NAME is invalid: use only A-Z, a-z, 0-9, _ or -, max 31 symbols."
      fi
    else
      exit_error "Third parameter must be IPSET name"
    fi

    if ! echo "$@" | grep -qE '\s(del|dnsmasq|autoscan|asnum|aws_region|ip)' && # none of the params are present
      [ ! -s "$DIR/$IPSET_NAME" ] &&                                            # file does not exist or is empty
      ! ipset list -n | grep -qFx "$IPSET_NAME" &&                              # ipset does not exist
      ! grep -q "ipset=.*$IPSET_NAME" "$DNSMASQ_CONF"; then                     # no entry in $DNSMASQ_CONF
      exit_error "$DIR/$IPSET_NAME missing or empty, ipset $IPSET_NAME not found, no entry for $IPSET_NAME in $DNSMASQ_CONF."
    fi
  else
    exit_error "Second parameter must be 0 (WAN), 1-5 (WireGuard), or 11-15 (OpenVPN)."
  fi
else
  exit_error "First parameter must be 'server=', 'ipset_name=', 0 (WAN), 1-5 (WireGuard), or 11-15 (OpenVPN)."
fi

case "$@" in
  *del=force*) DEL_FLAG="FORCE" && delete_Ipset_list && exit_routine ;;
  *del*) DEL_FLAG="del" && delete_Ipset_list && exit_routine ;;
  *server=*) server_param "$@" ;;
  *dnsmasq=* | *dnsmasq_file=*) dnsmasq_param "$@" ;;
  *autoscan=*) harvest_dnsmasq_queries "$@" ;;
  *asnum=*) asnum_param "$@" ;;
  *aws_region=*) aws_param "$@" ;;
  *ip=*) ip_param "$@" ;;
  *) ;;
esac

if [ -n "$SRC_IFACE" ] && [ -n "$DST_IFACE" ]; then
  parse_protocol_and_ports "$@" # Sets PROTOCOL_PORT_RULE & PROTOCOL_PORT_PARAMS
  parse_src_option "$@"         # Sets SRC_RULE & SRC_PARAMS
  check_files_for_entries "$@"
  set_routing_tags
  set_fwmark_ip_rule
  set_wg_rp_filter
  setup_ipset_list
  create_routing_rules
elif echo "$1" | grep -Eq '^ipset_name='; then
  check_files_for_entries "$@"
  setup_ipset_list
fi

exit_routine
