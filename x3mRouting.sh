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
# Last updated: 25-Nov-2024
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
#            ['ip_file='/path/to/file] # Same as 'ip='
#            ['src='src_ip]
#            ['src_range='from_ip-to_ip]
#            ['dir='save_restore_location] # if 'dir' not specified, defaults to /opt/tmp
#            ['del'] # Delete IPSET list and all configuration settings.
#                    # **Will prompt** for permission to delete any files if only a shebang exists
#            ['del=force'] # Force delete the IPSET list and all configuration settings if only
#                          # a shebang exists. **Will not** prompt for permission before deleting a
#                          # file if only a shebang exists.
#            ['proto='"protocol[:port][,port] [protocol] ..." # protocol e.g. 'tcp','udp'  port e.g. '80','443'
#                                                             # Use: proto="tcp:80,443 udp:443 icmp" | proto=tcp:80,443
#---------------------------------------------------------------------------------------------------
# Create IPSET List with no Routing Rules:
#
# x3mRouting {ipset_name=}
#            ['autoscan='keyword1[,keyword2]...] # Scans for keywords and creates IPSET list using the dnsmasq method
#            ['asnum='asnum[,asnum]...] # ASN method
#            ['aws_region='US[,EU]...]  # Amazon method
#            ['dnsmasq='domain[,domain]...] # dnsmasq method
#            ['dnsmasq_file='/path/to/file] # dnsmasq method
#            ['ip='ip[,ip][,cidr]...] # Equivalent to manual method (can be used to add entry to existing IPSET list)
#            ['ip_file='/path/to/file] # Same as 'ip='
#            ['dir='save_restore_location] # if 'dir' not specified, defaults to /opt/tmp
#            ['del'] # Delete IPSET list and all configuration settings.
#                    # **Will prompt** for permission to delete any files if only a shebang exists
#            ['del=force'] # Force delete the IPSET list and all configuration settings if only
#                          # a shebang exists. **Will not** prompt for permission before deleting a
#                          # file if only a shebang exists.
#---------------------------------------------------------------------------------------------------
# VPN Server to VPN Client Routing: (Work only with OpenVPN)
#
# x3mRouting {'server='1|2} {'client='11|12|13|14|15} ['del'] ['del=force']
#---------------------------------------------------------------------------------------------------
# VPN Server to existing LAN routing rules for one or more IPSET lists
#
# x3mRouting {'server='1|2|3|all} {'ipset_name='IPSET[,IPSET]...} ['proto='"protocol[:port][,port] ..." ['del'[=force]]
#___________________________________________________________________________________________________

SCR_NAME=$(basename "$0" | sed 's/.sh//')     # Script name without .sh
SCR_DIR=$(dirname "$(readlink -f "$0")")      # Script directory (absolute path)
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

release_lock() {
  [ -f "$LOCK_FILE" ] && rm -f "$LOCK_FILE"
}

exit_error() {
  [ "$LOCK_ACTIVE" = "true" ] && release_lock
  log_info "ERROR! $*"
  exit 1
}

exit_routine() {
  [ "$LOCK_ACTIVE" = "true" ] && release_lock
  log_info "Complete script execution"
  exit 0
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
  printf "%s\n" "$@" | grep "^$1=" | cut -d'=' -f2
}

add_entry_to_file() {
  file="$1"
  entry="$2"

  if [ ! -f "$file" ]; then
    echo '#!/bin/sh' >"$file" && chmod 755 "$file"
  fi

  if ! grep -Fq "$entry" "$file"; then
    echo "$entry # $SCR_NAME for ipset name: $IPSET_NAME" >>"$file"
    log_info "Add '$entry' to $file"
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
        read -r option
        case "${option:-y}" in
          [yY][eE][sS] | [yY]) rm "$file" && log_info "Deleted file $file" && break ;;
          [nN][oO] | [nN]) break ;;
          *) echo "Invalid option. File not deleted." ;;
        esac
      done
    elif [ "$DEL_FLAG" = "FORCE" ]; then
      rm "$file" && log_info "Deleted file $file"
    fi
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

ipt() {
  table=$1
  chain=$2
  rule=$3

  eval "iptables -t $table -D $chain $rule" 2>/dev/null
  eval "iptables -t $table -A $chain $rule"
  log_info "Set iptables -t $table -A $chain $rule"
}

vpns_to_vpnc() { # TODO: Add WG support
  vpns_id=$1
  vpnc_id=$2

  vpns_sub="$(nvram get vpn_server"${vpns_id}"_sn)/24"
  policy_rule="<VPN Server ${vpns_id}>${vpns_sub}>>VPN"

  vpnc_iface="tun${vpnc_id}"
  vpnc_ip_list="$(nvram get vpn_client"${vpnc_id#1}"_clientlist)"

  for n in 1 2 3 4 5; do
    vpnc_ip_list="${vpnc_ip_list}$(nvram get vpn_client"$vpnc_id"_clientlist"${n}")"
  done

  if [ -z "$DEL_FLAG" ]; then # Add entry if DEL_FLAG is null
    ipt nat POSTROUTING "-s $vpns_sub -o $vpnc_iface $PROTO_PARAM -j MASQUERADE"
    add_entry_to_file "$NAT_START" "sh $SCRIPT_DIR/$SCR_NAME.sh server=$vpns_id client=$vpnc_id"

    # Add nvram entry to vpn_client"${VPN_CLIENT_INSTANCE}"_clientlist
    if [ "$(echo "$vpnc_ip_list" | grep -c "${vpns_sub}>>VPN")" -eq 0 ]; then
      vpnc_ip_list="${vpnc_ip_list}${policy_rule}"
      if [ "$(uname -m)" = "aarch64" ]; then
        low=0
        max=255
        for n in "" $VPN_IDS; do
          nvram set vpn_client"${VPN_CLIENT_INSTANCE}"_clientlist"${n}"="$(echo "$vpnc_ip_list" | cut -b $low-$max)"
          low=$((max + 1))
          max=$((low + 254))
        done
      else
        nvram set vpn_client"${VPN_CLIENT_INSTANCE}"_clientlist="$vpnc_ip_list"
      fi
      nvram commit
      log_info "Restarting VPN Client ${VPN_CLIENT_INSTANCE} to add policy rule for VPN Server ${vpns_id}"
      service restart_vpnclient"${VPN_CLIENT_INSTANCE}"
    else # if the VPN Server entry exists in nvram using the 'vpnserverX' name created by the prior version, convert it to the new name
      if [ "$(echo "$vpnc_ip_list" | grep -c "vpnserver${vpns_id}")" -ge 1 ]; then
        vpnc_ip_list="$(echo "$vpnc_ip_list" | sed "s/<vpnserver${vpns_id}>/<VPN Server ${vpns_id}>/")"
        if [ "$(uname -m)" = "aarch64" ]; then
          low=0
          max=255
          for n in "" $VPN_IDS; do
            nvram set vpn_client"${VPN_CLIENT_INSTANCE}"_clientlist"${n}"="$(echo "$vpnc_ip_list" | cut -b $low-$max)"
            low=$((max + 1))
            max=$((low + 254))
          done
        else
          nvram set vpn_client"${VPN_CLIENT_INSTANCE}"_clientlist="$vpnc_ip_list"
        fi
        nvram commit
        log_info "Restarting vpnclient ${VPN_CLIENT_INSTANCE} for policy rule for VPN Server ${vpns_id} to take effect"
        service restart_vpnclient"${VPN_CLIENT_INSTANCE}"
      fi
    fi
  else # 'del' or 'del=force' parameter passed.
    iptables -t nat -D POSTROUTING -s "$vpns_sub" -o "$vpnc_iface" -p tcp -m multiport --dports 80,443 -j MASQUERADE 2>/dev/null

    delete_entry_from_file $NAT_START "server=$vpns_id client=$VPN_CLIENT_INSTANCE"

    # nvram get vpn_client"${VPN_CLIENT_INSTANCE}"_clientlist
    if [ "$(echo "$vpnc_ip_list" | grep -c "$policy_rule")" -eq "1" ]; then
      vpnc_ip_list="$(echo "$vpnc_ip_list" | sed "s,<VPN Server ${vpns_id}>${vpns_sub}>>VPN,,")"
      if [ "$(uname -m)" = "aarch64" ]; then
        low=0
        max=255
        for n in "" $VPN_IDS; do
          nvram set vpn_client"${VPN_CLIENT_INSTANCE}"_clientlist"${n}"="$(echo "$vpnc_ip_list" | cut -b $low-$max)"
          low=$((max + 1))
          max=$((low + 254))
        done
      else
        nvram set vpn_client"${VPN_CLIENT_INSTANCE}"_clientlist="$vpnc_ip_list"
      fi
      nvram commit
      log_info "Restarting vpnclient ${VPN_CLIENT_INSTANCE} to remove policy rule for VPN Server ${vpns_id}"
      service restart_vpnclient"${VPN_CLIENT_INSTANCE}"
    fi
  fi
}

vpns_to_ipset() {
  case "$1" in
    1 | tun21)
      vpns_iface="tun21"
      vpns_sub="$(nvram get vpn_server1_sn)/24" # Get VPN Server IP
      ;;
    2 | tun22)
      vpns_iface="tun22"
      vpns_sub="$(nvram get vpn_server2_sn)/24"
      ;;
    3 | wgs1)
      vpns_iface="wgs1"
      vpns_sub="$(nvram get wgs_addr)" # Already includes the subnet mask
      ;;
  esac

  # Extract the last field (fwmark) from the iptables PREROUTING rule that matches the IPSET name.
  fwmark=$(iptables -nvL PREROUTING -t mangle --line | grep -w "$IPSET_NAME" | awk '{print $NF}' | head -n 1)
  [ -z "$fwmark" ] && exit_error "Mandatory PREROUTING rule for IPSET name $IPSET_NAME does not exist."
  mark=$(echo "$fwmark" | cut -c 3-6) # Extract the 4-character mark (bitmask) from the fwmark.

  case "$mark" in # Define interface based on the extracted mark.
    a000) vpnc_iface="wgc1" ;;
    b000) vpnc_iface="wgc2" ;;
    c000) vpnc_iface="wgc3" ;;
    d000) vpnc_iface="wgc4" ;;
    e000) vpnc_iface="wgc5" ;;
    1000) vpnc_iface="tun11" ;;
    2000) vpnc_iface="tun12" ;;
    4000) vpnc_iface="tun13" ;;
    7000) vpnc_iface="tun14" ;;
    3000) vpnc_iface="tun15" ;;
    *) exit_error "$1 should be 1-5 for WireGuard Client or 11-15 for OpenVPN Client" ;;
  esac

  if [ -z "$DEL_FLAG" ]; then
    echo "$PROTO_RULES" | while read -r PROTO_RULE; do
      ipt nat POSTROUTING "-s $vpns_sub -o $vpnc_iface $PROTO_RULE -j MASQUERADE"
      ipt mangle PREROUTING "-i $vpns_iface -m set --match-set $IPSET_NAME dst $PROTO_RULE -j MARK --set-mark $fwmark"
    done
  else # 'del' or 'del=force' option specified
    iptables -nvL PREROUTING -t mangle --line | grep "$vpns_iface" | grep "$IPSET_NAME" | grep "match-set" | awk '{print $1}' | sort -nr | while read -r chain_num; do
      iptables -t mangle -D PREROUTING "$chain_num" && log_info "Deleted PREROUTING Chain $chain_num for IPSET List $IPSET_NAME on $vpns_iface"
    done

    iptables -nvL POSTROUTING -t nat --line | grep "${vpns_sub%%/*}" | grep "$vpnc_iface" | awk '{print $1}' | sort -nr | while read -r chain_num; do
      iptables -t nat -D POSTROUTING "$chain_num" && log_info "Deleted POSTROUTING Chain $chain_num for IPSET List $IPSET_NAME on $vpnc_iface"
    done
  fi
}

server_param() {
  vpns_id=$(get_param "server" "$@")
  echo "1 2 3 all" | grep -qw "$vpns_id" || exit_error \
    "Invalid server '$vpns_id' specified. Should be 1 or 2 for OpenVPN, 3 for WireGuard or 'all'."

  if [ "$(echo "$@" | grep -c 'client=')" -gt 0 ]; then
    client=$(get_param "client" "$@")
    echo "11 12 13 14 15" | grep -qw "$client" || exit_error \
      "Invalid client '$client' specified. Should be 11-15 for OpenVPN client."

    if [ "$vpns_id" = "all" ]; then
      for vpns_id in 1 2 3; do
        vpns_to_vpnc "$vpns_id" "$client"
      done
    else
      vpns_to_vpnc "$vpns_id" "$client"
    fi
  fi

  if [ "$(echo "$@" | grep -c 'ipset_name=')" -ge 1 ]; then
    IPSET_NAME=$(get_param "ipset_name" "$@" | tr ',' ' ')

    for IPSET_NAME in $IPSET_NAME; do
      if [ -n "$IPSET_NAME" ]; then # Check if IPSET list exists
        if [ "$(ipset list -n "$IPSET_NAME" 2>/dev/null)" != "$IPSET_NAME" ]; then
          exit_error "IPSET name $IPSET_NAME does not exist."
        fi
      fi

      if [ "$vpns_id" = "all" ]; then
        for vpns_id in 1 2 3; do
          vpns_to_ipset "$vpns_id"
        done
      else
        vpns_to_ipset "$vpns_id"
      fi
    done

    script_entry="sh $SCR_DIR/$SCR_NAME.sh $1 $2 $PROTO_PARAM"
    if [ -z "$DEL_FLAG" ]; then
      add_entry_to_file "$NAT_START" "$script_entry"
    else
      delete_entry_from_file "$NAT_START" "$1 $2"
    fi
  fi
}

del_ipset_list() { # TODO: Simplify logic
  log_info "Checking files for entry..."
  for file in "$NAT_START" "$WG_START" "$WAN_EVENT" "$DNSMASQ_CONF" "$DIR/$IPSET_NAME"; do
    delete_entry_from_file "$file" "$IPSET_NAME"
  done

  log_info "Checking PREROUTING & POSTROUTING iptables rules..."
  for vpns_iface in tun21 tun22 wgs1; do
    fw_rule="$(iptables -nvL PREROUTING -t mangle --line | grep "$vpns_iface" | grep "$IPSET_NAME" | grep "match-set")"
    if [ -n "$fw_rule" ]; then
      vpns_to_ipset "$vpns_iface"
    fi
  done

  # Extract the last field (fwmark) from the iptables PREROUTING rule that matches the IPSET name.
  fwmark=$(iptables -nvL PREROUTING -t mangle --line | grep -w "$IPSET_NAME" | awk '{print $NF}' | head -n 1)

  if [ -n "$fwmark" ]; then
    iptables -nvL PREROUTING -t mangle --line |
      grep "br0" | grep "$IPSET_NAME" | grep "match-set" | awk '{print $1, $12}' | sort -nr |
      while read -r chain_num ipset_name; do
        iptables -t mangle -D PREROUTING "$chain_num" # Delete PREROUTING Rules for Normal IPSET routing
        log_info "Deleted PREROUTING Chain $chain_num for IPSET List $ipset_name"
      done

    # Delete the fwmark priority if no IPSET lists are using it
    if ! iptables -nvL PREROUTING -t mangle --line | grep -m 1 -w "$fwmark" >/dev/null; then
      ip rule del fwmark "$fwmark" 2>/dev/null && log_info "Deleted ip rule for fwmark $fwmark"
    fi
  fi

  log_info "Checking if IPSET list $IPSET_NAME exists..."
  if [ "$(ipset list -n "$IPSET_NAME" 2>/dev/null)" = "$IPSET_NAME" ]; then
    if ipset destroy "$IPSET_NAME"; then
      log_info "Deleted IPSET $IPSET_NAME"
    else
      exit_error "Can't delete IPSET $IPSET_NAME"
    fi
  fi

  log_info "Checking if IPSET backup file exists..."
  if [ -f "$DIR/$IPSET_NAME" ]; then
    if [ "$DEL_FLAG" = "del" ]; then
      non_empty_lines=$(grep -cvE '^\s*$' "$DIR/$IPSET_NAME")
      while true; do
        if [ "$non_empty_lines" -eq 0 ]; then
          printf "NOTICE! The backup '%s' is empty. Delete it? [Y/n]:" "$DIR/$IPSET_NAME" && default="y"
        else
          printf "WARNING! The backup '%s' is NOT empty. Delete it? [y/N]:" "$DIR/$IPSET_NAME" && default="n"
        fi
        read -r option
        case "${option:-$default}" in
          [yY][eE][sS] | [yY]) rm "$DIR/$IPSET_NAME" && log_info "Deleted file '$DIR/$IPSET_NAME'" && break ;;
          [nN][oO] | [nN]) break ;;
          *) echo "Invalid option. File not deleted." ;;
        esac
      done
    elif [ "$DEL_FLAG" = "FORCE" ]; then
      rm "$DIR/$IPSET_NAME" && log_info "Deleted file '$DIR/$IPSET_NAME'"
    fi
  fi
}

update_dnsmasq_conf() {
  domains="$1"

  [ -s "$DNSMASQ_CONF" ] && sed -i "\|ipset=.*$IPSET_NAME|d" "$DNSMASQ_CONF"
  echo "ipset=/$domains/$IPSET_NAME" >>"$DNSMASQ_CONF" && log_info "Add '$domains' to $DNSMASQ_CONF"
  service restart_dnsmasq >/dev/null 2>&1 && log_info "Restart dnsmasq service"
}

dnsmasq_param() {
  dnsmasq_file=$(get_param "dnsmasq_file" "$@")
  domains=$(get_param "dnsmasq" "$@" | tr ',' '/' | sed 's|/$||')

  [ -z "$domains" ] && [ -s "$dnsmasq_file" ] && domains=$(tr '\n' '/' <"$dnsmasq_file" | sed 's|/$||')
  [ -z "$domains" ] && exit_error "No 'dnsmasq' parameter or valid non-empty 'dnsmasq_file' provided."

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

fetch_asn_to_ipset() {
  asn="$1"
  file="$DIR/$asn.json"
  url="https://api.bgpview.io/asn/$asn/prefixes" # https://stat.ripe.net/data/as-routing-consistency/data.json?resource=

  log_info "Fetching data from: $url"
  curl --retry 3 --connect-timeout 3 -sfL -o "$file" "$url" || exit_error "Fetching failed."
  tr -d "\\" <"$file" |
    grep -oE "$CIDR_REGEX" |
    sort -ut '.' -k1,1n -k2,2n -k3,3n -k4,4n -o "$DIR/$IPSET_NAME" && rm -f "$file"
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

ip_param() {
  ip_file=$(get_param "ip_file" "$@")
  ips=$(get_param "ip" "$@" | tr ',' ' ')

  [ -z "$ips" ] && [ -s "$ip_file" ] && ips=$(tr '\n' ' ' <"$ip_file")
  [ -z "$ips" ] && exit_error "'ip' parameter cannot be empty."

  for ip in $ips; do
    echo "$ip" | grep -oE "$IP_RE(/$IP_RE_PREFIX)?" || log_warning "$ip is an invalid IP or CIDR. Skipping entry." >&2
  done >>"$DIR/$IPSET_NAME"
  sort -ut '.' -k1,1n -k2,2n -k3,3n -k4,4n "$DIR/$IPSET_NAME" -o "$DIR/$IPSET_NAME"
}

parse_proto() {
  proto=$(get_param "proto" "$@")

  if [ -n "$proto" ]; then
    for p in $proto; do # Split proto parameter into individual entries
      protocol=$(echo "$p" | cut -d':' -f1 | awk '{print tolower($0)}')
      ports=$(echo "$p" | cut -sd':' -f2)

      protocols=$(awk '{print tolower($1)}' /etc/protocols | tr '\n' ' ') # Validate protocol
      echo "$protocols" | grep -qw "$protocol" || exit_error "Unsupported protocol: '$protocol'."

      if [ -n "$ports" ]; then
        if ! echo "$ports" | grep -Eq '^[0-9]+(,[0-9]+)*$'; then
          exit_error "Ports should contain only digits and commas."
        elif ! echo "tcp udp udplite sctp dccp" | grep -qw "$protocol"; then
          exit_error "Protocol '$protocol' doesn't support ports. Only TCP, UDP, UDPLITE, SCTP, and DCCP accept ports."
        else
          port_list=$(echo "$ports" | tr ',' ' ')
          for port in $port_list; do
            if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
              exit_error "Invalid $port number. Must be between 1 and 65535."
            fi
          done
        fi
      fi

      if [ -n "$protocol" ] && [ -n "$ports" ]; then
        PROTO_RULES=$(printf "%s\n-p %s -m multiport --dports %s" "$PROTO_RULES" "$protocol" "$ports" | awk 'NF')
      elif [ -n "$protocol" ] && [ -z "$ports" ]; then
        PROTO_RULES=$(printf "%s\n-p %s" "$PROTO_RULES" "$protocol" | awk 'NF')
      fi
    done
    PROTO_PARAM="proto=\"$proto\""
  fi
}

parse_src_option() {
  src=$(get_param "src" "$@")
  src_range=$(get_param "src_range" "$@")

  if [ -n "$src" ]; then
    echo "$src" | grep -qE "^$IP_RE$" || exit_error "'src=$src' not a valid IP address."

    SRC_RULE="--src $src"
    SRC_PARAM="src=$src"
  fi

  if [ -n "$src_range" ]; then
    echo "$src_range" | grep -qE "^$IP_RE-$IP_RE$" || exit_error "'src_range=$src_range' not a valid IP range."

    ip_start=$(echo "$src_range" | awk -F '[-.]' '{print ($1 * 256^3) + ($2 * 256^2) + ($3 * 256) + $4}')
    ip_end=$(echo "$src_range" | awk -F '[-.]' '{print ($5 * 256^3) + ($6 * 256^2) + ($7 * 256) + $8}')
    [ "$ip_start" -gt "$ip_end" ] && exit_error "'src_range=$src_range' is not valid, start IP greater than end IP."

    SRC_RULE="--src-range $src_range"
    SRC_PARAM="src_range=$src_range"
  fi
}

check_files_entry() {
  script_entry="sh $SCR_DIR/$SCR_NAME.sh"

  if [ -n "$SRC_IFACE" ] && [ -n "$DST_IFACE" ]; then
    script_entry="$script_entry $SRC_IFACE $DST_IFACE $IPSET_NAME ${SRC_PARAM:-} ${PROTO_PARAM:-}"
  else
    script_entry="$script_entry ipset_name=$IPSET_NAME"
  fi

  [ "$DIR" != "/opt/tmp" ] && script_entry="$script_entry dir=$DIR"

  add_entry_to_file "$NAT_START" "$script_entry"
}

conf_route_tags() {
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

set_wg_rp_filter() {
  if [ "${ROUTE_TABLE#wgc}" != "$ROUTE_TABLE" ]; then # Check if $ROUTE_TABLE starts with 'wgc'
    # Here we set the reverse path filtering mode for 'wgc*' interface.
    # This setting is only for WireGuard. OpenVPN on Asuswrt-Merlin defaults to '0'.
    # 0 - Disables reverse path filtering, accepting all packets without verifying the source route.
    # 1 - Strict mode, accepting packets only if the route to the source IP matches the incoming interface.
    # 2 - Loose mode, allowing packets to be accepted on any interface as long as a route to the source IP exists.
    rp_filter="/proc/sys/net/ipv4/conf/$ROUTE_TABLE/rp_filter"

    if [ -f "$rp_filter" ]; then
      echo 2 >$rp_filter
    else
      log_info "rp_filter file not found, VPN server '$ROUTE_TABLE' likely disabled."
    fi

    for file in "$NAT_START" "$WG_START" "$WAN_EVENT"; do
      add_entry_to_file "$file" "echo 2 >$rp_filter" # Ensure 'rp_filter' is set across restart and reboot.
    done
  fi
}

set_ipset() {
  if ! ipset list -n "$IPSET_NAME" >/dev/null 2>&1; then
    if echo "$@" | grep -qE '\s(dnsmasq|autoscan)' || grep -q "ipset=.*$IPSET_NAME" "$DNSMASQ_CONF"; then
      ipset create "$IPSET_NAME" hash:net family inet hashsize 1024 maxelem 2048 timeout 43200 # 12 hours
    else
      ipset create "$IPSET_NAME" hash:net family inet hashsize 16384 maxelem 32768
      touch "$DIR/$IPSET_NAME" && log_info "Created bak file for IPSET: $DIR/$IPSET_NAME"
    fi
    log_info "Created IPSET: $IPSET_NAME"
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

set_iprule_ipt() {
  if ! ip rule | grep -q "$TAG_MARK"; then
    ip rule add from 0/0 fwmark "$TAG_MARK" table "$ROUTE_TABLE" prio "$priority" && ip route flush cache
    log_info "Created ip rule for table $ROUTE_TABLE with fwmark $TAG_MARK"
  fi

  echo "$PROTO_RULES" | while read -r PROTO_RULE; do
    ipt mangle PREROUTING "-i br0 $SRC_RULE -m set --match-set $IPSET_NAME dst $PROTO_RULE -j MARK --set-mark $TAG_MARK"
  done
}

#======================================== End of functions =========================================

if [ "$1" = "help" ] || [ "$1" = "-h" ]; then
  show_help && exit 0
fi

check_entware 120 || exit_error "Entware not ready. Unable to access ipset save/restore location"
log_info "Starting Script Execution $*"
check_lock "$@"

DIR=$(case "$@" in                # Check if user specified 'dir=' parameter
  *dir=*) get_param "dir" "$@" ;; # Mount point/directory for backups
  *) echo "/opt/tmp" ;;
esac)

DEL_FLAG=$(case "$@" in
  *del=force*) echo "FORCE" ;;
  *del*) echo "del" ;;
esac)

parse_proto "$@" # Set PROTO_RULES & PROTO_PARAM

if [ "${1%%=*}" = "server" ]; then # Process 'server=' parameter
  if [ "${2%%=*}" != "client" ] && [ "${2%%=*}" != "ipset_name" ]; then
    exit_error "Second parameter must be 'client=' or 'ipset_name='."
  fi
  if [ "${2%%=*}" = "ipset_name" ]; then
    IPSET_NAME=$(get_param "ipset_name" "$@")
    [ -z "$IPSET_NAME" ] && exit_error "'ipset_name' parameter cannot be empty."
  fi
  server_param "$@"
  exit_routine
fi

if [ "${1%%=*}" = "ipset_name" ]; then # Only create IPSET without routing
  IPSET_NAME=$(get_param "ipset_name" "$@")
  [ -z "$IPSET_NAME" ] && exit_error "'ipset_name' parameter cannot be empty."
elif echo "$1" | grep -Eq '^[0-5]|1[1-5]$'; then # Create IPSET and set SRC_IFACE and DST_IFACE with routing
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
  parse_src_option "$@" # Set SRC_RULE & SRC_PARAM
else
  exit_error "First parameter must be 'server=', 'ipset_name=', 0 (WAN), 1-5 (WireGuard), or 11-15 (OpenVPN)."
fi

case "$@" in
  *del*) del_ipset_list && exit_routine ;;
  *dnsmasq=* | *dnsmasq_file=*) dnsmasq_param "$@" ;;
  *autoscan=*) harvest_dnsmasq_queries "$@" ;;
  *asnum=*) asnum_param "$@" ;;
  *aws_region=*) aws_param "$@" ;;
  *ip=* | *ip_file=*) ip_param "$@" ;;
  *) ;;
esac

if [ -n "$SRC_IFACE" ] && [ -n "$DST_IFACE" ]; then
  conf_route_tags
  set_wg_rp_filter
  set_ipset "$@"
  set_iprule_ipt
  check_files_entry
elif [ "${1%%=*}" = "ipset_name" ]; then
  set_ipset
  check_files_entry
fi

exit_routine
