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
# Date: 27-September-2024
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
#_____________________________________________________________________________________________________________
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
# TODO: Fix Server-to-client routing functionality for WireGuard clients in VPN_Server_to_VPN_Client() function.
#
#_____________________________________________________________________________________________________________
#
# VPN Server to existing LAN routing rules for one or more IPSET lists
#
# x3mRouting {'server='1|2|3|all} {'ipset_name='IPSET[,IPSET]...} ['protocol=udp|tcp'] ['port=port] ['ports=port[,port]...] ['del'] ['del=force']
#_____________________________________________________________________________________________________________

# Print between line beginning with '#__' to first blank line inclusive (source: Martineau)
show_help() {
  awk '/^#__/{f=1} f{print; if (!NF) exit}' "$0" | more
}

# Need assistance!???
if [ "$1" = "help" ] || [ "$1" = "-h" ]; then
  show_help
  exit 0
fi

VPN_IDS="1 2 3 4 5 11 12 13 14 15"
COLOR_RED='\033[0;31m'
COLOR_WHITE='\033[0m'
COLOR_GREEN='\033[0;32m'
IP_RE='([1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\.(0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])){3}'
IP_RE_PREFIX='([1-9]?[12][0-9]|3[0-2])'
CIDR_REGEX="$IP_RE/$IP_RE_PREFIX"

SCR_NAME=$(basename "$0" | sed 's/.sh//')     # Script name without .sh
SCR_DIR="$(cd "$(dirname "$0")" && pwd)"      # Script directory (absolute path)
LOCK_FILE="/tmp/x3mRouting.lock"              # Lock file to prevent multiple instances
NAT_START="/jffs/scripts/nat-start"           # NAT initialization (e.g., firewall restart)
WG_START="/jffs/scripts/wgclient-start"       # WireGuard client startup
WAN_EVENT="/jffs/scripts/wan-event"           # WAN events (e.g., IP changes)
DNSMASQ_CONF="/jffs/configs/dnsmasq.conf.add" # dnsmasq configuration file

log_info() {
  logger -st "${SCR_NAME}[$$]" "$*"
}

log_warning() {
  log_info "WARNING! $*"
}

exit_error() {
  if [ "$LOCK_ACTIVE" = "true" ]; then release_lock; fi
  log_info "ERROR! $*"
  exit 1
}

exit_routine() {
  if [ "$LOCK_ACTIVE" = "true" ]; then release_lock; fi
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
        log_info "x3mRouting lock file in use by PID $pid - wait time $(((max_tries - tries - 1) * 3)) secs left"
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

chk_entware() {
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

# Function to add an ipt_entry to a file, creating the file with shebang if it doesn't exist
add_entry_to_file() {
  file="$1"
  ipt_entry="$2"

  if [ ! -f "$file" ]; then
    echo '#!/bin/sh' >"$file" && chmod 755 "$file"
  fi
  if ! grep -Fq "$ipt_entry" "$file"; then
    echo "$ipt_entry # x3mRouting for ipset name: $IPSET_NAME" >>"$file"
    log_info "$ipt_entry added to $file"
  fi
}

# Function to delete an ipt_entry from a file
delete_entry_from_file() {
  file="$1"
  pattern="$2"
  if [ -s "$file" ]; then
    sed -i "\~\b$pattern\b~d" "$file"
    log_info "Entry matching '$pattern' deleted from $file"
    [ "$file" = "$DNSMASQ_CONF" ] || Check_For_Shebang "$file"
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
      printf '\n\n%s\n' "$CLIENTX_FILE has $SHEBANG_COUNT shebang ipt_entry and $EMPTY_LINE_COUNT empty lines."
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

check_files_for_entries() {
  param=$1
  script_entry="sh $SCR_DIR/$SCR_NAME.sh"

  if echo "$param" | grep -q "Manual"; then
    if [ -n "$SRC_IFACE" ] && [ -n "$DST_IFACE" ]; then
      script_entry="$script_entry $SRC_IFACE $DST_IFACE $IPSET_NAME $PROTOCOL_PORT_PARAMS"
    else
      script_entry="$script_entry ipset_name=$IPSET_NAME"
    fi
  else
    if [ -n "$SRC_IFACE" ] && [ -n "$DST_IFACE" ]; then
      script_entry="$script_entry $SRC_IFACE $DST_IFACE $IPSET_NAME $param $PROTOCOL_PORT_PARAMS"
    else
      script_entry="$script_entry ipset_name=$IPSET_NAME $param"
    fi
  fi

  if [ "$DIR" != "/opt/tmp" ]; then
    if ! echo "$@" | grep -q 'asnum='; then
      script_entry="$script_entry dir=$DIR"
    fi
  fi

  add_entry_to_file "$NAT_START" "$script_entry"

  if [ -n "$SRC_IFACE" ] && [ -n "$DST_IFACE" ]; then
    vpnid=$([ "$SRC_IFACE" = 0 ] && echo "$DST_IFACE" || echo "$SRC_IFACE")

    ipt_del_entry="iptables -t mangle -D PREROUTING -i br0 -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK 2>/dev/null"
    ipt_add_entry="iptables -t mangle -A PREROUTING -i br0 -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK"

    for ipt_entry in "$ipt_del_entry" "$ipt_add_entry"; do
      add_entry_to_file "$SCR_DIR/vpnclient${vpnid}-route-up" "$ipt_entry"
    done
    add_entry_to_file "$SCR_DIR/vpnclient${vpnid}-route-pre-down" "$ipt_del_entry"
  fi
}

# Set global TAG_MARK, ROUTE_TABLE, TARGET_DESC, and priority
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
    for file in "$NAT_START" "$WG_START" "$WAN_EVENT"; do
      add_entry_to_file "$file" "$rp_filter"
    done
  fi
}

parse_protocol_and_ports() {
  args="$*"

  PROTOCOL_PORT_RULE=""
  PROTOCOL_PORT_PARAMS=""

  if echo "$args" | grep -Fq "protocol="; then
    protocols=$(awk '{print tolower($1)}' /etc/protocols | grep -v '^#' | tr '\n' ' ')
    protocol=$(echo "$args" | sed -n 's/.*protocol=\([^ ]*\).*/\1/p' | awk '{print tolower($0)}')
    if ! echo "$protocols" | grep -qw "$protocol"; then
      exit_error "Unsupported protocol: '$protocol'."
    fi

    if echo "$args" | grep -Fq "port="; then
      port=$(get_param "port" "$args")
      if echo "$port" | grep -Eq '^[0-9]+$'; then
        if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
          exit_error "Port number in 'port=' must be between 1 and 65535."
        fi
      else
        exit_error "The 'port=' parameter should contain only digits."
      fi
    fi

    if echo "$args" | grep -Fq "ports="; then
      ports=$(get_param "ports" "$args")
      if echo "$ports" | grep -Eq '^[0-9]+(,[0-9]+)*$'; then
        port_list=$(echo "$ports" | tr ',' ' ')
        for port in $port_list; do
          if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
            exit_error "Port numbers in 'ports=' must be between 1 and 65535."
          fi
        done
      else
        exit_error "The 'ports=' parameter should contain only digits and commas."
      fi
    fi

    if { [ -n "$port" ] || [ -n "$ports" ]; } && ! echo "tcp udp udplite sctp dccp" | grep -qw "$protocol"; then
      exit_error "Unsupported protocol '$protocol' for port parameter. Accept only TCP, UDP, UDPLITE, SCTP, DCCP."
    elif [ -n "$ports" ]; then
      PROTOCOL_PORT_RULE="-p $protocol -m multiport --dports $ports"
      PROTOCOL_PORT_PARAMS="protocol=$protocol ports=$ports"
    elif [ -n "$port" ]; then
      PROTOCOL_PORT_RULE="-p $protocol --dport $port"
      PROTOCOL_PORT_PARAMS="protocol=$protocol port=$port"
    else
      PROTOCOL_PORT_RULE="-p $protocol"
      PROTOCOL_PORT_PARAMS="protocol=$protocol"
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

server_param() { # Special processing for VPN Server
  server=$(get_param "server" "$@")
  case "$server" in
    1 | 2 | 3 | all) ;;
    *) exit_error "Invalid Server '$server' specified." ;;
  esac

  if [ "$(echo "$@" | grep -c 'client=')" -eq 0 ] && [ "$(echo "$@" | grep -c 'ipset_name=')" -eq 0 ]; then
    exit_error "Expecting second parameter to be either 'client=' or 'ipset_name='"
  fi

  parse_protocol_and_ports "$@" # Sets PROTOCOL_PORT_RULE & PROTOCOL_PORT_PARAMS

  ### Process server when 'client=' specified
  if [ "$(echo "$@" | grep -c 'client=')" -gt 0 ]; then
    VPN_CLIENT_INSTANCE=$(get_param "client" "$@")
    case "$VPN_CLIENT_INSTANCE" in
      [1-5]) IFACE="wgc${VPN_CLIENT_INSTANCE}" ;;
      1[1-5]) IFACE="tun${VPN_CLIENT_INSTANCE}" ;;
      *) exit_error "ERROR 'client=$VPN_CLIENT_INSTANCE' reference should be 1-5 for WireGuard Client or 11-15 for OpenVPN Client" ;;
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
    done

    for IPSET_NAME in $IPSET_NAME; do
      define_iface "$IPSET_NAME"

      case "$IFACE" in
        wgc[1-5]) VPN_CLIENT_INSTANCE="${IFACE#wgc}" ;;
        tun1[1-5]) VPN_CLIENT_INSTANCE="${IFACE#tun}" ;;
      esac

      if [ "$server" = "all" ]; then
        for server in 1 2 3; do
          vpn_server_to_ipset "$server"
        done
      else
        vpn_server_to_ipset "$server"
      fi
    done
    # nat-start File
    script_entry="sh $SCR_DIR/x3mRouting.sh $1 $2 $PROTOCOL_PORT_PARAMS"
    if [ "$(echo "$@" | grep -cw 'del')" -eq 0 ] || [ "$(echo "$@" | grep -cw 'del=force')" -eq 0 ]; then
      add_entry_to_file "$NAT_START" "$script_entry"
    else
      delete_entry_from_file "$NAT_START" "$1 $2"
    fi
    exit_routine
  fi
}

VPN_Server_to_VPN_Client() { # Work only with OpenVPN
  vpn_server_instance=$1
  script_entry="sh $SCRIPT_DIR/x3mRouting.sh server=$vpn_server_instance client=$VPN_CLIENT_INSTANCE"
  vpn_server_subnet="$(nvram get vpn_server"${vpn_server_instance}"_sn)/24"
  IPT_DEL_ENTRY="iptables -t nat -D POSTROUTING -s \"\$(nvram get vpn_server${vpn_server_instance}_sn)\"/24 -o $IFACE $PROTOCOL_PORT_PARAMS -j MASQUERADE 2>/dev/null"
  IPT_ADD_ENTRY="iptables -t nat -A POSTROUTING -s \"\$(nvram get vpn_server${vpn_server_instance}_sn)\"/24 -o $IFACE $PROTOCOL_PORT_PARAMS -j MASQUERADE"
  vpnc_up_file="$SCRIPT_DIR/vpnclient${VPN_CLIENT_INSTANCE}-route-up"
  vpnc_down_file="$SCRIPT_DIR/vpnclient${VPN_CLIENT_INSTANCE}-route-pre-down"
  POLICY_RULE_WITHOUT_NAME="${vpn_server_subnet}>>VPN"
  POLICY_RULE="<VPN Server ${vpn_server_instance}>${vpn_server_subnet}>>VPN"

  VPN_IP_LIST="$(nvram get vpn_client"$VPN_CLIENT_INSTANCE"_clientlist)"
  for n in $VPN_IDS; do
    VPN_IP_LIST="${VPN_IP_LIST}$(nvram get vpn_client"$VPN_CLIENT_INSTANCE"_clientlist"${n}")"
  done

  if [ -z "$DEL_FLAG" ]; then # add ipt_entry if DEL_FLAG is null
    eval "$IPT_DEL_ENTRY"
    eval "$IPT_ADD_ENTRY"

    iptables -t nat -D POSTROUTING -s "$vpn_server_subnet" -o "$IFACE" $PROTOCOL_PORT_PARAMS -j MASQUERADE 2>/dev/null
    iptables -t nat -A POSTROUTING -s "$vpn_server_subnet" -o "$IFACE" $PROTOCOL_PORT_PARAMS -j MASQUERADE

    add_entry_to_file "$vpnc_up_file" "$IPT_DEL_ENTRY"
    add_entry_to_file "$vpnc_up_file" "$IPT_ADD_ENTRY"
    add_entry_to_file "$vpnc_down_file" "$IPT_DEL_ENTRY"
    add_entry_to_file "$NAT_START" "$script_entry"

    # Add nvram ipt_entry to vpn_client"${VPN_CLIENT_INSTANCE}"_clientlist
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
    else # if the VPN Server ipt_entry exists in nvram using the 'vpnserverX' name created by the prior version, convert it to the new name
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

    # vpnserverX-up file
    if [ -s "$vpnc_up_file" ]; then #file exists
      # POSTROUTING
      CMD="awk '\$5 == \"POSTROUTING\" && \$9 == \"vpn_server${vpn_server_instance}_sn)\\\"/24\"  && \$11 == \"$IFACE\" && \$13 == \"MASQUERADE\" {next} {print \$0}' \"$vpnc_up_file\" > \"$vpnc_up_file.tmp\" && mv \"$vpnc_up_file.tmp\" \"$vpnc_up_file\""
      eval "$CMD"
      logger -st "($(basename "$0"))" $$ "iptables ipt_entry for VPN Client ${VPN_CLIENT_INSTANCE} deleted from $vpnc_up_file"
      Check_For_Shebang "$vpnc_up_file"
    fi

    # vpnserverX-down file
    if [ -s "$vpnc_down_file" ]; then #file exists
      # POSTROUTING
      CMD="awk '\$5 == \"POSTROUTING\" && \$9 == \"vpn_server${vpn_server_instance}_sn)\\\"/24\"  && \$11 == \"$IFACE\" && \$13 == \"MASQUERADE\" {next} {print \$0}' \"$vpnc_down_file\" > \"$vpnc_down_file.tmp\" && mv \"$vpnc_down_file.tmp\" \"$vpnc_down_file\""
      eval "$CMD"
      logger -st "($(basename "$0"))" $$ "iptables ipt_entry deleted VPN Client ${VPN_CLIENT_INSTANCE} from $vpnc_down_file"
      Check_For_Shebang "$vpnc_down_file"
    fi

    # nat-start File
    if [ -s "$NAT_START" ]; then
      sed "/server=$vpn_server_instance client=$VPN_CLIENT_INSTANCE/d" "$NAT_START" >"$NAT_START.tmp" && mv "$NAT_START.tmp" "$NAT_START"
      logger -t "($(basename "$0"))" $$ "$script_entry ipt_entry deleted from $NAT_START"
      Check_For_Shebang "$NAT_START"
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

  # set permissions for each file
  [ -s "$vpnc_up_file" ] && chmod 755 "$vpnc_up_file"
  [ -s "$vpnc_down_file" ] && chmod 755 "$vpnc_down_file"
  [ -s "$NAT_START" ] && chmod 755 "$NAT_START"

}

vpn_server_to_ipset() {
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

  # POSTROUTING CHAIN
  ipt_post_del_entry="iptables -t nat -D POSTROUTING -s $vpn_server_subnet -o $IFACE $PROTOCOL_PORT_RULE -j MASQUERADE 2>/dev/null"
  ipt_post_add_entry="iptables -t nat -A POSTROUTING -s $vpn_server_subnet -o $IFACE $PROTOCOL_PORT_RULE -j MASQUERADE"

  # PREROUTING CHAIN
  ipt_pre_del_entry="iptables -t mangle -D PREROUTING -i $vpn_server_tun -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK 2>/dev/null"
  ipt_pre_add_entry="iptables -t mangle -A PREROUTING -i $vpn_server_tun -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK"

  # VPN Client Up/Down files
  vpnc_up_file="$SCR_DIR/vpnclient${VPN_CLIENT_INSTANCE}-route-up"
  vpnc_down_file="$SCR_DIR/vpnclient${VPN_CLIENT_INSTANCE}-route-pre-down"

  if [ -z "$DEL_FLAG" ]; then
    iptables -t nat -D POSTROUTING -s "$vpn_server_subnet" -o "$IFACE" "$PROTOCOL_PORT_RULE" -j MASQUERADE 2>/dev/null
    iptables -t nat -A POSTROUTING -s "$vpn_server_subnet" -o "$IFACE" $PROTOCOL_PORT_RULE -j MASQUERADE
    iptables -t mangle -D PREROUTING -i $vpn_server_tun -m set --match-set "$IPSET_NAME" dst $PROTOCOL_PORT_RULE -j MARK --set-mark "$TAG_MARK" 2>/dev/null
    iptables -t mangle -A PREROUTING -i $vpn_server_tun -m set --match-set "$IPSET_NAME" dst $PROTOCOL_PORT_RULE -j MARK --set-mark "$TAG_MARK"

    for ipt_entry in "$ipt_post_del_entry" "$ipt_post_add_entry" "$ipt_pre_del_entry" "$ipt_pre_add_entry"; do
      add_entry_to_file "$vpnc_up_file" "$ipt_entry"
    done

    for ipt_entry in "$ipt_post_del_entry" "$ipt_pre_del_entry"; do
      add_entry_to_file "$vpnc_down_file" "$ipt_entry"
    done
  else # 'del' or 'del=force' option specified.
    if [ -n "$PROTOCOL_PORT_RULE" ]; then
      iptables -t mangle -D PREROUTING -i $vpn_server_tun -m set --match-set "$IPSET_NAME" dst $PROTOCOL_PORT_RULE -j MARK --set-mark "$TAG_MARK" 2>/dev/null
      iptables -t nat -D POSTROUTING -s "$vpn_server_subnet" -o "$IFACE" $PROTOCOL_PORT_RULE -j MASQUERADE 2>/dev/null
    else
      iptables -nvL PREROUTING -t mangle --line | grep $vpn_server_tun | grep "$IPSET_NAME" | grep "match-set" | awk '{print $1}' | sort -nr | while read -r chain_num; do
        iptables -t mangle -D PREROUTING "$chain_num" && log_info "Deleted PREROUTING Chain $chain_num for IPSET List $IPSET_NAME on $vpn_server_tun"
      done

      iptables -nvL POSTROUTING -t nat --line | grep "${vpn_server_subnet%%/*}" | grep "$IFACE" | awk '{print $1}' | sort -nr | while read -r chain_num; do
        iptables -t nat -D POSTROUTING "$chain_num" && log_info "Deleted POSTROUTING Chain $chain_num for IPSET List $IPSET_NAME on $IFACE"
      done
    fi

    for vpnc_file in "$vpnc_up_file" "$vpnc_down_file"; do
      for ipt_entry in "PREROUTING.*$vpn_server_tun.*$IPSET_NAME" "POSTROUTING.*$vpn_server_subnet.*$IFACE.*MASQUERADE"; do
        delete_entry_from_file "$vpnc_file" "$ipt_entry"
      done
    done
  fi
}

process_src_option() {
  src=$(echo "$@" | sed -n "s/^.*src=//p" | awk '{print $1}')
  src_range=$(echo "$@" | sed -n "s/^.*src_range=//p" | awk '{print $1}')

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
      dnsmasq_param "$@"
      break
    fi
    # Check for 'autoscan=' parm
    if [ "$(echo "$@" | grep -c 'autoscan=')" -gt 0 ]; then
      Dnsmasq_Log_File
      Harvest_Domains "$@"
      break
    fi
    # check if 'asnum=' parm
    if [ "$(echo "$@" | grep -c 'asnum=')" -gt 0 ]; then
      asnum_param "$@"
      break
    fi
    # check if 'aws_region=' parm
    if [ "$(echo "$@" | grep -c 'aws_region=')" -gt 0 ]; then
      aws_region_param "$@"
      break
    fi
    # Manual Method
    if [ "$X3M_METHOD" = "Manual" ]; then
      manual_method "$@"
      break
    fi
  done

  # Manual Method to create ipset list if IP address specified
  if [ -n "$src" ]; then
    if [ "$X3M_METHOD" = "Manual" ]; then #
      script_entry="sh $SCR_DIR/x3mRouting.sh $SRC_IFACE $DST_IFACE $IPSET_NAME src=${src} $PROTOCOL_PORT_PARAMS"
      [ "$DIR" != "/opt/tmp" ] && script_entry="sh $SCR_DIR/x3mRouting.sh $SRC_IFACE $DST_IFACE $IPSET_NAME src=${src} $PROTOCOL_PORT_PARAMS dir=${DIR}"
      manual_method "$@"
    else
      script_entry="sh $SCR_DIR/x3mRouting.sh $SRC_IFACE $DST_IFACE $IPSET_NAME $X3M_METHOD src=${src} $PROTOCOL_PORT_PARAMS"
      [ "$DIR" != "/opt/tmp" ] && script_entry="sh $SCR_DIR/x3mRouting.sh $SRC_IFACE $DST_IFACE $IPSET_NAME $X3M_METHOD src=${src} $PROTOCOL_PORT_PARAMS dir=${DIR}"
    fi
    IPT_DEL_ENTRY="iptables -t mangle -D PREROUTING -i br0 --src $src -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK 2>/dev/null"
    IPT_ADD_ENTRY="iptables -t mangle -A PREROUTING -i br0 --src $src -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK"
    # Create routing rules
    eval "$IPT_DEL_ENTRY"
    eval "$IPT_ADD_ENTRY"
  fi

  if [ -n "$src_range" ]; then
    if [ "$X3M_METHOD" = "Manual" ]; then
      script_entry="sh $SCR_DIR/x3mRouting.sh $SRC_IFACE $DST_IFACE $IPSET_NAME src_range=${src_range} $PROTOCOL_PORT_PARAMS"
      [ "$DIR" != "/opt/tmp" ] && script_entry="sh $SCR_DIR/x3mRouting.sh $SRC_IFACE $DST_IFACE $IPSET_NAME src_range=${src_range} $PROTOCOL_PORT_PARAMS dir=${DIR}"
      manual_method "$@"
    else
      script_entry="sh $SCR_DIR/x3mRouting.sh $SRC_IFACE $DST_IFACE $IPSET_NAME $X3M_METHOD src_range=${src_range} $PROTOCOL_PORT_PARAMS"
      [ "$DIR" != "/opt/tmp" ] && script_entry="sh $SCR_DIR/x3mRouting.sh $SRC_IFACE $DST_IFACE $IPSET_NAME $X3M_METHOD src_range=${src_range} $PROTOCOL_PORT_PARAMS dir=${DIR}"
    fi
    IPT_DEL_ENTRY="iptables -t mangle -D PREROUTING -i br0 -m iprange --src-range $src_range -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK 2>/dev/null"
    IPT_ADD_ENTRY="iptables -t mangle -A PREROUTING -i br0 -m iprange --src-range $src_range -m set --match-set $IPSET_NAME dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK"
    # Create routing rules
    eval "$IPT_DEL_ENTRY"
    eval "$IPT_ADD_ENTRY"
  fi

  vpnid=$([ "$SRC_IFACE" = 0 ] && echo "$DST_IFACE" || echo "$SRC_IFACE")

  vpnc_up_file="$SCR_DIR/vpnclient${vpnid}-route-up"
  vpnc_down_file="$SCR_DIR/vpnclient${vpnid}-route-pre-down"

  for ipt_entry in "$IPT_DEL_ENTRY" "$IPT_ADD_ENTRY"; do
    add_entry_to_file "$vpnc_up_file" "$ipt_entry"
  done
  add_entry_to_file "$vpnc_down_file" "$IPT_DEL_ENTRY"
  add_entry_to_file "$NAT_START" "$script_entry"
}

dnsmasq_param() {
  dnsmasq_file=$(get_param "dnsmasq_file" "$@")
  dnsmasq_param=$(get_param "dnsmasq" "$@")

  if [ -s "$dnsmasq_file" ]; then
    domains=$(tr '\n' ',' <"$dnsmasq_file" | sed 's/,$//')
  elif [ -n "$dnsmasq_param" ]; then
    domains="$dnsmasq_param"
  else
    exit_error "No DNSMASQ parameter specified."
  fi

  [ ! -s "$DIR/$IPSET_NAME" ] && touch "$DIR/$IPSET_NAME"
  process_dnsmasq "$(echo "$domains" | sed 's/,$//' | tr ',' '/')"
}

process_dnsmasq() {
  dnsmasq_entry="ipset=/$1/$IPSET_NAME"

  [ -s "$DNSMASQ_CONF" ] && sed -i "\~ipset=.*$IPSET_NAME~d" "$DNSMASQ_CONF"                  # Delete old entry
  echo "$dnsmasq_entry" >>"$DNSMASQ_CONF" && log_info "Added $dnsmasq_entry to $DNSMASQ_CONF" # Add new entry
  service restart_dnsmasq >/dev/null 2>&1 && log_info "Restart dnsmasq service"

  create_ipset_list "DNSMASQ"

  [ -n "$(find "$DIR/$IPSET_NAME" -mtime +1 2>/dev/null)" ] && ipset save "$IPSET_NAME" >"$DIR/$IPSET_NAME"

  if ! cru l | grep -q "$IPSET_NAME"; then
    cru a "$IPSET_NAME" "0 2 * * * ipset save $IPSET_NAME > $DIR/$IPSET_NAME"
    log_info "CRON schedule created: At 2:00 AM every day, run ipset save $IPSET_NAME"
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
    exit_error "dnsmasq.log file NOT found!"
  fi
}

Harvest_Domains() {
  #  [ ! -s "$DIR/$IPSET_NAME" ] && touch "$DIR/$IPSET_NAME"
  scan_space_list=$(echo "$@" | sed -n "s/^.*autoscan=//p" | awk '{print $1}' | tr ',' ' ')

  true >/opt/tmp/domain_list

  for top_level_domain in $scan_space_list; do
    scan_list=$(grep "$top_level_domain" "/opt/var/log/dnsmasq.log" | grep query | awk '{print $(NF-2)}' | awk -F\. '{print $(NF-1) FS $NF}' | sort | uniq)
    [ -n "$scan_list" ] && echo "$scan_list" >>/opt/tmp/domain_list && log_info "Added $scan_list during autoscan"
  done

  domain_list=$(awk '{ print $1 }' "/opt/tmp/domain_list" | sort -u | tr '\n' '/' | sed -n 's/\/$/\n/p')
  NAT_ENTRY=$(echo "$domain_list" | sed 's|/|,|g')

  rm /opt/tmp/domain_list

  if [ -z "$domain_list" ]; then
    exit_error "No domain names were harvested from $DNSMASQ_LOG_FILE"
  else
    process_dnsmasq "$domain_list"
  fi
}

asnum_param() {
  asn=$(get_param "asnum" "$@" | tr ',' ' ')

  for asn in $asn; do
    prefix=$(printf '%-.2s' "$asn")
    number="$(echo "$asn" | sed 's/^AS//')"
    if [ "$prefix" = "AS" ]; then
      # Check for valid Number and skip if bad
      A=$(echo "$number" | grep -Eo '^[0-9]+$')
      if [ -z "$A" ]; then
        echo "Skipping invalid ASN: $number"
      else
        create_ipset_list "ASN"
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

  tr -d "\\" <"$file" | grep -oE "$CIDR_REGEX" | sort -ut '.' -k1,1n -k2,2n -k3,3n -k4,4n -o "$DIR/$IPSET_NAME"
  sed "s/^/add $IPSET_NAME /" "$DIR/$IPSET_NAME" | ipset restore -! && rm -f $file
}

aws_region_param() {
  aws_regions=$(get_param "aws_region" "$@" | tr ',' ' ' | awk '{print toupper($0)}')
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
    create_ipset_list "AWS"
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

  sed "s/^/add $IPSET_NAME /" "$DIR/$IPSET_NAME" | ipset restore -!
}

manual_method() {
  ips=$(get_param "ip" "$@" | tr ',' ' ')

  chk_entware 60 || exit_error "Entware not ready. Unable to access ipset save/restore location"

  [ -n "$ips" ] && for ip in $ips; do
    echo "$ip" | grep -oE "$IP_RE(/$IP_RE_PREFIX)?" || log_warning "$ip is an invalid IP or CIDR. Skipping entry." >&2
  done | sort -ut '.' -k1,1n -k2,2n -k3,3n -k4,4n -o "$DIR/$IPSET_NAME"

  if [ -s "$DIR/$IPSET_NAME" ]; then
    if grep -q "create" "$DIR/$IPSET_NAME"; then
      exit_error "$DIR/$IPSET_NAME save/restore file is in dnsmasq format. The Manual Method requires IPv4 format."
    fi
    create_ipset_list "MANUAL"
    sed "s/^/add $IPSET_NAME /" "$DIR/$IPSET_NAME" | ipset restore -!
  else
    exit_error "The save/restore file $DIR/$IPSET_NAME does not exist."
  fi
}

create_ipset_list() {
  method=$1

  chk_entware 120 || exit_error "Entware not ready. Unable to access ipset save/restore location"

  if ! ipset list -n "$IPSET_NAME" >/dev/null 2>&1; then            # does ipset list exist?
    if [ -s "$DIR/$IPSET_NAME" ] && [ "$method" = "DNSMASQ" ]; then # does ipset restore file exist and method = DNSMASQ
      ipset restore -! <"$DIR/$IPSET_NAME"
      log_info "IPSET restored: $IPSET_NAME from $DIR/$IPSET_NAME"
    else # method = ASN, MANUAL, AWS or no restore file, so create ipset list from scratch
      ipset create "$IPSET_NAME" hash:net family inet hashsize 1024 maxelem 65536
      log_info "IPSET created: $IPSET_NAME"
    fi
  fi
}

# Route IPSET to target WAN or VPN
create_routing_rules() {
  iptables -t mangle -D PREROUTING -i br0 -m set --match-set "$IPSET_NAME" dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK 2>/dev/null
  log_info "Selective routing rule via $ROUTE_TABLE deleted for $IPSET_NAME fwmark $TAG_MARK"
  iptables -t mangle -A PREROUTING -i br0 -m set --match-set "$IPSET_NAME" dst $PROTOCOL_PORT_RULE -j MARK --set-mark $TAG_MARK
  log_info "Selective routing rule via $ROUTE_TABLE created for $IPSET_NAME fwmark $TAG_MARK"
}

delete_Ipset_list() {
  if [ -s $DNSMASQ_CONF ]; then
    delete_entry_from_file "$DNSMASQ_CONF" "$IPSET_NAME"
    service restart_dnsmasq >/dev/null 2>&1 && log_info "Restart dnsmasq service"
  fi

  for file in "$NAT_START" "$WG_START" "$WAN_EVENT"; do
    delete_entry_from_file "$file" "$IPSET_NAME"
  done

  for vpnid in $VPN_IDS; do
    for suffix in "route-up" "route-pre-down"; do
      delete_entry_from_file "$SCR_DIR/vpnclient${vpnid}-$suffix" "$IPSET_NAME"
    done
  done

  #Check_Cron_Job
  log_info "Checking crontab..."
  if cru l | grep "$IPSET_NAME" 2>/dev/null; then
    cru d "$IPSET_NAME" "0 2 * * * ipset save $IPSET_NAME" 2>/dev/null
    log_info "CRON schedule deleted: #$IPSET_NAME# '0 2 * * * ipset save $IPSET_NAME'"
  fi

  # Delete PREROUTING Rule for VPN Server to IPSET & POSTROUTING Rule
  log_info "Checking POSTROUTING iptables rules..."
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
  fwmarks=$(iptables -nvL PREROUTING -t mangle --line | grep -w "$IPSET_NAME" | awk '{print $NF}' | cut -d '/' -f 1)

  if [ -n "$fwmarks" ]; then
    # Delete PREROUTING Rules for Normal IPSET routing
    iptables -nvL PREROUTING -t mangle --line | grep "br0" | grep "$IPSET_NAME" | grep "match-set" | awk '{print $1, $12}' | sort -nr | while read -r chain_num ipset_name; do
      iptables -t mangle -D PREROUTING "$chain_num" && log_info "Deleted PREROUTING Chain $chain_num for IPSET List $ipset_name"
    done
    # Delete the fwmark priority if no IPSET lists are using it
    for fwmark in $fwmarks; do
      if ! iptables -nvL PREROUTING -t mangle --line | grep -m 1 -w "$fwmark" >/dev/null; then
        ip rule del fwmark "$fwmark" 2>/dev/null && log_info "Deleted fwmark $fwmark"
      fi
    done
  fi

  # Destroy the IPSET list
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

log_info "Starting Script Execution" "$@"
check_lock "$@"

# Set DEL_FLAG if user specified 'del' or 'del=force' parameter
DEL_FLAG=$(case "$@" in
  *del=force*) echo "FORCE" ;;
  *del*) echo "del" ;;
esac)

# Check if user specified 'dir=' parameter
DIR=$(case "$@" in
  *dir=*asnum=*) echo "/opt/tmp" && log_info "ASN Method stores IPv4 in memory, ignoring 'dir=' parameter." ;;
  *dir=*) get_param "dir" "$@" ;; # Mount point/directory for backups
  *) echo "/opt/tmp" ;;
esac)

# Set SRC_IFACE and DST_IFACE unless 'server=' or 'ipset_name=' are used
if echo "$1" | grep -q '^server='; then
  if ! echo "$2" | grep -Eq '^(client=|ipset_name=)'; then
    exit_error "Second parameter must be 'client=' or 'ipset_name='."
  fi
elif echo "$1" | grep -Eq '^ipset_name='; then
  if [ -z "$2" ]; then
    exit_error "Second parameter must be 'dnsmasq=', 'dnsmasq_file=', 'autoscan=', 'asnum=', 'aws_region=', 'ip=' or 'dir='."
  elif echo "$2" | grep -Eq '^(src=|src_range=)'; then
    exit_error "'src=' or 'src_range=' cannot be used with 'ipset_name='."
  fi
elif echo "$1" | grep -Eq '^[0-5]|1[1-5]$'; then
  SRC_IFACE=$1
  if [ -n "$2" ]; then
    DST_IFACE=$2
    if { [ "$SRC_IFACE" = 0 ] && ! echo "$DST_IFACE" | grep -Eq '^[1-5]|1[1-5]$'; } ||
      { echo "$VPN_IDS" | grep -qw "$SRC_IFACE" && [ "$DST_IFACE" != 0 ]; }; then
      exit_error "Invalid source '$SRC_IFACE' and destination '$DST_IFACE' combination."
    fi

    if [ -z "$DEL_FLAG" ]; then
      set_routing_tags
      set_fwmark_ip_rule
    fi
  else
    exit_error "Second parameter must be 0 (WAN), 1-5 (WireGuard), or 11-15 (OpenVPN)."
  fi
else
  exit_error "First parameter must be 'server=', 'ipset_name=', 0 (WAN), 1-5 (WireGuard), or 11-15 (OpenVPN)."
fi

# Set and validate IPSET_NAME
IPSET_NAME=$(get_param "ipset_name" "$@")
if [ -z "$IPSET_NAME" ]; then
  if [ -n "$3" ]; then
    IPSET_NAME=$3
    if [ "${#IPSET_NAME}" -gt 31 ]; then
      exit_error "$IPSET_NAME is longer than 31 characters"
    elif echo "$IPSET_NAME" | grep -Eq '[^A-Za-z0-9_]'; then
      exit_error "$IPSET_NAME contains invalid characters, only A-Z, a-z, 0-9 and _ allowed"
    fi
  else
    exit_error "Missing arg3 IPSET_NAME"
  fi
fi

if [ -n "$DEL_FLAG" ] && ! echo "$1" | grep -q '^server='; then
  delete_Ipset_list
  exit_routine
fi

set_wg_rp_filter
parse_protocol_and_ports "$@" # Sets PROTOCOL_PORT_RULE & PROTOCOL_PORT_PARAMS

case "$*" in
  *server=*) server_param "$@" ;;
  *src=* | *src_range=*) # 'src=' or 'src_range=' params require exception processing
    process_src_option "$@"
    ;;
  *dnsmasq=*) # Check for 'dnsmasq' parm which indicates DNSMASQ method & make sure 'autoscan' parm is not passed!
    dnsmasq_param "$@"
    check_files_for_entries "dnsmasq=$(get_param "dnsmasq" "$@")"
    ;;
  *dnsmasq_file=*) # Check for 'dnsmasq_file' parm
    dnsmasq_param "$@"
    check_files_for_entries "dnsmasq_file=$(get_param "dnsmasq_file" "$@")"
    ;;
  *autoscan=*) # autoscan method
    Dnsmasq_Log_File
    Harvest_Domains "$@"
    check_files_for_entries "dnsmasq=$NAT_ENTRY"
    ;;
  *asnum=*) # ASN Method
    asnum_param "$@"
    check_files_for_entries "asnum=$(get_param "asnum" "$@")"
    ;;
  *aws_region=*) # Amazon Method
    aws_region_param "$@"
    check_files_for_entries "aws_region=$(get_param "aws_region" "$@")"
    ;;
  *ip=* | *dir=*)
    manual_method "$@"
    check_files_for_entries "Manual"
    ;;
  *) exit_error "Invalid parameter(s) passed." ;;
esac

if [ -n "$SRC_IFACE" ] && [ -n "$DST_IFACE" ] && ! echo "$@" | grep -Eq 'src=|src_range='; then
  create_routing_rules
fi

exit_routine
