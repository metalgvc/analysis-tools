#!/bin/bash

# TODO: extract/export objects,files

function show_help() {
    echo "Usage: $0 <mode> <pcap file> [mode params]"
    echo ""
    echo "modes:"
    echo "  analyze   show devices, traffic, hosts, ..."
    echo "  export    split/export pcap using filters"
}

if [[ -z $1 ]]; then
  show_help
  exit 1
fi

common_nmapservices_paths=(
    "/usr/share/nmap/nmap-services"
    "/usr/local/share/nmap/nmap-services"
    "/etc/nmap/nmap-services"
)

for path in "${common_nmapservices_paths[@]}"; do
    if [[ -f "$path" ]]; then
        NMAP_SERVICES_FILE="$path"
        break
    fi
done

if [[ -z "$NMAP_SERVICES_FILE" && -d "/opt/homebrew/Cellar/nmap" ]]; then
    echo "[*] Searching for nmap-services..."
    NMAP_SERVICES_FILE=$(find /opt/homebrew/Cellar/nmap -type f -name "nmap-services" 2>/dev/null | head -n 1)
fi

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")

MODE="$1"
PCAP_FILE="$2"

PCAP_FILENAME=$(basename "$PCAP_FILE")
PCAP_FILENAME="${PCAP_FILENAME%.*}"
RESULTS_DIR="${PWD}/out/${PCAP_FILENAME}"

SCRIPT_NAME="$0"
MAC_VENDORS_CSV="${SCRIPT_DIR}/db/mac-vendors-export.csv"

if [[ ! -f $MAC_VENDORS_CSV ]]; then
  msg "Not Found: $MAC_VENDORS_CSV"
  echo -e "download https://maclookup.app/downloads/csv-database/get-db and save as: $MAC_VENDORS_CSV"
  exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
NC='\033[0m'
DIV="${YELLOW}----------------------------------------------------------------------------------------------------${NC}"

if [[ ! -d $RESULTS_DIR ]]; then
  mkdir -p "$RESULTS_DIR"
fi

function separator() {
    echo -e $DIV
}

function msg() {
    echo -e "${YELLOW}${1}${NC}"
}

function row() {
  if [[ -n $3 ]]; then
    printf " %-10s %-30s: %s\n" "$1" "$2" "$3"
  fi
}

# ======================================================================================================================
# mode: analyze

function _analyze_help() {
  echo -e "Usage: ${SCRIPT_NAME} analyze ${PCAP_FILE} <action>"
  echo ""
  echo -e "Actions:"
  echo -e " all             run all analyze scripts"
  echo -e " devices         show local devices: IP MAC Vendor"
  echo -e "     -a    show all devices (include these which without IP)"
  echo -e " networkinfo     extract computer names, vendors"
  echo -e " hostsinfo       detect OS, NetBios Names, ..."
  echo -e " listproto       list used protocols"
  echo -e " dnsrequests     extract & count hosts from DNS requests"
  echo -e "     -d    split by MAC addresses"
  echo -e " hostsrequests   extract & count hosts requests, included SSL/TLS requests"
  echo -e " httpurls        extract urls from http requests"
  echo -e " openedports     extract TCP/UDP destination ports by IP"
  echo -e " peakusage       analyzing traffic usage by days & hours"
  echo -e " searchfiles     searching file's magic numbers"
}

function _mac_vendor() {
  local mac_address="$1"
  local formatted_mac=$(echo "$mac_address" | tr '[:lower:]' '[:upper:]')
  awk -F, -v mac="$formatted_mac" '
  {
    if (index(mac, $1) == 1) {
        print $2
    }
  }' "$MAC_VENDORS_CSV"
}

function _analyze_network() {
  msg "Extracting network info..."
  # Detect whether the pcap file is Wi-Fi or Ethernet
  if tshark -r "$PCAP_FILE" -T fields -e wlan.sa 2>/dev/null | head -n 1000 | grep -q .; then
    src_field="wlan.sa"
    dst_field="wlan.da"
    msg "Detected Wi-Fi traffic"
  else
    src_field="eth.src"
    dst_field="eth.dst"
    msg "Detected Ethernet traffic"
  fi
  separator

  # extract MAC addresses & Vendors
  echo -e "${YELLOW}- [arp,dhcp,mdns,llmnr,nbns,icmp] Extracting MAC Addresses & Vendors: ${NC}"
  local macaddrs=$(tshark -r "$PCAP_FILE" -Y "arp or dhcp or mdns or llmnr or nbns or icmp" -T fields -e "$src_field" -e "$dst_field" | grep . | tr '\t' '\n' | sort -u)
  echo "$macaddrs" | while read macaddr; do
      vendor=$(_mac_vendor "$macaddr" 2>/dev/null)
      echo -e "${macaddr}\t${vendor}"
  done
  separator

  # extract IPs
  echo -e "${YELLOW}- [arp,dhcp,mdns,llmnr,nbns,icmp] Extracting Local IPs: ${NC}"
  local ips=$(tshark -r "$PCAP_FILE" -Y "arp or dhcp or mdns or llmnr or nbns or icmp" -T fields -e ip.src -e ip.dst | grep . | tr '\t' '\n' | sort -u)
  echo "$ips"
  separator

  # Extract Computer names in the network
  echo -e "${YELLOW}- [llmnr,mdns,dhcp,nbns] Extracting Computer Names: ${NC}"
  local llmnr_dns_names=$(tshark -r "$PCAP_FILE" -Y "llmnr or mdns" -T fields -e dns.qry.name 2>/dev/null | grep . | sed 's/.local$//' | sort -u)
  local dhcp_names=$(tshark -r "$PCAP_FILE" -Y "dhcp" -T fields -e bootp.option.hostname 2>/dev/null | grep . | sed 's/.local$//' | sort -u)
  local nbns_names=$(tshark -r "$PCAP_FILE" -Y "nbns" -T fields -e nbns.name 2>/dev/null | grep . | sort -u)
  local names=$(printf "%s\n" "$llmnr_dns_names" "$dhcp_names" "$nbns_names" | sort -u)

  echo "$names"
  separator

}

function _analyze_hosts() {
  msg "Analyzing hosts..."

  # Detect whether the pcap file is Wi-Fi or Ethernet
  if tshark -r "$PCAP_FILE" -T fields -e wlan.sa 2>/dev/null | head -n 1000 | grep -q .; then
    src_field="wlan.sa"
    dst_field="wlan.da"
    msg "Detected Wi-Fi traffic"
  else
    src_field="eth.src"
    dst_field="eth.dst"
    msg "Detected Ethernet traffic"
  fi

  local cmd="tshark -r \"$PCAP_FILE\" -T fields -e \"$src_field\" -e ip.src | pgrep \"[ \t]+(192\.168\.|10\.)\" | grep -vE \"([0-9]+,[0-9]+)\" | awk '{printf \"%s %s\n\", \$1, \$2}'"

  eval $cmd | sort -u | while read mac ip; do

    local result=$(tshark -r "$PCAP_FILE" -Y "$src_field == $mac and browser" -T fields -e browser.response_computer_name -e browser.windows_version -e browser.server -e browser.mb_server 2>/dev/null | grep . | awk -F'\t' '
      {
        if ($1 && !seen[$1]++) {
          compname = (compname ? compname "," $1 : $1)
        }

        if ($2 && !seen1[$2]++) {
          ostype = (ostype ? ostype "," $2 : $2)
        }

        if ($3 && !seen2[$3]++) {
          servers = (servers ? servers "," $3 : $3)
        }

        if ($4 && !seen3[$4]++) {
          mbserver = (mbserver ? mbserver "," $4 : $4)
        }

      } END {
        printf "%s\t%s\t%s\t%s\n", compname, ostype, servers, mbserver
      }
    ')

    compname=$(echo "$result" | awk -F'\t' '{print $1}' | tr ',' '\n' | awk '!seen[$0]++' | tr '\n' ',' | sed 's/,$//')
    ostype=$(echo "$result" | awk -F'\t' '{print $2}' | tr ',' '\n' | awk '!seen[$0]++' | tr '\n' ',' | sed 's/,$//')
    knowncomps=$(echo "$result" | awk -F'\t' '{print $3}' | tr ',' '\n' | awk '!seen[$0]++' | tr '\n' ',' | sed 's/,$//')
    mbserver=$(echo "$result" | awk -F'\t' '{print $4}' | tr ',' '\n' | awk '!seen[$0]++' | tr '\n' ',' | sed 's/,$//')

    # MDNS
    result=$(tshark -r "$PCAP_FILE" -Y "$src_field == $mac and mdns" -T fields -e dns.resp.name 2>/dev/null | grep . | awk -F'\t' '
      {
        if ($1 && !seen[$1]++) {
          dnsname = (dnsname ? dnsname "," $1 : $1)
        }
      } END {
        printf "%s\n", dnsname
      }
    ')

    dnsname=$(echo "$result" | awk -F'\t' '{print $1}' | tr ',' '\n' | awk '!seen[$0]++' | tr '\n' ',' | sed 's/,$//')

    # used protocols
    protocols=$(tshark -r "$PCAP_FILE" -Y "$src_field == $mac" -T fields -e _ws.col.Protocol 2>/dev/null | grep . | sort -u | tr '\n' ',')

    # netbios names
    local nbname=$(tshark -r "$PCAP_FILE" -Y "nbns and $src_field == $mac" -T fields -e nbns.name 2>/dev/null | awk '
      {
        # nbns.name
        if ($1 && $1 ~ /<00>/) {
          # Remove the <xx> suffix from nbns.name
          gsub(/<..>/, "", $1)
          #gsub(/^[ \t\n]+|[ \t\n]+$/, "", $1)
          #gsub(/[^[:print:]]/, "", $1)
          if (!seen[$1]++) {
            nbns_names = (nbns_names ? nbns_names "," $1 : $1)
          }
        }
      } END {
        print nbns_names
      }
    ')

    # rm duplicates
    nbname=$(echo $nbname | tr ',' '\n' | awk '!seen[$0]++' | tr '\n' ',' | sed 's/,$//')

    # dhcp names
    local dhcpname=$(tshark -r "$PCAP_FILE" -Y "dhcp and $src_field == $mac" -T fields -e bootp.option.hostname 2>/dev/null | awk -F'\t' '
      {
        if ($1 && !seen[$1]++) {
          dhcp_names = (dhcp_names ? dhcp_names "," $1 : $1)
        }
      } END {
        print dhcp_names
      }
    ')

    vendor=$(_mac_vendor "$mac" 2>/dev/null)

    separator
    row "" "MAC" "${mac}   ${vendor}"
    row "" "IP" "$ip"
    row "[nbns]" "Name" "$nbname "
    row "[dhcp]" "Name" "$dhcpname"
    row "[browser]" "Name" "$compname"
    row "[browser]" "Known Computers" "$knowncomps"
    row "[browser]" "Master Browser Server" "$mbserver"
    row "[browser]" "OS" "$ostype"

    row "[mdns]" "Local DNS response" "$dnsname"
    row "" "Protocols used" "$protocols"
  done
  separator
}

function _analyze_devices() {
  msg "Analyzing devices..."

  local get_all=''
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -a) get_all='1'; shift ;;
        *) shift ;;
    esac
  done

  # Detect whether the pcap file is Wi-Fi or Ethernet
  if tshark -r "$PCAP_FILE" -T fields -e wlan.sa 2>/dev/null | head -n 1000 | grep -q .; then
    src_field="wlan.sa"
    dst_field="wlan.da"
    msg "Detected Wi-Fi traffic"
  else
    src_field="eth.src"
    dst_field="eth.dst"
    msg "Detected Ethernet traffic"
  fi

  printf "%-10s %-20s %-18s %-30s %-30s %-20s\n" "Frames" "MAC" "IP" "Vendor" "DHCP Name" "traffic"

  local cmd=""
  if [[ -z $get_all ]]; then
    # show only with IP
    cmd="tshark -r \"$PCAP_FILE\" -T fields -e \"$src_field\" -e ip.src | pgrep \"[ \t]+(192\.168\.|10\.)\" | grep -vE \"([0-9]+,[0-9]+)\" | awk '{printf \"%s %s\n\", \$1, \$2}'"
  else
    cmd="tshark -r \"$PCAP_FILE\" -T fields -e \"$src_field\" -e ip.src | awk '{printf \"%s %s\n\", \$1, \$2}'"
  fi

  # Process local devices
  eval $cmd | sort | uniq -c | sort -k1,1nr | \
  while read count mac ip; do
    vendor=$(_mac_vendor "$mac" 2>/dev/null)

    # Count traffic
    local framelen=$(tshark -r "$PCAP_FILE" -Y "$src_field == $mac or $dst_field == $mac" -T fields -e frame.len -e nbns.name 2>/dev/null | awk '
      {
        bytes += $1
      } END {
        print bytes
      }
    ')

    # dhcp names
    local dhcpname=$(tshark -r "$PCAP_FILE" -Y "dhcp and $src_field == $mac" -T fields -e bootp.option.hostname 2>/dev/null | sed 's/ /+/g' | awk '
      {
        if ($1 && !seen[$1]++) {
          dhcp_names = (dhcp_names ? dhcp_names "," $1 : $1)
        }
      } END {
        print dhcp_names
      }
    ')

    #framelen=$(echo $result | awk '{print $1}')
    #nbname=$(echo $result | awk '{print $1}')
    #dhcpname=$(echo $result | awk '{print $1}')

    #framelen=$(( framelen / 1024 / 1024 ))
    framelen=$(echo "scale=2; $framelen / 1024 / 1024" | bc)

    #echo -e "[$count]\t $mac \t $ip \t $vendor \t traffic: ${framelen}MB"
    printf "%-10s %-20s %-18s %-30s %-30s %-20s\n" "[$count]" "$mac" "$ip" "$vendor" "$dhcpname" "${framelen}MB"
  done
  separator
}

function _analyze_dns_requests() {

  # Detect whether the pcap file is Wi-Fi or Ethernet
  if tshark -r "$PCAP_FILE" -T fields -e wlan.sa 2>/dev/null | head -n 1000 | grep -q .; then
    src_field="wlan.sa"
    dst_field="wlan.da"
    msg "Detected Wi-Fi traffic"
  else
    src_field="eth.src"
    dst_field="eth.dst"
    msg "Detected Ethernet traffic"
  fi

  local split_by_devices=''
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -d) split_by_devices='1'; shift ;;
        *) shift ;;
    esac
  done

  if [[ -n $split_by_devices ]]; then
    msg "host list from DNS requests by devices..."
    tshark -r "$PCAP_FILE" -T fields -e "$src_field" | grep . | sort -u | while read MAC; do
      echo -e "${YELLOW}- device: $MAC ${NC}"
      tshark -r "$PCAP_FILE" -Y "$src_field == $MAC" -T fields -e dns.qry.name | grep . | sort | uniq -c | sort -nr
      separator
    done

  else
    msg "host list from DNS requests..."
    tshark -r "$PCAP_FILE" -Y "dns" -T fields -e dns.qry.name | sort | uniq -c | sort -nr
  fi

  separator
}

function _analyze_opened_ports() {
  echo -e "${YELLOW}opened/destination TCP/UDP ports...${NC}"

  tshark -r "$PCAP_FILE" -Y "ip.dst" -T fields -e ip.dst | grep -E "(192\.168\.|10\.)" | grep -vE "([0-9]+,[0-9]+)" | sort -u | while read IP; do
    separator
    echo -e "${YELLOW}- IP: $IP ${NC}"

    local ports=$(tshark -r "$PCAP_FILE" -Y "ip.dst == $IP" -T fields -e tcp.dstport -e udp.dstport | awk -F'\t' '
    {
      if ($1 && !seen[$1]++) {
        tcp_ports = (tcp_ports ? tcp_ports "," $1 : $1)
      }

      if ($2 && !seen1[$2]++) {
        udp_ports = (udp_ports ? udp_ports "," $2 : $2)
      }

    } END {
      printf "%s %s\n", tcp_ports, udp_ports
    }')

    local tcp_ports=$(echo "$ports" | awk '{print $1}' | tr ',' '\n' | sort -n | tr '\n' ',' | sed 's/,$//')
    local udp_ports=$(echo "$ports" | awk '{print $2}' | tr ',' '\n' | sort -n | tr '\n' ',' | sed 's/,$//')

    # all destination ports
    echo -e "${YELLOW}\nTCP:${NC} $tcp_ports"
    echo -e "${YELLOW}\nUDP:${NC} $udp_ports"
    echo -e "\n${YELLOW}--------------------${NC}"

    # possible services
    if [[ -f "$NMAP_SERVICES_FILE" ]]; then
      local service
      echo -e "${YELLOW}- Services TCP:${NC}"

      echo "$tcp_ports" | tr ',' '\n' | while read port; do
        service=$(grep -w "${port}/tcp" "$NMAP_SERVICES_FILE" | grep -vw 'unknown')
        if [[ -n "$service" ]]; then
          echo "$service"
        fi
      done

      echo -e "${YELLOW}\n- Services UDP:${NC}"

      echo "$udp_ports" | tr ',' '\n' | while read port; do
        service=$(grep -w "${port}/udp" "$NMAP_SERVICES_FILE" | grep -vw 'unknown')
        if [[ -n "$service" ]]; then
          echo "$service"
        fi
      done
    fi

    separator
  done
}

function _analyze_peak_usage() {
    msg "Analyzing traffic usage by days & hours..."

    tshark -r "$PCAP_FILE" -T fields -e frame.time_epoch -e frame.len |
    gawk '{
        time = strftime("%Y-%m-%d %H", $1);  # Convert epoch to date (day & hour)
        traffic[time] += $2;
        total += $2;
    }
    END {
        for (t in traffic) {
            percent = (traffic[t] / total) * 100;
            bars = int(percent / 2);
            printf "%s: %10d bytes | %5.1f%% | %s\n", t, traffic[t], percent, substr("||||||||||||||||||||||||||||||||||||||||||||||||||||||", 1, bars);
        }
    }' | sort
}

function _analyze_host_requests() {
  msg "count hosts requests..."
  tshark -r "$PCAP_FILE" -Y "http.host || ssl.handshake.extensions_server_name" -T fields -e http.host -e ssl.handshake.extensions_server_name | sort | uniq -c | sort -nr
  separator
}

function _analyze_http_urls() {
  msg "http urls..."
  tshark -r "$PCAP_FILE" -Y "http.request.full_uri" -T fields -e http.request.full_uri | sort | uniq -c | sort -nr
  separator
}

function _analyze_protocols_list() {
    msg "list used protocols..."
    tshark -r "$PCAP_FILE" -q -z io,phs
    separator
}

function _analyze_detect_files() {
  msg "searching files magic numbers..."

  tshark -r "$PCAP_FILE" -T fields -e frame.number -e data | while IFS=$'\t' read -r fnum line; do
    local ftype
    if [[ -n "$line" ]]; then
      ftype=$(printf '%s' "$line" | xxd -p | awk '{if (length($0) >= 8) { print substr($0, 1, 8) | "xxd -r -p | file -" } else { exit 1 }}' | awk -F: '{ gsub(/^ +| +$/, "", $2); if ($2 !~ /(ASCII text|empty)/) print $2 }')
      if [[ -n "$ftype" ]]; then
        echo -e "${fnum}\t${ftype}"
      fi
    fi
  done

  separator
}

function _analyze_all() {
    echo "Analyzing all..." >&2

    local analyze_protocols_list_tmp=$(mktemp)
    local analyze_peak_usage_tmp=$(mktemp)
    local analyze_devices_tmp=$(mktemp)
    local analyze_hosts_tmp=$(mktemp)
    local analyze_dns_requests_d_tmp=$(mktemp)
    local analyze_dns_requests_tmp=$(mktemp)
    local analyze_host_requests_tmp=$(mktemp)
    local analyze_http_urls_tmp=$(mktemp)
    local analyze_network_tmp=$(mktemp)
    local analyze_opened_ports_tmp=$(mktemp)

    # Run functions in parallel
    _analyze_protocols_list > "$analyze_protocols_list_tmp" & pids+=($!)
    _analyze_peak_usage > "$analyze_peak_usage_tmp" & pids+=($!)
    _analyze_devices > "$analyze_devices_tmp" & pids+=($!)
    _analyze_hosts > "$analyze_hosts_tmp" & pids+=($!)
    _analyze_dns_requests -d > "$analyze_dns_requests_d_tmp" & pids+=($!)
    _analyze_dns_requests > "$analyze_dns_requests_tmp" & pids+=($!)
    _analyze_host_requests > "$analyze_host_requests_tmp" & pids+=($!)
    _analyze_http_urls > "$analyze_http_urls_tmp" & pids+=($!)
    _analyze_network > "$analyze_network_tmp" & pids+=($!)
    _analyze_opened_ports > "$analyze_opened_ports_tmp" & pids+=($!)

    # Wait for all background jobs and check for failures
    echo "Waiting for background jobs to finish... " >&2
    echo "PIDs: ${pids[@]}" >&2
    for pid in "${pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then  # Check if PID is still running
            echo "Waiting for PID $pid..." >&2
            wait "$pid" || echo "Warning: A background process (PID $pid) failed." >&2
        else
            echo "Skipping PID $pid (already finished)." >&2
        fi
    done

    # Read outputs safely
    local analyze_protocols_list_out; mapfile -t analyze_protocols_list_out < "$analyze_protocols_list_tmp"
    local analyze_peak_usage_out; mapfile -t analyze_peak_usage_out < "$analyze_peak_usage_tmp"
    local analyze_devices_out; mapfile -t analyze_devices_out < "$analyze_devices_tmp"
    local analyze_hosts_out; mapfile -t analyze_hosts_out < "$analyze_hosts_tmp"
    local analyze_dns_requests_d_out; mapfile -t analyze_dns_requests_d_out < "$analyze_dns_requests_d_tmp"
    local analyze_dns_requests_out; mapfile -t analyze_dns_requests_out < "$analyze_dns_requests_tmp"
    local analyze_host_requests_out; mapfile -t analyze_host_requests_out < "$analyze_host_requests_tmp"
    local analyze_http_urls_out; mapfile -t analyze_http_urls_out < "$analyze_http_urls_tmp"
    local analyze_network_out; mapfile -t analyze_network_out < "$analyze_network_tmp"
    local analyze_opened_ports_out; mapfile -t analyze_opened_ports_out < "$analyze_opened_ports_tmp"

    # Print results safely
    separator
    printf "%s\n" "${analyze_protocols_list_out[@]}"
    separator
    printf "%s\n" "${analyze_peak_usage_out[@]}"
    separator
    printf "%s\n" "${analyze_devices_out[@]}"
    separator
    printf "%s\n" "${analyze_hosts_out[@]}"
    separator
    printf "%s\n" "${analyze_dns_requests_d_out[@]}"
    separator
    printf "%s\n" "${analyze_dns_requests_out[@]}"
    separator
    printf "%s\n" "${analyze_host_requests_out[@]}"
    separator
    printf "%s\n" "${analyze_http_urls_out[@]}"
    separator
    printf "%s\n" "${analyze_network_out[@]}"
    separator
    printf "%s\n" "${analyze_opened_ports_out[@]}"

    # Cleanup temporary files
    rm -rf "$analyze_protocols_list_tmp" "$analyze_peak_usage_tmp" "$analyze_devices_tmp" \
           "$analyze_hosts_tmp" "$analyze_dns_requests_d_tmp" "$analyze_dns_requests_tmp" \
           "$analyze_host_requests_tmp" "$analyze_http_urls_tmp" "$analyze_network_tmp" \
           "$analyze_opened_ports_tmp"
}

function mode_analyze() {
  case $1 in
    all) _analyze_all $2 $3 $4 $5 ;;
    devices) _analyze_devices $2 $3 $4 $5 ;;
    networkinfo) _analyze_network $2 $3 $4 $5 ;;
    hostsinfo) _analyze_hosts $2 $3 $4 $5 ;;
    dnsrequests) _analyze_dns_requests $2 $3 $4 $5 ;;
    hostsrequests) _analyze_host_requests $2 $3 $4 $5 ;;
    httpurls) _analyze_http_urls ;;
    listproto) _analyze_protocols_list ;;
    openedports) _analyze_opened_ports ;;
    peakusage) _analyze_peak_usage $2 $3 $4 $5 ;;
    searchfiles) _analyze_detect_files ;;
    *) _analyze_help ;;
  esac
}

# ======================================================================================================================
# mode: export

function _export_help() {
  echo "Usage: $0 export <pcap file> <action>"
  echo ""
  echo "Actions:"
  echo " all             run all export actions"
  echo " devices         split pcap by devices using MAC addresses"
  echo " http            extract http proto"
  echo " clearproto      extract cleartext protocols (http,smtp,ftp,pop,imap)"
  echo " files           search & export files"
  echo " tcpstream <frame num>      export TCP stream by frame number"
  echo " httpstreams     extract all HTTP streams"
  echo "       -o <out dir>    output results directory"
}

function _export_devices() {
  msg "split by devices..."

  # Detect whether the pcap file is Wi-Fi or Ethernet
  if tshark -r "$PCAP_FILE" -T fields -e wlan.sa 2>/dev/null | head -n 1000 | grep -q .; then
    src_field="wlan.sa"
    dst_field="wlan.da"
    msg "Detected Wi-Fi traffic"
  else
    src_field="eth.src"
    dst_field="eth.dst"
    msg "Detected Ethernet traffic"
  fi

  local ips_list=$(tshark -r "$PCAP_FILE" -T fields -e "$src_field" -e ip.src | pgrep "[ \t]+(192\.168\.|10\.)" | grep -vE "([0-9]+,[0-9]+)" | sort -u)

  echo -e "Local devices:"
  echo "$ips_list"

  local MAC
  local outfile
  echo "$ips_list" | while read MAC IP; do
    MAC=$(echo "$MAC" | awk '{print $1}')
    outfile="${RESULTS_DIR}/device_${MAC//:/}.pcap"

    msg "- processing mac: $MAC"
    tshark -r "$PCAP_FILE" -Y "$src_field == $MAC or $dst_field == $MAC" -w "$outfile"
  done

  separator
  ls -lh "${RESULTS_DIR}" | grep 'device_'
}

function _export_http() {
  local outname
  local outfile
  outname=$(basename "$PCAP_FILE")
  outfile="${RESULTS_DIR}/http_${outname}"

  msg "extract http into: ${outfile}"
  tshark -r "$PCAP_FILE" -Y "http" -w "$outfile"
  separator
  ls -lh "${RESULTS_DIR}" | grep 'http_'
}

function _export_tcpstream() {
  local streamid
  local outfile
  local outname
  outname=$(basename "$PCAP_FILE")

  streamid=$(tshark -r "$PCAP_FILE" -Y "frame.number == ${1}" -T fields -e tcp.stream 2>/dev/null)
  outfile="${RESULTS_DIR}/tcp_stream_${streamid}_${outname}"

  echo -e "exporting TCP stream ${streamid} into ${outfile}"
  tshark -r "$PCAP_FILE" -Y "tcp.stream == ${streamid}" -w "$outfile"
  echo -e "Stream saved in: ${YELLOW}${outfile}${NC}"
}

function _export_httpstreams() {

  local OUTDIR="$RESULTS_DIR"
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -o) shift; OUTDIR="$1"; shift ;;
        *) shift ;;
    esac
  done

  if [[ ! -d "$OUTDIR" ]]; then
    mkdir -p "$OUTDIR"
  fi

  stream_ids=$(tshark -r "$PCAP_FILE" -Y "http" -T fields -e tcp.stream | sort -n | uniq)
  local count=$(echo "$stream_ids" | wc -l)
  echo "streams found: $count"

  # Loop through each stream ID and extract the data
  for stream_id in $stream_ids; do
    output_file="${OUTDIR}/http_stream_${stream_id}.txt"
    echo "Extracting HTTP stream ${stream_id} to ${output_file}"
    tshark -r "$PCAP_FILE" -q -z follow,http,ascii,$stream_id > "$output_file"
  done
}

function _export_cleartext_proto() {
  local outname
  local outfile
  outname=$(basename "$PCAP_FILE")

  local OUTDIR="$RESULTS_DIR"
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -o) shift; OUTDIR="$1"; shift ;;
        *) shift ;;
    esac
  done

  if [[ ! -d "$OUTDIR" ]]; then
    mkdir -p "$OUTDIR"
  fi

  outfile="${OUTDIR}/cleartext_protos_${outname}"

  msg "extract cleartext protocols into: ${outfile}"
  tshark -r "$PCAP_FILE" -Y "http or ftp or smtp or telnet or pop or imap or xml" -w "$outfile"
  separator
  ls -lh "${OUTDIR}" | grep 'cleartext_protos_'
}

function _export_files() {
  outdir="${RESULTS_DIR}/files"
  if [[ ! -d "$outdir" ]]; then
    mkdir -p "$outdir"
  fi

  msg "exporting http files"
  tshark -r "$PCAP_FILE" -q --export-objects "http,${outdir}/"

  # TODO: search files in other protocols (by magic numbers ?? see _analyze_detect_files)
  # like -Y "frame contains 0x89504E47 or ..." + follow stream ??
  separator
}

function _export_all() {
    _export_devices
    _export_http
    _export_cleartext_proto
}

function mode_export() {
  case $1 in
    all) _export_all ;;
    devices) _export_devices ;;
    http)  _export_http ;;
    clearproto) _export_cleartext_proto $2 $3 ;;
    files) _export_files ;;
    tcpstream) _export_tcpstream $2 ;;
    httpstreams) _export_httpstreams $2 $3 ;;
    *) _export_help ;;
  esac
}


# ======================================================================================================================
# main
case $MODE in
    analyze) mode_analyze $3 $4 $5 $6 ;;
    export) mode_export $3 $4 $5 $6 ;;
    *) show_help; exit 1 ;;
esac