# Scripts:
- [pcap.sh - PCAP Analysis & Export Toolkit](#pcapsh--pcap-analysis--export-toolkit)
- [magicnum.sh - data type by file magic number](#magicnumsh---data-type-by-file-magic-number)

---

# `pcap.sh` – PCAP Analysis & Export Toolkit

A lightweight Bash script for quick analysis and export of `.pcap` files using `tshark`. Supports device discovery, protocol analysis, DNS/HTTP extraction, and more.

---

#### Usage

```bash
./pcap.sh <mode> <pcap file> [mode params]
```

---

### Analyze Mode

```bash
./pcap.sh analyze <pcap file> <action>
```

#### Actions:
| Action         | Description                                     |
|----------------|-------------------------------------------------|
| `all`          | Run all analysis modules                        |
| `devices`      | Show devices (IP, MAC, Vendor) <br> `-a` to include devices without IP |
| `networkinfo`  | Extract computer names, vendors                 |
| `hostsinfo`    | Detect OS, NetBIOS names                        |
| `listproto`    | List used protocols                             |
| `dnsrequests`  | Count DNS requests <br> `-d` to split by MAC    |
| `hostsrequests`| Count hosts from HTTP/SSL requests             |
| `httpurls`     | Extract HTTP request URLs                       |
| `openedports`  | List TCP/UDP ports per IP                       |
| `peakusage`    | Show traffic peak by hour/day                   |
| `searchfiles`  | Search files by magic numbers                   |

---

### Export Mode

```bash
./pcap.sh export <pcap file> <action>
```

#### Actions:
| Action         | Description                                     |
|----------------|-------------------------------------------------|
| `all`          | Run all export actions                          |
| `devices`      | Split PCAP by MAC address                       |
| `http`         | Extract HTTP protocol traffic                   |
| `clearproto`   | Extract cleartext protocols (HTTP, SMTP, FTP...)|
| `files`        | Search & export files from traffic              |
| `tcpstream <frame>` | Export TCP stream by frame number         |
| `httpstreams`  | Extract all HTTP streams                        |
| `-o <outdir>`  | Set output directory for results                |

---

#### Dependencies
- `tshark`, `nmap` (needed only 'nmap-services' file)
- `awk`, `grep`, `cut`, `sed` (standard Unix tools)

---

#### Example
```bash
./pcap.sh analyze traffic.pcap devices -a
./pcap.sh export traffic.pcap httpstreams -o output/
```
---

# `magicnum.sh` - data type by file magic number
A simple script to identify file types based on their magic numbers. It uses the `file` command to determine the type of a file and compares it with a list of known magic numbers.

#### Usage
```bash
./magicnum.sh <magic number>
```

#### Example
```bash
./magicnum.sh "ffd8ffe0"
JPEG image data
```