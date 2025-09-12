import csv
import time
import requests
import re
import json
# data structure to hold different values in every log line
# Example of a log line:
# 2025-09-06T20:53:33.586015+00:00 itpnetworks kernel: [UFW BLOCK] IN=eth0 OUT= MAC=32:cc:1f:83:84:fc:fe:00:00:00:01:01:08:00 SRC=103.102.230.4 DST=157.245.90.47 LEN=40 TOS=0x08 PREC=0x20 TTL=244 ID=54321 PROTO=TCP SPT=39810 DPT=8728 WINDOW=65535 RES=0x00 SYN URGP=0
class LogEntry:
    def __init__(self, timestamp, interface_in, mac, src_ip, dst_ip, length, tos, prec, ttl, id, proto, src_port, dst_port, window, res, urgp):
        self.timestamp = timestamp
        self.interface_in = interface_in
        self.mac = mac
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.length = length
        self.tos = tos
        self.prec = prec
        self.ttl = ttl
        self.id = id
        self.proto = proto
        self.src_port = src_port
        self.dst_port = dst_port
        self.window = window
        self.res = res
        self.urgp = urgp
        self.continent = "N/A"
        self.country = "N/A"
        self.asn = "N/A"
        self.as_name = "N/A"
        self.as_domain = "N/A"

logList = []

with open("./logs/ufw.log") as file:
    for line in file:
        # Separate log line into components
        components = line.strip().split(" ")
        if len(components) < 17:
            continue
        log_entry = LogEntry(
            timestamp=components[0],
            # For rest of components, attempt to find the value after the '=' sign using regex in the original line, if not found, set to "N/A"
            interface_in=re.search(r"IN=(\S+)", line).group(1) if re.search(r"IN=(\S+)", line) else "N/A",
            mac=re.search(r"MAC=(\S+)", line).group(1) if re.search(r"MAC=(\S+)", line) else "N/A",
            src_ip=re.search(r"SRC=(\S+)", line).group(1) if re.search(r"SRC=(\S+)", line) else "N/A",
            dst_ip=re.search(r"DST=(\S+)", line).group(1) if re.search(r"DST=(\S+)", line) else "N/A",
            length=re.search(r"LEN=(\S+)", line).group(1) if re.search(r"LEN=(\S+)", line) else "N/A",
            tos=re.search(r"TOS=(\S+)", line).group(1) if re.search(r"TOS=(\S+)", line) else "N/A",
            prec=re.search(r"PREC=(\S+)", line).group(1) if re.search(r"PREC=(\S+)", line) else "N/A",
            ttl=re.search(r"TTL=(\S+)", line).group(1) if re.search(r"TTL=(\S+)", line) else "N/A",
            id=re.search(r"ID=(\S+)", line).group(1) if re.search(r"ID=(\S+)", line) else "N/A",
            proto=re.search(r"PROTO=(\S+)", line).group(1) if re.search(r"PROTO=(\S+)", line) else "N/A",
            src_port=re.search(r"SPT=(\S+)", line).group(1) if re.search(r"SPT=(\S+)", line) else "N/A",
            dst_port=re.search(r"DPT=(\S+)", line).group(1) if re.search(r"DPT=(\S+)", line) else "N/A",
            window=re.search(r"WINDOW=(\S+)", line).group(1) if re.search(r"WINDOW=(\S+)", line) else "N/A",
            res=re.search(r"RES=(\S+)", line).group(1) if re.search(r"RES=(\S+)", line) else "N/A",
            urgp=re.search(r"URGP=(\S+)", line).group(1) if re.search(r"URGP=(\S+)", line) else "N/A"
        )
        logList.append(log_entry)
    print(f"Parsed {len(logList)} log entries.")


# Create pruned log_entry list with only unique entries in order to not overload IPinfo.io API.
unique_log_entries = []
for log in logList:
    if log.src_ip not in [entry.src_ip for entry in unique_log_entries]:
        unique_log_entries.append(log)
print(f"Reduced to {len(unique_log_entries)} unique log entries based on source IP.")


# For each log entry, add datapoints provided by IPinfo.io using their API, and my Token f16eb2292770cb
print("Enriching log entries with IPinfo.io data...")
for log in unique_log_entries:
    # Make a request to the IPinfo.io API
    response = requests.get(f"https://api.ipinfo.io/lite/{log.src_ip}?token=f16eb2292770cb")
    print(f"Requesting data for IP {log.src_ip}, status code: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(data)
        log.continent = data.get("continent", "N/A")
        log.country = data.get("country", "N/A")
        log.asn = data.get("asn", "N/A")
        log.as_name = data.get("as_name", "N/A")
        log.as_domain = data.get("as_domain", "N/A")
        print(f"Enriched log for IP {log.src_ip}: {log.continent}, {log.country}, {log.asn}, {log.as_name}, {log.as_domain}")
    else:
        print(f"Failed to retrieve data for IP {log.src_ip}, status code: {response.status_code}")
        log.continent = "N/A"
        log.country = "N/A"
        log.asn = "N/A"
        log.as_name = "N/A"
        log.as_domain = "N/A"
    # To avoid hitting the rate limit, add a delay of 1 second between requests
    time.sleep(1)

# Save the enriched data into a file just as a safeguard
with open("enriched_logs.json", mode="w") as jsonfile:
    json.dump([log.__dict__ for log in unique_log_entries], jsonfile)

# Export the enriched log entries to a CSV file
print("Exporting enriched logs to enriched_logs.csv...")
with open("enriched_logs.csv", mode="w", newline="") as csvfile:
    fieldnames = ["timestamp", "interface_in", "interface_out", "mac", "src_ip", "dst_ip", "length", "tos", "prec", "ttl", "id", "proto", "src_port", "dst_port", "window", "res", "flags", "urgp", "city", "region", "country", "loc", "org", "postal"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for log in logList:
        writer.writerow({
            "timestamp": log.timestamp,
            "interface_in": log.interface_in,
            "interface_out": log.interface_out,
            "mac": log.mac,
            "src_ip": log.src_ip,
            "dst_ip": log.dst_ip,
            "length": log.length,
            "tos": log.tos,
            "prec": log.prec,
            "ttl": log.ttl,
            "id": log.id,
            "proto": log.proto,
            "src_port": log.src_port,
            "dst_port": log.dst_port,
            "window": log.window,
            "res": log.res,
            "flags": log.flags,
            "urgp": log.urgp,
            "city": getattr(log, 'city', 'N/A'),
            "region": getattr(log, 'region', 'N/A'),
            "country": getattr(log, 'country', 'N/A'),
            "loc": getattr(log, 'loc', 'N/A'),
            "org": getattr(log, 'org', 'N/A'),
            "postal": getattr(log, 'postal', 'N/A')
        })
print("Enriched logs have been exported to enriched_logs.csv")
