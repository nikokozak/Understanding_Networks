#!/usr/bin/env python3
import json
import os
import re
import socket
import time
import csv
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, Iterable, List, Tuple, Any, Optional

try:
    import requests  # type: ignore
except Exception:
    requests = None  # lazy fallback; we'll warn at call time

REPORT_PATH = "/Users/niko/Documents/ITP/Understanding-Networks/Traceroute/mtr_report.json"
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "f16eb2292770cb")
IPINFO_SLEEP_SEC = float(os.getenv("IPINFO_SLEEP_SEC", "0.35"))

# Simple in-process caches to avoid redundant DNS/API calls
_dns_cache: Dict[str, Optional[str]] = {}
_ipinfo_cache: Dict[str, Dict[str, Any]] = {}
_last_ipinfo_query_ts: float = 0.0

ProviderRegex = [
    ("campus", re.compile(r"\bnyu\.edu\b", re.I)),
    ("nysernet", re.compile(r"\bnysernet\.net\b", re.I)),
    ("lumen_level3", re.compile(r"\b(level3|lumen)\.(net|tech)\b", re.I)),
    ("zayo", re.compile(r"\bzayo\.com\b", re.I)),
    ("akamai", re.compile(r"\b(akamaitechnologies|netarch\.akamai)\b", re.I)),
    ("google", re.compile(r"\b(1e100\.net|google)\b", re.I)),
    ("cloudflare", re.compile(r"\b(cloudflare|1\.1\.1\.1|104\.|162\.158\.)\b", re.I)),
    ("fastly", re.compile(r"\bfastly\b", re.I)),
    ("cirion", re.compile(r"\bciriontechnologies\b", re.I)),
]


def is_ip_address(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host))


def resolve_host_to_ip(host: str) -> Optional[str]:
    if not host or host == "???":
        return None
    if is_ip_address(host):
        return host
    if host in _dns_cache:
        return _dns_cache[host]
    try:
        # Prefer IPv4
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
        if infos:
            ip = infos[0][4][0]
            _dns_cache[host] = ip
            return ip
    except Exception:
        pass
    _dns_cache[host] = None
    return None


def _throttled_get(url: str) -> Optional["requests.Response"]:
    global _last_ipinfo_query_ts
    if requests is None:
        print("requests module not available; skipping IPInfo enrichment")
        return None
    now = time.time()
    wait = _last_ipinfo_query_ts + IPINFO_SLEEP_SEC - now
    if wait > 0:
        time.sleep(wait)
    try:
        resp = requests.get(url, timeout=8)
    except Exception as e:
        print(f"IPInfo request failed: {e}")
        return None
    _last_ipinfo_query_ts = time.time()
    return resp


def parse_org_to_asn(org: Optional[str]) -> Tuple[str, str]:
    """Parse strings like 'AS15169 Google LLC' -> (AS15169, Google LLC)."""
    if not org:
        return ("N/A", "N/A")
    m = re.match(r"^(AS\d+)\s+(.*)$", org.strip(), re.I)
    if m:
        return (m.group(1), m.group(2).strip())
    return ("N/A", org.strip())


def ipinfo_enrich(ip: str) -> Dict[str, Any]:
    if ip in _ipinfo_cache:
        return _ipinfo_cache[ip]
    info: Dict[str, Any] = {
        "ip": ip,
        "country": "N/A",
        "asn": "N/A",
        "as_name": "N/A",
        "as_domain": "N/A",
    }
    url = f"https://api.ipinfo.io/lite/{ip}?token={IPINFO_TOKEN}"
    resp = _throttled_get(url)
    if resp is None:
        _ipinfo_cache[ip] = info
        return info
    if resp.status_code == 200:
        try:
            data = resp.json()
        except Exception:
            data = {}
        info.update({
            "country": data.get("country", info["country"]),
            "asn": data.get("asn", info["asn"]),
            "as_name": data.get("as_name", info["as_name"]),
            "as_domain": data.get("as_domain", info["as_domain"]),
        })

    else:
        print(f"IPInfo {ip} -> HTTP {resp.status_code}")
    _ipinfo_cache[ip] = info
    return info

def iter_json_objects(path: str) -> Iterable[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    objs: List[str] = []
    buf: List[str] = []
    depth = 0
    in_str = False
    escape = False
    for ch in text:
        buf.append(ch)
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                obj_str = "".join(buf).strip()
                if obj_str:
                    try:
                        yield json.loads(obj_str)
                    except json.JSONDecodeError:
                        pass
                buf = []
    # handle trailing buffer if any (shouldn't happen if balanced)

def classify_provider(host: str) -> str:
    if host == "???":
        return "unknown"
    for name, rx in ProviderRegex:
        if rx.search(host):
            return name
    # heuristics by TLD/keywords
    if re.search(r"\.net$|\.com$|\.tech$", host, re.I):
        return "other_external"
    return "unknown"

def is_campus(host: str) -> bool:
    return host != "???" and host.lower().endswith(".nyu.edu")

def safe_float(x: Any) -> Optional[float]:
    try:
        return float(x)
    except Exception:
        return None

def summarize_report(rep: Dict[str, Any]) -> Dict[str, Any]:
    meta = rep["report"]["mtr"]
    dst = meta["dst"]
    hubs = rep["report"]["hubs"]

    hops: List[Dict[str, Any]] = []
    for h in hubs:
        host = h.get("host", "???")
        item = {
            "idx": h.get("count"),
            "host": host,
            "prov": classify_provider(host),
            "is_campus": is_campus(host),
            "loss": safe_float(h.get("Loss%")),
            "snt": h.get("Snt"),
            "last": safe_float(h.get("Last")),
            "avg": safe_float(h.get("Avg")),
            "best": safe_float(h.get("Best")),
            "wrst": safe_float(h.get("Wrst")),
            "stdev": safe_float(h.get("StDev")),
        }
        hops.append(item)

    # incremental avg rtt deltas
    for i, h in enumerate(hops):
        prev = hops[i - 1] if i > 0 else None
        if h["avg"] is not None and prev and prev["avg"] is not None:
            h["avg_delta"] = max(0.0, h["avg"] - prev["avg"])
        else:
            h["avg_delta"] = None

    # destination metrics
    dest_hop = hops[-1] if hops else None
    e2e_avg = dest_hop["avg"] if dest_hop else None
    e2e_loss = dest_hop["loss"] if dest_hop else None

    # largest single-hop increase
    deltas = [(h["avg_delta"] or -1, h) for h in hops]
    deltas.sort(key=lambda x: x[0], reverse=True)
    max_delta, max_hop = (deltas[0] if deltas else (None, None))

    # On-campus (NYU) vs external contribution (sum of positive deltas)
    nyu_added = sum(h["avg_delta"] or 0 for h in hops if h["avg_delta"] and h["is_campus"])
    external_added = sum(h["avg_delta"] or 0 for h in hops if h["avg_delta"] and not h["is_campus"])

    # loss artifact classification
    probe_loss_hops: List[int] = []
    if e2e_loss is not None and e2e_loss == 0.0:
        for h in hops:
            if (h["loss"] or 0) > 0.0:
                probe_loss_hops.append(h["idx"])

    # unknown hops
    unknown_idxs = [h["idx"] for h in hops if h["host"] == "???"]

    # provider sequence
    providers = [h["prov"] for h in hops]

    # first external hop
    first_external = None
    for h in hops:
        if not h["is_campus"]:
            first_external = h
            break

    return {
        "dst": dst,
        "e2e_avg": e2e_avg,
        "e2e_loss": e2e_loss,
        "max_delta": max_delta,
        "max_delta_hop": max_hop,
        "nyu_network_added_rtt_ms": nyu_added,
        "external_network_added_rtt_ms": external_added,
        "unknown_idxs": unknown_idxs,
        "providers": providers,
        "first_external": first_external,
        "hops": hops,
    }

def normalize_host_for_similarity(host: str) -> str:
    if host == "???":
        return "???"
    # keep provider label granularity mostly; strip per-device cruft
    # e.g., take last 3 labels for FQDNs
    parts = host.split(".")
    if len(parts) >= 3:
        return ".".join(parts[-3:]).lower()
    return host.lower()


def write_rows_to_csv(path: str, fieldnames: List[str], rows: List[Dict[str, Any]]) -> None:
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                # ensure all headers exist in row
                safe_row = {k: row.get(k, "") for k in fieldnames}
                writer.writerow(safe_row)
    except Exception as e:
        print(f"Failed to write CSV {path}: {e}")


def infer_as_for_hop(h: Dict[str, Any]) -> Tuple[str, str]:
    """Return (asn, as_name). Uses ipinfo if present; falls back to labels."""
    ipinfo = h.get("ipinfo") or {}
    asn = ipinfo.get("asn") or ""
    as_name = ipinfo.get("as_name") or ""
    if h.get("is_campus"):
        return ("AS-NYU", "NYU Campus Network")
    if asn and as_name:
        return (asn, as_name)
    prov = h.get("prov") or "unknown"
    fallback = {
        "google": ("AS15169", "Google"),
        "akamai": ("AS20940", "Akamai"),
        "cloudflare": ("AS13335", "Cloudflare"),
        "lumen_level3": ("AS3356", "Lumen/Level3 (heuristic)"),
        "zayo": ("AS6461", "Zayo (heuristic)"),
        "nysernet": ("AS19969", "NYSERNet (heuristic)"),
        "cirion": ("AS26599", "Cirion (heuristic)"),
    }
    if prov in fallback:
        return fallback[prov]
    if asn:
        return (asn, as_name or "Unknown AS")
    return ("AS-UNKNOWN", (prov if prov != "unknown" else "Unknown") + " provider")


def build_as_segments(hops: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    segments: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    for h in hops:
        hop_asn, hop_as_name = infer_as_for_hop(h)
        country = (h.get("ipinfo") or {}).get("country") or "N/A"
        avg = h.get("avg")
        delta = h.get("avg_delta") or 0.0

        # Treat unknown ASN as part of the current segment to avoid spurious Unknown segments
        effective_asn = hop_asn
        effective_as_name = hop_as_name
        if hop_asn == "AS-UNKNOWN" and current is not None:
            effective_asn = current["asn"]
            effective_as_name = current["as_name"]

        if current is None or current["asn"] != effective_asn:
            # close previous
            if current is not None:
                current["end_hop_idx"] = h.get("idx") - 1 if h.get("idx") else current["end_hop_idx"]
                current["end_avg_ms"] = current.get("last_seen_avg_ms")
            # start new segment
            current = {
                "asn": effective_asn,
                "as_name": effective_as_name,
                "start_hop_idx": h.get("idx"),
                "end_hop_idx": h.get("idx"),
                "num_hops": 0,
                "countries": set([country]) if country else set(),
                "added_ms": 0.0,
                "start_avg_ms": avg,
                "end_avg_ms": avg,
                "last_seen_avg_ms": avg,
                # per-segment entry delta equals the boundary increase at first hop of this segment
                "entry_delta_ms": float(delta or 0.0),
            }
            segments.append(current)
        # accumulate
        current["num_hops"] += 1
        current["countries"].add(country)
        current["added_ms"] += max(0.0, float(delta or 0.0))
        current["end_hop_idx"] = h.get("idx")
        current["last_seen_avg_ms"] = avg
    if current is not None:
        current["end_avg_ms"] = current.get("last_seen_avg_ms")
    # stringify country sets for output later
    for seg in segments:
        seg["countries_str"] = ";".join(sorted([c for c in seg.get("countries", set()) if c and c != "N/A"])) or "N/A"

    # post-pass: collapse adjacent segments if ASN equal (defensive) and drop zero-hop segments
    collapsed: List[Dict[str, Any]] = []
    for seg in segments:
        if seg.get("num_hops", 0) <= 0:
            continue
        if collapsed and collapsed[-1]["asn"] == seg["asn"]:
            prev = collapsed[-1]
            prev["end_hop_idx"] = seg["end_hop_idx"]
            prev["num_hops"] += seg["num_hops"]
            prev["countries"].update(seg.get("countries", set()))
            prev["added_ms"] += float(seg.get("added_ms", 0.0))
            prev["end_avg_ms"] = seg.get("end_avg_ms")
            continue
        collapsed.append(seg)

    # recompute countries_str after possible merges
    for seg in collapsed:
        seg["countries_str"] = ";".join(sorted([c for c in seg.get("countries", set()) if c and c != "N/A"])) or "N/A"
    return collapsed


def compute_as_boundaries(segments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    boundaries: List[Dict[str, Any]] = []
    for i in range(len(segments) - 1):
        a = segments[i]
        b = segments[i + 1]
        # Skip Unknown->Unknown boundaries (uninformative)
        if a.get("asn") == "AS-UNKNOWN" and b.get("asn") == "AS-UNKNOWN":
            continue
        # Prefer the per-hop entry delta of the next segment as the boundary jump
        jump = b.get("entry_delta_ms")
        if jump is None:
            try:
                ae = float(a.get("end_avg_ms") or 0.0)
                bs = float(b.get("start_avg_ms") or 0.0)
                jump = max(0.0, bs - ae)
            except Exception:
                jump = None
        # De-noise tiny boundaries
        if isinstance(jump, (int, float)) and jump is not None and jump < 0.5:
            jump = 0.0
        boundaries.append({
            "from_asn": a.get("asn"),
            "from_name": a.get("as_name"),
            "to_asn": b.get("asn"),
            "to_name": b.get("as_name"),
            "from_countries": a.get("countries_str"),
            "to_countries": b.get("countries_str"),
            "from_hop_end": a.get("end_hop_idx"),
            "to_hop_start": b.get("start_hop_idx"),
            "boundary_jump_ms": jump,
        })
    return boundaries


def write_markdown_report(path: str, summaries: List[Dict[str, Any]], as_data_per_dst: Dict[str, Dict[str, Any]]) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("# MTR AS-path Narrative\n\n")
            f.write("This report summarizes end-to-end performance by Autonomous System (AS), highlighting where latency is introduced and at which inter-AS boundaries significant jumps occur.\n\n")
            for s in summaries:
                dst = s.get("dst", "")
                e2e = s.get("e2e_avg")
                f.write(f"## {dst} (e2e_avg {e2e:.2f} ms)\n\n")
                as_info = as_data_per_dst.get(dst, {})
                segments: List[Dict[str, Any]] = as_info.get("segments", [])
                boundaries: List[Dict[str, Any]] = as_info.get("boundaries", [])
                # ASCII diagram
                for i, seg in enumerate(segments, 1):
                    star = " *" if seg.get("added_ms", 0.0) == max((x.get("added_ms", 0.0) for x in segments), default=0.0) else ""
                    cname = f"[{seg.get('countries_str')}]" if seg.get("countries_str") and seg.get("countries_str") != "N/A" else ""
                    f.write(f"{i:>2}. {seg.get('asn')} {seg.get('as_name')} {cname}: +{seg.get('added_ms'):.2f} ms over {seg.get('num_hops')} hops{star}\n")
                    if i < len(segments):
                        b = boundaries[i - 1]
                        bj = b.get("boundary_jump_ms")
                        f.write(f"     |__ boundary {b.get('from_asn')} -> {b.get('to_asn')} jump +{(bj if bj is not None else 0):.2f} ms\n")
                f.write("\n")
    except Exception as e:
        print(f"Failed to write Markdown report {path}: {e}")

def main():
    reports = list(iter_json_objects(REPORT_PATH))
    summaries: List[Dict[str, Any]] = [summarize_report(r) for r in reports]

    # DNS resolution and IPInfo enrichment (unique IPs across all hops)
    host_to_ip: Dict[str, Optional[str]] = {}
    all_ips: Dict[str, None] = {}
    for s in summaries:
        for h in s["hops"]:
            host = h.get("host") or "???"
            ip = resolve_host_to_ip(host)
            host_to_ip[host] = ip
            h["ip"] = ip
            if ip and not ip.startswith("10.") and not ip.startswith("192.168.") and not ip.startswith("172.16."):
                all_ips[ip] = None

    for ip in all_ips.keys():
        info = ipinfo_enrich(ip)
        _ipinfo_cache[ip] = info

    for s in summaries:
        for h in s["hops"]:
            ip = h.get("ip")
            if ip and ip in _ipinfo_cache:
                h["ipinfo"] = _ipinfo_cache[ip]
            else:
                h["ipinfo"] = None

    # Per-destination summary
    print("Per-destination latency breakdown (all RTT in ms):")
    print("Legend: e2e_avg = end-to-end avg RTT; NYU network added/external added = sum of positive per-hop RTT increases before/after leaving nyu.edu; 'probe-only loss' means hop shows loss but downstream and destination do not (common ICMP de-prioritization).")
    for s in summaries:
        md = s["max_delta_hop"]
        md_host = md["host"] if md else "-"
        md_idx = md["idx"] if md else "-"
        md_prov = md["prov"] if md else "-"
        md_val = f"{s['max_delta']:.2f} ms" if s["max_delta"] is not None else "-"
        # ASN/country for max hop if available
        md_country = "-"
        md_asn = "-"
        md_as_name = "-"
        if md and md.get("ipinfo"):
            md_country = md["ipinfo"].get("country", "-")
            md_asn = md["ipinfo"].get("asn", "-")
            md_as_name = md["ipinfo"].get("as_name", "-")
        fe = s.get("first_external")
        fe_desc = "-"
        if fe:
            fe_info = fe.get("ipinfo") or {}
            fe_desc = f"hop {fe.get('idx')} {fe.get('prov')} :: {fe.get('host')} [{fe_info.get('country','-')} {fe_info.get('asn','-')}]"
        print(f"- {s['dst']}: e2e_avg={s['e2e_avg']:.2f}, nyu_added={s['nyu_network_added_rtt_ms']:.2f}, external_added={s['external_network_added_rtt_ms']:.2f}")
        print(f"  exit_to_external: {fe_desc}")
        print(f"  biggest_jump: {md_val} at hop {md_idx} ({md_prov} :: {md_host}) [{md_country} {md_asn} {md_as_name}]  unknown_hops={s['unknown_idxs']}  e2e_loss={s['e2e_loss']}%")

    # Provider appearances and added latency
    provider_counts = Counter()
    provider_added_latency = defaultdict(float)
    for s in summaries:
        for h in s["hops"]:
            if h["avg_delta"]:
                provider_counts[h["prov"]] += 1
                provider_added_latency[h["prov"]] += h["avg_delta"]

    print("\nProvider appearances and total added avg latency:")
    for prov, cnt in provider_counts.most_common():
        print(f"- {prov}: hops={cnt}, sum_avg_delta={provider_added_latency[prov]:.2f} ms")

    # Loss-probe artifacts
    print("\nHops with probe-only loss (downstream ok):")
    for s in summaries:
        mdst = s["dst"]
        flagged = []
        for h in s["hops"]:
            if (h["loss"] or 0) > 0 and (s["e2e_loss"] or 0) == 0:
                flagged.append((h["idx"], h["host"], h["prov"], h["loss"]))
        if flagged:
            print(f"- {mdst}: " + ", ".join([f"hop {i} {p} {host} loss={loss}%" for i, host, p, loss in flagged]))

    # Path similarity (by normalized host tokens)
    path_sets = [(s["dst"], set(normalize_host_for_similarity(h["host"]) for h in s["hops"])) for s in summaries]
    print("\nPath Jaccard similarity (top pairs):")
    sims: List[Tuple[float, str, str]] = []
    for i in range(len(path_sets)):
        for j in range(i + 1, len(path_sets)):
            di, seti = path_sets[i]
            dj, setj = path_sets[j]
            inter = len(seti & setj)
            union = len(seti | setj)
            if union == 0:
                continue
            sims.append((inter / union, di, dj))
    sims.sort(reverse=True)
    for sim, a, b in sims[:10]:
        print(f"- {a} vs {b}: J={sim:.2f}")

    # Build AS-path data per destination
    as_data_per_dst: Dict[str, Dict[str, Any]] = {}
    for s in summaries:
        segs = build_as_segments(s.get("hops", []))
        bounds = compute_as_boundaries(segs)
        as_data_per_dst[s.get("dst", "")] = {"segments": segs, "boundaries": bounds}

    # ---------- CSV/Markdown exports ----------
    base_dir = os.path.dirname(REPORT_PATH) or "."
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    prefix = os.path.join(base_dir, f"mtr_{ts}")

    # 1) Per-destination summary CSV
    summary_rows: List[Dict[str, Any]] = []
    for s in summaries:
        md = s.get("max_delta_hop") or {}
        fe = s.get("first_external") or {}
        fe_info = (fe.get("ipinfo") or {}) if fe else {}
        md_info = (md.get("ipinfo") or {}) if md else {}
        summary_rows.append({
            "destination": s.get("dst", ""),
            "e2e_avg_ms": s.get("e2e_avg", ""),
            "e2e_loss_pct": s.get("e2e_loss", ""),
            "nyu_added_ms": s.get("nyu_network_added_rtt_ms", ""),
            "external_added_ms": s.get("external_network_added_rtt_ms", ""),
            "exit_hop_idx": fe.get("idx", ""),
            "exit_hop_provider": fe.get("prov", ""),
            "exit_hop_host": fe.get("host", ""),
            "exit_hop_country": fe_info.get("country", ""),
            "exit_hop_asn": fe_info.get("asn", ""),
            "exit_hop_as_name": fe_info.get("as_name", ""),
            "max_delta_ms": s.get("max_delta", ""),
            "max_delta_hop_idx": md.get("idx", ""),
            "max_delta_provider": md.get("prov", ""),
            "max_delta_host": md.get("host", ""),
            "max_delta_country": md_info.get("country", ""),
            "max_delta_asn": md_info.get("asn", ""),
            "max_delta_as_name": md_info.get("as_name", ""),
            "unknown_hops_count": len(s.get("unknown_idxs", [])),
            "unknown_hops_list": ";".join(str(i) for i in s.get("unknown_idxs", [])),
            "provider_path": ";".join(s.get("providers", [])),
        })
    summary_path = f"{prefix}_summary.csv"
    write_rows_to_csv(summary_path, [
        "destination","e2e_avg_ms","e2e_loss_pct","nyu_added_ms","external_added_ms",
        "exit_hop_idx","exit_hop_provider","exit_hop_host","exit_hop_country","exit_hop_asn","exit_hop_as_name",
        "max_delta_ms","max_delta_hop_idx","max_delta_provider","max_delta_host","max_delta_country","max_delta_asn","max_delta_as_name",
        "unknown_hops_count","unknown_hops_list","provider_path"
    ], summary_rows)

    # 2) Per-hop enriched dataset (backup)
    hop_rows: List[Dict[str, Any]] = []
    for s in summaries:
        dst = s.get("dst", "")
        for h in s.get("hops", []):
            ipinfo = h.get("ipinfo") or {}
            hop_rows.append({
                "destination": dst,
                "hop_idx": h.get("idx", ""),
                "host": h.get("host", ""),
                "ip": h.get("ip", ""),
                "provider": h.get("prov", ""),
                "is_nyu": h.get("is_campus", ""),
                "snt": h.get("snt", ""),
                "loss_pct": h.get("loss", ""),
                "last_ms": h.get("last", ""),
                "avg_ms": h.get("avg", ""),
                "best_ms": h.get("best", ""),
                "wrst_ms": h.get("wrst", ""),
                "stdev_ms": h.get("stdev", ""),
                "avg_delta_ms": h.get("avg_delta", ""),
                "country": ipinfo.get("country", ""),
                "region": ipinfo.get("region", ""),
                "city": ipinfo.get("city", ""),
                "loc": ipinfo.get("loc", ""),
                "org": ipinfo.get("org", ""),
                "asn": ipinfo.get("asn", ""),
                "as_name": ipinfo.get("as_name", ""),
                "hostname": ipinfo.get("hostname", ""),
            })
    hops_path = f"{prefix}_hops.csv"
    write_rows_to_csv(hops_path, [
        "destination","hop_idx","host","ip","provider","is_nyu","snt","loss_pct","last_ms","avg_ms","best_ms","wrst_ms","stdev_ms","avg_delta_ms",
        "country","region","city","loc","org","asn","as_name","hostname"
    ], hop_rows)

    # 3) Provider stats CSV
    provider_rows: List[Dict[str, Any]] = []
    for prov, cnt in provider_counts.items():
        total = provider_added_latency.get(prov, 0.0)
        provider_rows.append({
            "provider": prov,
            "hops_with_positive_delta": cnt,
            "sum_added_avg_ms": round(total, 3),
            "avg_added_per_hop_ms": round(total / cnt, 3) if cnt else 0.0,
        })
    providers_path = f"{prefix}_providers.csv"
    write_rows_to_csv(providers_path, [
        "provider","hops_with_positive_delta","sum_added_avg_ms","avg_added_per_hop_ms"
    ], provider_rows)

    # 4) Flat IPInfo cache CSV (for future re-use)
    ipinfo_rows: List[Dict[str, Any]] = []
    for ip, info in sorted(_ipinfo_cache.items()):
        ipinfo_rows.append({
            "ip": ip,
            "country": info.get("country", ""),
            "region": info.get("region", ""),
            "city": info.get("city", ""),
            "loc": info.get("loc", ""),
            "org": info.get("org", ""),
            "asn": info.get("asn", ""),
            "as_name": info.get("as_name", ""),
            "hostname": info.get("hostname", ""),
        })
    ipinfo_path = f"{prefix}_ipinfo.csv"
    write_rows_to_csv(ipinfo_path, [
        "ip","country","region","city","loc","org","asn","as_name","hostname"
    ], ipinfo_rows)

    # 5) AS segments per-destination CSV
    as_rows: List[Dict[str, Any]] = []
    for dst, data in as_data_per_dst.items():
        for seg in data.get("segments", []):
            as_rows.append({
                "destination": dst,
                "asn": seg.get("asn", ""),
                "as_name": seg.get("as_name", ""),
                "start_hop_idx": seg.get("start_hop_idx", ""),
                "end_hop_idx": seg.get("end_hop_idx", ""),
                "num_hops": seg.get("num_hops", ""),
                "countries": seg.get("countries_str", ""),
                "start_avg_ms": seg.get("start_avg_ms", ""),
                "end_avg_ms": seg.get("end_avg_ms", ""),
                "added_ms": seg.get("added_ms", ""),
            })
    as_segments_path = f"{prefix}_as_segments.csv"
    write_rows_to_csv(as_segments_path, [
        "destination","asn","as_name","start_hop_idx","end_hop_idx","num_hops","countries","start_avg_ms","end_avg_ms","added_ms"
    ], as_rows)

    # 6) AS boundaries CSV
    asb_rows: List[Dict[str, Any]] = []
    for dst, data in as_data_per_dst.items():
        for b in data.get("boundaries", []):
            asb_rows.append({
                "destination": dst,
                "from_asn": b.get("from_asn", ""),
                "from_name": b.get("from_name", ""),
                "to_asn": b.get("to_asn", ""),
                "to_name": b.get("to_name", ""),
                "from_countries": b.get("from_countries", ""),
                "to_countries": b.get("to_countries", ""),
                "from_hop_end": b.get("from_hop_end", ""),
                "to_hop_start": b.get("to_hop_start", ""),
                "boundary_jump_ms": b.get("boundary_jump_ms", ""),
            })
    as_boundaries_path = f"{prefix}_as_boundaries.csv"
    write_rows_to_csv(as_boundaries_path, [
        "destination","from_asn","from_name","to_asn","to_name","from_countries","to_countries","from_hop_end","to_hop_start","boundary_jump_ms"
    ], asb_rows)

    # 7) Markdown narrative
    md_path = f"{prefix}_as_narrative.md"
    write_markdown_report(md_path, summaries, as_data_per_dst)

    print("\nCSV outputs:")
    print(f"- Summary: {summary_path}")
    print(f"- Per-hop enriched: {hops_path}")
    print(f"- Provider stats: {providers_path}")
    print(f"- IPInfo cache: {ipinfo_path}")
    print(f"- AS segments: {as_segments_path}")
    print(f"- AS boundaries: {as_boundaries_path}")
    print(f"- AS narrative (Markdown): {md_path}")

if __name__ == "__main__":
    if not os.path.exists(REPORT_PATH):
        raise SystemExit(f"File not found: {REPORT_PATH}")
    main()