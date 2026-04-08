import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict


IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DEFAULT_KEYWORDS = (
    "failed",
    "invalid",
    "error",
    "denied",
    "refused",
    "unauthorized",
    "forbidden",
    "attack",
    "malware",
    "blocked",
    "bruteforce",
    "exploit",
)


def load_dotenv(dotenv_path: str = ".env") -> None:
    path = Path(dotenv_path)
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")

        if key and key not in os.environ:
            os.environ[key] = value


def parse_args() -> argparse.Namespace:
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Analyze a log file for suspicious IP addresses."
    )
    parser.add_argument("logfile", help="Path to the log file to analyze.")
    parser.add_argument(
        "--min-hits",
        type=int,
        default=3,
        help="Mark IPs as suspicious after this many log entries. Default: 3.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=20,
        help="Maximum number of IPs to print. Default: 20.",
    )
    parser.add_argument(
        "--keyword",
        action="append",
        default=[],
        help="Add a suspicious keyword. Can be repeated.",
    )
    parser.add_argument(
        "--vt-check",
        action="store_true",
        help="Query VirusTotal for suspicious IPs.",
    )
    parser.add_argument(
        "--vt-api-key",
        default=os.getenv("VT_API_KEY"),
        help="VirusTotal API key. Default: reads VT_API_KEY.",
    )
    parser.add_argument(
        "--json-output",
        help="Write findings to a JSON file.",
    )
    return parser.parse_args()


def is_public_ipv4(candidate: str) -> bool:
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return False

    return isinstance(ip, ipaddress.IPv4Address) and ip.is_global


def analyze_log(logfile: str, min_hits: int, keywords: tuple[str, ...]) -> list[dict]:
    ip_counter: Counter[str] = Counter()
    suspicious_counter: Counter[str] = Counter()
    reasons: defaultdict[str, set[str]] = defaultdict(set)
    examples: defaultdict[str, list[str]] = defaultdict(list)

    with open(logfile, "r", encoding="utf-8", errors="ignore") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            lower_line = line.lower()
            matched_keywords = [word for word in keywords if word in lower_line]

            for candidate in IPV4_RE.findall(line):
                if not is_public_ipv4(candidate):
                    continue

                ip_counter[candidate] += 1

                if matched_keywords:
                    suspicious_counter[candidate] += 1
                    reasons[candidate].update(
                        f"matched keyword '{word}'" for word in matched_keywords
                    )

                if len(examples[candidate]) < 3:
                    examples[candidate].append(line[:220])

    findings = []
    for ip, count in ip_counter.most_common():
        ip_reasons = sorted(reasons[ip])
        if count >= min_hits:
            ip_reasons.append(f"seen {count} times")

        if not ip_reasons:
            continue

        findings.append(
            {
                "ip": ip,
                "hits": count,
                "suspicious_hits": suspicious_counter[ip],
                "reasons": ip_reasons,
                "examples": examples[ip],
            }
        )

    return findings


def query_virustotal(ip: str, api_key: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(ip)}"
    request = urllib.request.Request(
        url,
        headers={
            "accept": "application/json",
            "x-apikey": api_key,
        },
    )

    with urllib.request.urlopen(request, timeout=15) as response:
        payload = json.load(response)

    stats = (
        payload.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }


def enrich_with_virustotal(findings: list[dict], api_key: str) -> None:
    for finding in findings:
        try:
            finding["virustotal"] = query_virustotal(finding["ip"], api_key)
        except urllib.error.HTTPError as error:
            finding["virustotal_error"] = f"HTTP {error.code}"
        except urllib.error.URLError as error:
            finding["virustotal_error"] = f"Network error: {error.reason}"


def print_report(findings: list[dict], top: int) -> None:
    if not findings:
        print("No suspicious public IPv4 addresses found.")
        return

    for index, finding in enumerate(findings[:top], start=1):
        print(f"[{index}] IP: {finding['ip']}")
        print(f"    Hits: {finding['hits']}")
        print(f"    Suspicious lines: {finding['suspicious_hits']}")
        print(f"    Reasons: {', '.join(finding['reasons'])}")

        virustotal = finding.get("virustotal")
        if virustotal:
            print(
                "    VirusTotal: "
                f"malicious={virustotal['malicious']}, "
                f"suspicious={virustotal['suspicious']}, "
                f"harmless={virustotal['harmless']}, "
                f"undetected={virustotal['undetected']}"
            )
        elif "virustotal_error" in finding:
            print(f"    VirusTotal: {finding['virustotal_error']}")

        print("    Example lines:")
        for example in finding["examples"]:
            print(f"      - {example}")


def export_json(findings: list[dict], output_path: str, top: int) -> None:
    payload = {
        "total_findings": len(findings),
        "exported_findings": min(len(findings), top),
        "findings": findings[:top],
    }

    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def main() -> int:
    args = parse_args()
    keywords = tuple(dict.fromkeys(DEFAULT_KEYWORDS + tuple(args.keyword)))

    try:
        findings = analyze_log(args.logfile, args.min_hits, keywords)
    except FileNotFoundError:
        print(f"Log file not found: {args.logfile}", file=sys.stderr)
        return 1

    if args.vt_check:
        if not args.vt_api_key:
            print(
                "VirusTotal API key is required. Set VT_API_KEY or pass --vt-api-key.",
                file=sys.stderr,
            )
            return 1

        enrich_with_virustotal(findings, args.vt_api_key)

    print_report(findings, args.top)
    if args.json_output:
        export_json(findings, args.json_output, args.top)
        print(f"JSON report saved to: {args.json_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
