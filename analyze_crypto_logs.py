#!/usr/bin/env python3
"""
Analyze ESP32 Adaptive IoT Cryptography serial logs and Python receiver logs.

Usage:
    python analyze_crypto_logs.py esp32_serial.log receiver.log

The ESP32 log should contain the serial monitor output.
The receiver log should contain the Python receiver output.
The receiver log is optional:
    python analyze_crypto_logs.py esp32_serial.log

Outputs:
    crypto_analysis_summary.txt
    esp32_crypto_records.csv
    receiver_crypto_records.csv (if receiver log is supplied)

Note:
- Context fields such as battery/CPU/memory are reported as simulated if the
  ESP32 log labels them that way.
- AES timing may include key setup while ASCON/GIFT timing may not. Compare
  timings only after standardizing the measured code regions.
"""
import csv
import re
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

ALGO_MAP = {
    "AES-128": "AES-128-GCM",
    "AES-128-GCM": "AES-128-GCM",
    "ASCON-128": "ASCON-AEAD128",
    "ASCON-AEAD128": "ASCON-AEAD128",
    "GIFT-COFB-128": "GIFT-COFB-128",
}

def read_text(path):
    # utf-8-sig handles common Windows log files; replacement handles garbled serial bytes.
    return Path(path).read_text(encoding="utf-8-sig", errors="replace")

def parse_esp32(path):
    text = read_text(path)
    # Each adaptive decision starts a record. Split on the marker to avoid mixing fields.
    chunks = re.split(r"(?=----- ADAPTIVE DECISION -----)", text)
    records = []
    for chunk in chunks:
        if "----- ADAPTIVE DECISION -----" not in chunk:
            continue

        def search(pattern, flags=re.I):
            m = re.search(pattern, chunk, flags)
            return m.group(1).strip() if m else ""

        raw_algo = search(r"Selected algorithm:\s*([^\r\n]+)")
        algo = ALGO_MAP.get(raw_algo.upper(), raw_algo)
        if not algo:
            continue

        security = search(r"Security requirement:\s*([0-9.]+)")
        pressure = search(r"Resource pressure:\s*([0-9.]+)")
        timing = search(
            r"(?:AES-GCM key setup \+ encryption time|AES-GCM encryption time \(including setup\)|"
            r"AES-128-GCM encryption time|ASCON-AEAD128 encryption time|"
            r"GIFT-COFB-128 encryption time|AES encryption time(?: \(including setup\))?):\s*([0-9.]+)\s*(?:us|µs)"
        )
        status = search(r"Encryption status:\s*(PASS|FAIL)")
        temp = search(r"Temperature:\s*(-?[0-9.]+)\s*C")
        humidity = search(r"Humidity:\s*([0-9.]+)\s*%")
        battery = search(r"Battery:\s*([0-9.]+)\s*%")
        cpu = search(r"CPU usage:\s*([0-9.]+)\s*%")
        memory = search(r"Memory usage:\s*([0-9.]+)\s*%")
        sensitivity = search(r"Sensitivity:\s*([^\r\n]+)")
        threat = search(r"Threat:\s*([^\r\n]+)")
        network = search(r"Network:\s*([^\r\n]+)")
        tcp = "SUCCESS" if re.search(r"(?:GIFT TCP connection|TCP connection):\s*SUCCESS", chunk, re.I) else (
            "FAIL" if re.search(r"(?:GIFT TCP connection|TCP connection):\s*FAIL", chunk, re.I) else ""
        )
        sent = "YES" if re.search(r"encrypted message sent to laptop", chunk, re.I) else "NO"
        # Detect older logs where GIFT selection was skipped because implementation was missing.
        skipped = "YES" if re.search(r"Transmission skipped|encryption is not implemented yet", chunk, re.I) else "NO"

        records.append({
            "algorithm": algo,
            "security_requirement": float(security) if security else "",
            "resource_pressure": float(pressure) if pressure else "",
            "encryption_time_us": float(timing) if timing else "",
            "encryption_status": status.upper(),
            "tcp_status": tcp,
            "message_sent": sent,
            "transmission_skipped": skipped,
            "temperature_c": float(temp) if temp else "",
            "humidity_percent": float(humidity) if humidity else "",
            "battery_percent_simulated": float(battery) if battery else "",
            "cpu_percent_simulated": float(cpu) if cpu else "",
            "memory_percent_simulated": float(memory) if memory else "",
            "sensitivity": sensitivity,
            "threat": threat,
            "network": network,
        })
    return records

def parse_receiver(path):
    text = read_text(path)
    # The receiver formats may vary; split on connection headings when available.
    chunks = re.split(r"(?=(?:Connection|Client|Received connection|New connection)\b)", text, flags=re.I)
    if len(chunks) <= 1:
        chunks = re.split(r"(?=Algorithm:\s*(?:AES|ASCON|GIFT))", text, flags=re.I)

    records = []
    for chunk in chunks:
        algo_raw = re.search(r"Algorithm:\s*(AES-128-GCM|AES-128|ASCON-AEAD128|ASCON-128|GIFT-COFB-128)", chunk, re.I)
        if not algo_raw:
            continue
        raw = algo_raw.group(1).upper()
        algo = ALGO_MAP.get(raw, raw)
        auth_pass = bool(re.search(r"Authentication:\s*PASS", chunk, re.I))
        decrypt_pass = bool(re.search(r"Decryption:\s*PASS", chunk, re.I))
        rejected = bool(re.search(r"REJECTED|Authentication:\s*FAIL|Decryption:\s*FAIL", chunk, re.I))
        records.append({
            "algorithm": algo,
            "authentication_pass": auth_pass,
            "decryption_pass": decrypt_pass,
            "rejected": rejected,
        })
    return records

def write_csv(path, records):
    if not records:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(records[0].keys()))
        writer.writeheader()
        writer.writerows(records)

def fmt(value, digits=2):
    return f"{value:.{digits}f}"

def summarize(esp_records, receiver_records, esp_path, receiver_path=None):
    lines = []
    lines.append("ADAPTIVE IoT CRYPTOGRAPHY — LOG ANALYSIS")
    lines.append("=" * 48)
    lines.append(f"ESP32 log: {esp_path}")
    if receiver_path:
        lines.append(f"Receiver log: {receiver_path}")
    lines.append("")

    counts = Counter(r["algorithm"] for r in esp_records)
    total = sum(counts.values())
    lines.append("1. ESP32 algorithm selections")
    lines.append("-" * 32)
    lines.append(f"Total parsed adaptive decisions: {total}")
    for algo in ("AES-128-GCM", "ASCON-AEAD128", "GIFT-COFB-128"):
        n = counts.get(algo, 0)
        pct = 100 * n / total if total else 0
        lines.append(f"{algo}: {n} ({fmt(pct, 1)}%)")
    if not total:
        lines.append("No algorithm decisions parsed. Check log format.")
    lines.append("")

    lines.append("2. Encryption timing (microseconds)")
    lines.append("-" * 32)
    for algo in ("AES-128-GCM", "ASCON-AEAD128", "GIFT-COFB-128"):
        vals = [r["encryption_time_us"] for r in esp_records
                if r["algorithm"] == algo and r["encryption_time_us"] != ""]
        if vals:
            lines.append(
                f"{algo}: n={len(vals)}, mean={fmt(statistics.mean(vals))}, "
                f"median={fmt(statistics.median(vals))}, min={fmt(min(vals))}, "
                f"max={fmt(max(vals))}"
            )
        else:
            lines.append(f"{algo}: no timing values parsed")
    lines.append("Timing caveat: do not compare algorithms directly unless the timed regions match.")
    lines.append("")

    lines.append("3. ESP32 encryption / transmission status")
    lines.append("-" * 32)
    status_counts = Counter(r["encryption_status"] or "NOT_LOGGED" for r in esp_records)
    tcp_counts = Counter(r["tcp_status"] or "NOT_LOGGED" for r in esp_records)
    skipped = sum(r["transmission_skipped"] == "YES" for r in esp_records)
    for k, v in sorted(status_counts.items()):
        lines.append(f"Encryption {k}: {v}")
    for k, v in sorted(tcp_counts.items()):
        lines.append(f"TCP {k}: {v}")
    lines.append(f"Transmission skipped: {skipped}")
    lines.append("")

    lines.append("4. Receiver authentication and decryption")
    lines.append("-" * 32)
    if receiver_records:
        lines.append(f"Receiver records parsed: {len(receiver_records)}")
        for algo in ("AES-128-GCM", "ASCON-AEAD128", "GIFT-COFB-128"):
            rs = [r for r in receiver_records if r["algorithm"] == algo]
            auth = sum(r["authentication_pass"] for r in rs)
            dec = sum(r["decryption_pass"] for r in rs)
            rej = sum(r["rejected"] for r in rs)
            lines.append(f"{algo}: records={len(rs)}, auth_pass={auth}, decrypt_pass={dec}, rejected={rej}")
        lines.append("Receiver parsing depends on the receiver log's exact output format; spot-check the CSV.")
    else:
        lines.append("No receiver log supplied or no receiver records parsed.")
    lines.append("")

    lines.append("5. Adaptive behavior checks")
    lines.append("-" * 32)
    for algo in ("AES-128-GCM", "ASCON-AEAD128", "GIFT-COFB-128"):
        subset = [r for r in esp_records if r["algorithm"] == algo]
        sec = [r["security_requirement"] for r in subset if r["security_requirement"] != ""]
        pressure = [r["resource_pressure"] for r in subset if r["resource_pressure"] != ""]
        if subset:
            sec_avg = fmt(statistics.mean(sec)) if sec else "N/A"
            pres_avg = fmt(statistics.mean(pressure)) if pressure else "N/A"
            lines.append(f"{algo}: mean security requirement={sec_avg}, mean resource pressure={pres_avg}")
    lines.append("These averages are descriptive, not proof that the decision policy is correct.")
    lines.append("")
    lines.append("Interpretation notes:")
    lines.append("- Battery/CPU/memory fields in the current demo are simulated context.")
    lines.append("- A TCP send success is not equivalent to receiver authentication/decryption success.")
    lines.append("- Use receiver-side PASS records to evaluate end-to-end success.")
    lines.append("- Security requirements should take priority over trying to equalize algorithm counts.")
    return "\n".join(lines) + "\n"

def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_crypto_logs.py esp32_serial.log [receiver.log]")
        raise SystemExit(2)
    esp_path = sys.argv[1]
    receiver_path = sys.argv[2] if len(sys.argv) > 2 else None

    esp = parse_esp32(esp_path)
    receiver = parse_receiver(receiver_path) if receiver_path else []

    write_csv("esp32_crypto_records.csv", esp)
    if receiver_path:
        write_csv("receiver_crypto_records.csv", receiver)

    report = summarize(esp, receiver, esp_path, receiver_path)
    Path("crypto_analysis_summary.txt").write_text(report, encoding="utf-8")
    print(report)
    print("Wrote: crypto_analysis_summary.txt")
    print("Wrote: esp32_crypto_records.csv")
    if receiver_path:
        print("Wrote: receiver_crypto_records.csv")

if __name__ == "__main__":
    main()
