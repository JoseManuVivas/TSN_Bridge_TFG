#!/usr/bin/env python3
"""
Analiza la salida de hping3 y muestra estadísticas + histograma ASCII
de la distribución de RTT para dos flujos VLAN.

Uso:
    python3 scripts/analyze_latency.py [fichero_vlan1] [fichero_vlan2]

Por defecto lee /tmp/vlan1.txt y /tmp/vlan2.txt
"""

import re
import sys

DEFAULT_FILES = ["/tmp/pcp0.txt", "/tmp/pcp1.txt"]
LABELS       = ["PCP=0 (cola 0)", "PCP=1 (cola 1)"]


def parse_rtts(path):
    rtts = []
    try:
        with open(path) as f:
            for line in f:
                m = re.search(r"rtt=([\d.]+)", line)
                if m:
                    rtts.append(float(m.group(1)))
    except FileNotFoundError:
        print(f"  [!] Fichero no encontrado: {path}")
    return rtts


def percentile(data, p):
    if not data:
        return 0.0
    k = (len(data) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(data) - 1)
    return data[lo] + (data[hi] - data[lo]) * (k - lo)


def stats(rtts):
    if not rtts:
        return {}
    s = sorted(rtts)
    n = len(s)
    return {
        "n":    n,
        "min":  s[0],
        "mean": sum(s) / n,
        "p50":  percentile(s, 50),
        "p95":  percentile(s, 95),
        "p99":  percentile(s, 99),
        "max":  s[-1],
    }


def ascii_histogram(rtts, label, bins=20, width=50, cap_ms=50.0):
    if not rtts:
        return
    filtered = [r for r in rtts if r <= cap_ms]
    dropped = len(rtts) - len(filtered)
    if dropped:
        print(f"  (se excluyen {dropped} outliers > {cap_ms} ms del histograma)")
    rtts = filtered
    if not rtts:
        return
    lo, hi = min(rtts), max(rtts)
    if lo == hi:
        hi = lo + 1
    step = (hi - lo) / bins
    counts = [0] * bins
    for v in rtts:
        idx = min(int((v - lo) / step), bins - 1)
        counts[idx] += 1
    max_count = max(counts) or 1

    print(f"\n  Histograma — {label}")
    print(f"  {'ms':>6}  {'':50}  n")
    print(f"  {'─'*6}  {'─'*50}  {'─'*5}")
    for i, c in enumerate(counts):
        bar_lo = lo + i * step
        bar    = "█" * int(c / max_count * width)
        print(f"  {bar_lo:6.2f}  {bar:<50}  {c}")


def main():
    files = sys.argv[1:3] if len(sys.argv) >= 3 else DEFAULT_FILES

    all_rtts = []
    for path, label in zip(files, LABELS):
        print(f"\n{'='*60}")
        print(f"  {label}  —  {path}")
        print(f"{'='*60}")
        rtts = parse_rtts(path)
        all_rtts.append(rtts)
        if not rtts:
            print("  Sin datos.")
            continue
        st = stats(rtts)
        print(f"  Muestras : {st['n']}")
        print(f"  Mínimo   : {st['min']:.3f} ms")
        print(f"  Media    : {st['mean']:.3f} ms")
        print(f"  p50      : {st['p50']:.3f} ms")
        print(f"  p95      : {st['p95']:.3f} ms")
        print(f"  p99      : {st['p99']:.3f} ms")
        print(f"  Máximo   : {st['max']:.3f} ms")
        ascii_histogram(rtts, label)

    if len(all_rtts) == 2 and all_rtts[0] and all_rtts[1]:
        mean0 = sum(all_rtts[0]) / len(all_rtts[0])
        mean1 = sum(all_rtts[1]) / len(all_rtts[1])
        print(f"\n{'='*60}")
        print(f"  Diferencia de medias: {abs(mean0 - mean1):.3f} ms")
        print(f"  (esperado ~0 ms si ambas colas se gatan igual)")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
