#!/usr/bin/env python3
"""
Analiza los timestamps recogidos por el programa XDP en cada bridge
y calcula la latencia por salto: BR1→BR2, BR2→BR3, y extremo a extremo.

Uso:
    python3 scripts/analyze_hops.py <ts_s1-eth1.csv> <ts_s2-eth1.csv> <ts_s3-eth1.csv>

Los ficheros CSV tienen el formato:
    icmp_seq,ts_ns,vlan_id
"""

import sys
import csv
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'Imagenes', 'diagrams')


def load_timestamps(path):
    """Devuelve dict {pkt_seq: ts_ns} para cada fichero CSV."""
    ts = {}
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            if None in row.values() or '' in row.values():
                continue  # fila truncada o incompleta
            seq  = int(row['icmp_seq'])
            ns   = int(row['ts_ns'])
            vlan = int(row['vlan_id'])
            if seq not in ts:
                ts[seq] = (ns, vlan)
    return ts


def compute_latencies(ts_a, ts_b):
    """Latencia en ms entre dos bridges para los paquetes comunes."""
    latencies = {}
    for seq in ts_a:
        if seq in ts_b:
            diff_ns = ts_b[seq][0] - ts_a[seq][0]
            if diff_ns > 0:
                latencies[seq] = diff_ns / 1e6  # ns → ms
    return latencies


def stats(values):
    s = sorted(values)
    n = len(s)
    if n == 0:
        return {}
    def pct(p):
        k = (n - 1) * p / 100
        lo, hi = int(k), min(int(k) + 1, n - 1)
        return s[lo] + (s[hi] - s[lo]) * (k - lo)
    return {
        'n':    n,
        'min':  s[0],
        'mean': sum(s) / n,
        'p50':  pct(50),
        'p95':  pct(95),
        'p99':  pct(99),
        'max':  s[-1],
    }


def print_stats(label, lat_dict):
    values = list(lat_dict.values())
    st = stats(values)
    if not st:
        print(f"  {label}: sin datos")
        return
    print(f"\n  {label} ({st['n']} paquetes)")
    print(f"    min={st['min']:.3f}  mean={st['mean']:.3f}  "
          f"p50={st['p50']:.3f}  p95={st['p95']:.3f}  p99={st['p99']:.3f}  max={st['max']:.3f}  ms")


def main():
    if len(sys.argv) != 4:
        print(f"Uso: {sys.argv[0]} ts_br1.csv ts_br2.csv ts_br3.csv")
        sys.exit(1)

    ts1 = load_timestamps(sys.argv[1])
    ts2 = load_timestamps(sys.argv[2])
    ts3 = load_timestamps(sys.argv[3])

    lat_12 = compute_latencies(ts1, ts2)   # BR1 → BR2
    lat_23 = compute_latencies(ts2, ts3)   # BR2 → BR3
    lat_13 = compute_latencies(ts1, ts3)   # BR1 → BR3 (extremo a extremo)

    print("=" * 60)
    print("  Latencia por salto (timestamps XDP, CLOCK_MONOTONIC)")
    print("=" * 60)
    print_stats("BR1 → BR2", lat_12)
    print_stats("BR2 → BR3", lat_23)
    print_stats("BR1 → BR3 (E2E)", lat_13)

    # --- CDF de latencia por salto ---
    fig, ax = plt.subplots(figsize=(9, 5))
    hops = [
        ("BR1 → BR2", lat_12, '#2196F3'),
        ("BR2 → BR3", lat_23, '#4CAF50'),
        ("BR1 → BR3 (E2E)", lat_13, '#F44336'),
    ]
    CAP = 50.0
    for label, lat_dict, color in hops:
        values = sorted(v for v in lat_dict.values() if v <= CAP)
        if not values:
            continue
        cdf = np.arange(1, len(values) + 1) / len(values)
        ax.plot(values, cdf, label=label, color=color, linewidth=2)

    ax.set_xlabel('Latencia (ms)', fontsize=10)
    ax.set_ylabel('CDF', fontsize=10)
    ax.set_title('Latencia por salto — timestamps XDP', fontsize=11)
    ax.legend(fontsize=9)
    ax.grid(linestyle=':', linewidth=0.5, alpha=0.5)
    ax.set_xlim(left=0)
    ax.set_ylim(0, 1.05)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out = os.path.join(OUTPUT_DIR, 'tas_hop_latency.pdf')
    plt.tight_layout()
    plt.savefig(out, dpi=150, bbox_inches='tight')
    print(f"\n  CDF guardada en: {out}")


if __name__ == '__main__':
    main()
