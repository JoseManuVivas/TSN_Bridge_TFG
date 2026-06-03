#!/usr/bin/env python3
"""
Genera diagramas de latencia real medida con hping3.
Produce dos graficas:
  - Serie temporal de RTT para VLAN 100 y VLAN 101
  - CDF comparativa de ambos flujos
"""

import re
import os
import sys
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR  = os.path.join(SCRIPT_DIR, '..', 'results')
OUTPUT_DIR   = os.path.join(SCRIPT_DIR, '..', 'Imagenes', 'diagrams')

FILES = {
    'VLAN 100 — TSN crítico (cola 0)':    os.path.join(RESULTS_DIR, 'vlan100.txt'),
    'VLAN 101 — Best effort (cola 1)':    os.path.join(RESULTS_DIR, 'vlan101.txt'),
}
COLORS = ['#2196F3', '#FF9800']

CAP_MS = 50.0   # excluir outliers extremos del plot (no de las estadisticas)


def parse_rtts(path):
    rtts = []
    try:
        with open(path) as f:
            for line in f:
                m = re.search(r'rtt=([\d.]+)', line)
                if m:
                    rtts.append(float(m.group(1)))
    except FileNotFoundError:
        print(f'[!] No encontrado: {path}')
    return rtts


def percentile(data, p):
    s = sorted(data)
    k = (len(s) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def main():
    all_rtts = {}
    for label, path in FILES.items():
        rtts = parse_rtts(path)
        if rtts:
            all_rtts[label] = rtts
        else:
            print(f'Sin datos para {label}')

    if not all_rtts:
        print('No hay datos. Ejecuta primero los experimentos.')
        sys.exit(1)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # ------------------------------------------------------------------ #
    # 1. Serie temporal
    # ------------------------------------------------------------------ #
    fig, ax = plt.subplots(figsize=(12, 4))
    for (label, rtts), color in zip(all_rtts.items(), COLORS):
        filtered = [r if r <= CAP_MS else None for r in rtts]
        ax.plot(filtered, label=label, color=color, linewidth=0.8, alpha=0.85)

    ax.set_xlabel('Número de paquete', fontsize=10)
    ax.set_ylabel('RTT (ms)', fontsize=10)
    ax.set_title('Latencia RTT medida — cadena BR1→BR2→BR3', fontsize=11)
    ax.legend(fontsize=9)
    ax.grid(linestyle=':', linewidth=0.5, alpha=0.5)
    ax.set_ylim(bottom=0)

    out_ts = os.path.join(OUTPUT_DIR, 'tas_real_timeseries.pdf')
    plt.tight_layout()
    plt.savefig(out_ts, dpi=150, bbox_inches='tight')
    print(f'Serie temporal guardada en: {out_ts}')
    plt.close()

    # ------------------------------------------------------------------ #
    # 2. CDF comparativa
    # ------------------------------------------------------------------ #
    fig, ax = plt.subplots(figsize=(8, 5))
    for (label, rtts), color in zip(all_rtts.items(), COLORS):
        filtered = sorted(r for r in rtts if r <= CAP_MS)
        cdf = np.arange(1, len(filtered) + 1) / len(filtered)
        ax.plot(filtered, cdf, label=label, color=color, linewidth=2)

        # Marca p50 y p99
        p50 = percentile(filtered, 50)
        p99 = percentile(filtered, 99)
        ax.axvline(p50, color=color, linestyle='--', linewidth=1, alpha=0.6)
        ax.axvline(p99, color=color, linestyle=':',  linewidth=1, alpha=0.6)

    # Anotaciones p50/p99 en el eje X
    ax.text(0.01, 0.52, 'p50', transform=ax.transAxes, fontsize=8, color='grey')
    ax.text(0.01, 0.99, 'p99', transform=ax.transAxes, fontsize=8, color='grey', va='top')

    ax.set_xlabel('RTT (ms)', fontsize=10)
    ax.set_ylabel('CDF', fontsize=10)
    ax.set_title('CDF de latencia RTT — TSN crítico vs. best effort', fontsize=11)
    ax.legend(fontsize=9)
    ax.grid(linestyle=':', linewidth=0.5, alpha=0.5)
    ax.set_xlim(left=0)
    ax.set_ylim(0, 1.05)

    out_cdf = os.path.join(OUTPUT_DIR, 'tas_real_cdf.pdf')
    plt.tight_layout()
    plt.savefig(out_cdf, dpi=150, bbox_inches='tight')
    print(f'CDF guardada en: {out_cdf}')
    plt.close()

    # ------------------------------------------------------------------ #
    # 3. Tabla de estadisticas como figura independiente
    # ------------------------------------------------------------------ #
    rows = []
    for label, rtts in all_rtts.items():
        s = sorted(rtts)
        rows.append([
            label.split('—')[0].strip(),
            f'{min(s):.1f}',
            f'{sum(s)/len(s):.1f}',
            f'{percentile(s, 50):.1f}',
            f'{percentile(s, 95):.1f}',
            f'{percentile(s, 99):.1f}',
            f'{max(s):.1f}',
        ])
    col_labels = ['Flujo', 'Mín (ms)', 'Media (ms)', 'p50 (ms)', 'p95 (ms)', 'p99 (ms)', 'Máx (ms)']

    fig, ax = plt.subplots(figsize=(10, 1.4))
    ax.axis('off')
    tbl = ax.table(cellText=rows, colLabels=col_labels,
                   loc='center', cellLoc='center')
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(9)
    tbl.scale(1, 1.8)

    out_tbl = os.path.join(OUTPUT_DIR, 'tas_real_stats.pdf')
    plt.tight_layout()
    plt.savefig(out_tbl, dpi=150, bbox_inches='tight')
    print(f'Tabla guardada en: {out_tbl}')
    plt.close()


if __name__ == '__main__':
    main()
