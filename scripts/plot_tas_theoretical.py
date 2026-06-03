#!/usr/bin/env python3
"""
Genera el diagrama de tiempo teorico del TAS para la cadena BR1-BR2-BR3.
Lee parametros desde usecase.xml y produce Imagenes/diagrams/tas_theoretical.pdf
"""

import xml.etree.ElementTree as ET
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, 'usecase.xml')
OUTPUT_FILE = os.path.join(SCRIPT_DIR, '..', 'Imagenes', 'diagrams', 'tas_theoretical.pdf')

COLORS = {
    0: '#2196F3',  # azul  — cola 0 (VLAN 100, TSN critico)
    1: '#FF9800',  # naranja — cola 1 (VLAN 101, best effort)
}
QUEUE_LABELS = {
    0: 'Cola 0 — VLAN 100 (TSN crítico)',
    1: 'Cola 1 — VLAN 101 (best effort)',
}
NUM_CYCLES = 2


def load_config(path):
    root = ET.parse(path).getroot()
    cycle_ns = int(root.find('tas/cycle_ns').text)
    gcl = []
    for e in root.find('tas/gcl').findall('entry'):
        gcl.append({
            'gate_mask':   int(e.get('gate_mask'), 16),
            'duration_ns': int(e.get('duration_ns')),
        })
    bridges = []
    for b in root.find('bridges').findall('bridge'):
        bridges.append({
            'id':        int(b.get('id')),
            'offset_ns': int(b.get('offset_ns')),
        })
    return cycle_ns, gcl, bridges


def ns_to_ms(ns):
    return ns / 1e6


def build_slots(cycle_ns, gcl, offset_ns, num_cycles):
    """Devuelve lista de (t_start_ms, duration_ms, queue_idx) para num_cycles ciclos."""
    slots = []
    for c in range(num_cycles):
        t = offset_ns + c * cycle_ns
        for entry in gcl:
            mask = entry['gate_mask']
            dur  = entry['duration_ns']
            for q in range(8):
                if mask & (1 << q):
                    slots.append((ns_to_ms(t), ns_to_ms(dur), q))
            t += dur
    return slots


def main():
    cycle_ns, gcl, bridges = load_config(CONFIG_FILE)
    cycle_ms = ns_to_ms(cycle_ns)
    total_ms = cycle_ms * NUM_CYCLES + ns_to_ms(max(b['offset_ns'] for b in bridges)) + 1

    fig, ax = plt.subplots(figsize=(12, 3.5))

    y_positions = {b['id']: len(bridges) - i for i, b in enumerate(bridges)}
    bar_height  = 0.5

    for bridge in bridges:
        y   = y_positions[bridge['id']]
        slots = build_slots(cycle_ns, gcl, bridge['offset_ns'], NUM_CYCLES)
        for (t_start, dur, q) in slots:
            if t_start > total_ms:
                continue
            ax.barh(y, min(dur, total_ms - t_start), left=t_start,
                    height=bar_height, color=COLORS.get(q, 'grey'),
                    edgecolor='white', linewidth=0.5, align='center')

    # Lineas de ciclo
    for c in range(NUM_CYCLES + 1):
        ax.axvline(c * cycle_ms, color='black', linestyle='--', linewidth=0.7, alpha=0.4)
        if c < NUM_CYCLES:
            ax.text(c * cycle_ms + cycle_ms / 2, len(bridges) + 0.6,
                    f'Ciclo {c+1} ({cycle_ms:.0f} ms)', ha='center', fontsize=8, color='grey')

    # Ejes y etiquetas
    ax.set_yticks([y_positions[b['id']] for b in bridges])
    ax.set_yticklabels([f'BR{b["id"]}  (+{ns_to_ms(b["offset_ns"]):.0f} ms)' for b in bridges],
                       fontsize=10)
    ax.set_xlabel('Tiempo (ms)', fontsize=10)
    ax.set_xlim(0, total_ms)
    ax.set_ylim(0.5, len(bridges) + 1)
    ax.set_title('Diagrama de tiempo TAS teórico — cadena BR1→BR2→BR3', fontsize=11, pad=10)
    ax.grid(axis='x', linestyle=':', linewidth=0.5, alpha=0.5)

    # Leyenda
    patches = [mpatches.Patch(color=COLORS[q], label=QUEUE_LABELS[q]) for q in sorted(COLORS)]
    ax.legend(handles=patches, loc='upper right', fontsize=9)

    plt.tight_layout()
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    plt.savefig(OUTPUT_FILE, dpi=150, bbox_inches='tight')
    print(f"Diagrama guardado en: {OUTPUT_FILE}")


if __name__ == '__main__':
    main()
