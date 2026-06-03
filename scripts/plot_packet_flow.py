#!/usr/bin/env python3
"""
Diagrama de flujo de paquete TSN a traves de la cadena BR1->BR2->BR3.
Muestra las ventanas GCL y la trayectoria de un paquete TSN critico
y uno best-effort, ilustrando el efecto del offset entre bridges.
"""

import xml.etree.ElementTree as ET
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.lines as mlines

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, 'usecase.xml')
OUTPUT_FILE = os.path.join(SCRIPT_DIR, '..', 'Imagenes', 'diagrams', 'tas_packet_flow.pdf')

COLORS = {
    0: '#2196F3',   # azul   — cola 0 TSN critico
    1: '#FF9800',   # naranja — cola 1 best effort
}

def ns_to_ms(ns):
    return ns / 1e6

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

def build_slots(cycle_ns, gcl, offset_ns, num_cycles):
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
    cycle_ms    = ns_to_ms(cycle_ns)
    offset_ms   = ns_to_ms(bridges[1]['offset_ns'])   # 1ms entre bridges
    num_cycles  = 2
    total_ms    = cycle_ms * num_cycles + offset_ms * len(bridges) + 1

    fig, ax = plt.subplots(figsize=(13, 4.5))

    n_bridges   = len(bridges)
    y_positions = {b['id']: n_bridges - i + 1 for i, b in enumerate(bridges)}
    # Añadimos H1 (arriba) y H2 (abajo) como filas decorativas
    y_h1 = n_bridges + 2
    y_h2 = 0.5
    bar_height = 0.45

    # --- Ventanas GCL ---
    for bridge in bridges:
        y     = y_positions[bridge['id']]
        slots = build_slots(cycle_ns, gcl, bridge['offset_ns'], num_cycles)
        for (t_start, dur, q) in slots:
            if t_start > total_ms:
                continue
            ax.barh(y, min(dur, total_ms - t_start), left=t_start,
                    height=bar_height, color=COLORS.get(q, 'grey'),
                    edgecolor='white', linewidth=0.5, align='center', alpha=0.85)

    # --- Lineas de ciclo ---
    for c in range(num_cycles + 1):
        ax.axvline(c * cycle_ms, color='black', linestyle='--', linewidth=0.7, alpha=0.3)

    # --- Trayectoria paquete TSN critico (cola 0) ---
    # Paquete entra en BR1 a t=0.5ms, cada bridge tarda offset_ms en reenviar
    t_tsn = [0.5 + i * offset_ms for i in range(n_bridges + 1)]
    y_tsn = [y_positions[b['id']] for b in bridges] + [y_h2]
    # Punto de origen en H1
    t_tsn = [0.0] + t_tsn
    y_tsn = [y_h1] + y_tsn

    ax.plot(t_tsn, y_tsn, color='#1565C0', linewidth=2.2,
            marker='o', markersize=6, zorder=5, label='Paquete TSN (cola 0)')
    for i, (t, y) in enumerate(zip(t_tsn[1:-1], y_tsn[1:-1])):
        ax.annotate(f't={t:.1f}ms', xy=(t, y), xytext=(t + 0.15, y + 0.3),
                    fontsize=7.5, color='#1565C0', zorder=6)

    # --- Trayectoria paquete best-effort (cola 1) ---
    # El paquete BE llega en t=0.5ms pero su ventana en BR1 no abre hasta t=7ms
    # Espera en cola, sale a t=7.5ms, y en cada bridge siguiente espera igualmente
    t_be_send_br1 = 7.5   # sale de BR1 cuando abre cola 1
    t_be = [0.5,                              # llega a BR1
            t_be_send_br1,                    # sale de BR1 (espera ventana)
            t_be_send_br1 + offset_ms,        # llega a BR2
            t_be_send_br1 + offset_ms * 2,    # llega a BR3
            t_be_send_br1 + offset_ms * 3]    # llega a H2
    y_be = [y_h1,
            y_positions[1],
            y_positions[2],
            y_positions[3],
            y_h2]

    # Linea de espera en BR1 (horizontal)
    ax.plot([0.5, t_be_send_br1], [y_positions[1], y_positions[1]],
            color='#E65100', linewidth=1.5, linestyle=':', zorder=4)
    ax.annotate('espera\nventana', xy=(4.0, y_positions[1]),
                xytext=(4.0, y_positions[1] + 0.4),
                fontsize=7, color='#E65100', ha='center', zorder=6)

    ax.plot(t_be, y_be, color='#E65100', linewidth=2.2,
            marker='s', markersize=6, zorder=5, label='Paquete BE (cola 1)',
            linestyle='--')

    # --- Etiquetas de filas ---
    ax.set_yticks([y_h1] + [y_positions[b['id']] for b in bridges] + [y_h2])
    ax.set_yticklabels(['H1'] + [f'BR{b["id"]}' for b in bridges] + ['H2'], fontsize=10)

    ax.set_xlabel('Tiempo (ms)', fontsize=10)
    ax.set_xlim(-0.3, total_ms)
    ax.set_ylim(0, y_h1 + 0.8)
    ax.set_title('Flujo de paquete TSN vs. best-effort — cadena BR1→BR2→BR3', fontsize=11, pad=10)
    ax.grid(axis='x', linestyle=':', linewidth=0.5, alpha=0.4)

    # Leyenda
    patch0   = mpatches.Patch(color=COLORS[0], alpha=0.85, label='Ventana cola 0 (TSN crítico, 7 ms)')
    patch1   = mpatches.Patch(color=COLORS[1], alpha=0.85, label='Ventana cola 1 (best effort, 3 ms)')
    line_tsn = mlines.Line2D([], [], color='#1565C0', marker='o', linewidth=2, label='Paquete TSN (cola 0)')
    line_be  = mlines.Line2D([], [], color='#E65100', marker='s', linewidth=2,
                              linestyle='--', label='Paquete BE (cola 1)')
    ax.legend(handles=[patch0, patch1, line_tsn, line_be], loc='upper right', fontsize=8.5)

    plt.tight_layout()
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    plt.savefig(OUTPUT_FILE, dpi=150, bbox_inches='tight')
    print(f"Diagrama guardado en: {OUTPUT_FILE}")

if __name__ == '__main__':
    main()
