# TSN_Bridge_TFG
**Virtualización de un bridge TSN con soporte para TAS (Time-Aware Shaper, IEEE 802.1Qbv)**

Este repositorio contiene el código fuente de mi Trabajo de Fin de Grado (TFG), centrado en el desarrollo de un bridge de red en espacio de usuario utilizando la tecnología **AF_XDP** de Linux. El bridge reenvía tráfico entre interfaces de red con latencia ultra-baja y determinista, e implementa un **Time-Aware Shaper (TAS)** basado en una Gate Control List (GCL) para controlar el acceso al medio en ventanas de tiempo, tal y como define el estándar IEEE 802.1Qbv dentro del ecosistema TSN (Time-Sensitive Networking).

## Características principales

- **Bridge AF_XDP en espacio de usuario**: los paquetes son redirigidos desde el driver de red al proceso de usuario mediante el mecanismo XDP, evitando el procesamiento completo por la pila de red del kernel.
- **Doble plano de datos**:
  - **Kernel (eBPF/XDP)**: programa XDP mínimo que redirige paquetes al socket AF_XDP correspondiente mediante un mapa `XSKMAP`. También registra timestamps de llegada (`bpf_ktime_get_ns`) en un `BPF_MAP_TYPE_RINGBUF` para medición de latencia por salto.
  - **Usuario (C)**: gestiona los sockets AF_XDP, los anillos RX/TX, la UMEM y la lógica de reenvío y clasificación de tráfico.
- **TAS / GCL (IEEE 802.1Qbv)**: el bridge clasifica los paquetes por VLAN (PCP) y los encola en colas software. Un hilo dedicado implementa la Gate Control List como ejecutivo cíclico, abriendo y cerrando cada cola según ventanas de tiempo configurables.
- **Medición de latencia por salto**: timestamps XDP en cada bridge de la cadena permiten calcular la latencia entre bridges sin necesidad de relojes externos, aprovechando que todos los procesos comparten `CLOCK_MONOTONIC` en la misma máquina.
- **Topología de emulación con Mininet**: cadena de 3 bridges virtuales (`H1 - BR1 - BR2 - BR3 - H2`) con etiquetado VLAN 802.1Q y dos clases de tráfico (TSN crítico y best-effort).

## Requisitos del sistema

- **OS**: Linux Kernel 5.4 o superior (recomendado 5.15+ para mejor soporte XDP).
- **Librerías**: `libelf`, `zlib`, `libbpf` y `libxdp`.
- **Herramientas**: `clang`, `llvm`, `gcc`, `make` y `mininet`.

Instalación de dependencias en Ubuntu/Debian:
```bash
sudo apt update && sudo apt install -y clang llvm libelf-dev libpcap-dev gcc-multilib build-essential libbpf-dev libxdp-dev mininet
```

## Compilación

```bash
make
```

## Ejecución

```bash
# 1. Arrancar la topología Mininet
sudo python3 scripts/usecase.py

# 2. Lanzar los bridges (uno por terminal dentro de Mininet)
#    s1: sudo build/af_xdp_user s1-eth1 s1-eth2
#    s2: sudo build/af_xdp_user s2-eth1 s2-eth2
#    s3: sudo build/af_xdp_user s3-eth1 s3-eth2

# 3. Analizar latencias extremo a extremo
python3 scripts/analyze_latency.py /tmp/vlan100.txt /tmp/vlan101.txt

# 4. Analizar latencia por salto (timestamps XDP)
python3 scripts/analyze_hops.py /tmp/ts_s1-eth1.csv /tmp/ts_s2-eth1.csv /tmp/ts_s3-eth1.csv
```
