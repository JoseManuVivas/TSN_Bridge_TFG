# TSN_Bridge_TFG
**Implementación de un Bridge Virtual de Alto Rendimiento con soporte para TAS (Time-Aware Shaper)**

Este repositorio contiene el código fuente de mi Trabajo de Fin de Grado (TFG), centrado en el desarrollo de un bridge de red en espacio de usuario utilizando la tecnología **AF_XDP** de Linux. El objetivo principal es lograr un reenvío de tráfico con latencia ultra-baja y determinista, sentando las bases para la implementación de mecanismos TSN.

## Características Principales

- **Arquitectura AF_XDP**: Redirección de paquetes desde el Kernel al espacio de usuario mediante `Zero-Copy`, eliminando copias innecesarias en la RAM.
- **Doble Plano de Datos**:
  - **Kernel (eBPF/XDP)**: Filtrado y redirección rápida mediante mapas `XSKMAP`.
  - **Usuario (C)**: Lógica de reenvío (Forwarding) basada en descriptores de memoria y anillos circulares.
- **Gestión de Memoria UMEM**: Organización de memoria alineada a páginas de sistema para optimizar transferencias DMA.
- **Escenario Virtual**: Diseñado para ejecutarse sobre topologías de **Mininet** con soporte para etiquetado VLAN (802.1Q).

## Requisitos del Sistema

Para compilar y ejecutar este proyecto, necesitarás:

- **OS**: Linux Kernel 5.4 o superior (recomendado 5.15+ para mejor soporte XDP).
- **Librerías**: `libelf`, `zlib`, `libbpf` y `libxdp`.
- **Herramientas**: `clang`, `llvm`, `gcc`, `make` y `mininet`.

Instalación de dependencias en Ubuntu/Debian:
```bash
sudo apt update && sudo apt install -y clang llvm libelf-dev libpcap-dev gcc-multilib build-essential libbpf-dev libxdp-dev mininet
```