# Bitácora del desarrollo - TFG Bridge TSN con AF_XDP

## Sesión [15-03-2026]

### Puesta en marcha del escenario
**Objetivo:** Configurar el entorno de red virtual con Mininet y verificar el etiquetado VLAN.

#### Tareas realizadas
- Creación de `.gitignore` para limpiar el repo de binarios y temporales
- Implementación de `topo.py`basado en el script del tutor. Es una versión simplificada que únicamente define la red virtual de Mininet con dos hosts y un switch entre ellos y etiqueta las interfaces de cada uno de los host con VLAN.
- Probar el script y comprobar que la red se crea correctamente, así como el etiquetado VLAN de las interfaces de los hosts.
- Usando `tcpdump`, verificar que las tramas son etiquetadas con el `802.1Q`

#### Notas técnicas
- La clase `VLANHost` es una especialización (hereda) de la clase básica `Host` de Mininet, la cual ejecuta los comandos necesarios para crear una nueva interfaz VLAN cuyo nombre consiste en el de la interfaz física en la que se crea junto al número de VLAN correspondiente.
- En la situación actual del script, al ejecutar `ip addr` en el host `h1` se observa la nueva interfaz `h1-eth0.10` que se corresponde con lo especificado en el script.
- Además, el script también arranca Mininet.

#### Comandos clave
```bash
# Lanzar la red
sudo python3 topo.py

# Una vez en Mininet, verificar que la interfaz ha sido definida correctamente
mininet> h1 ip addr

# Prueba de conexión básica entre hosts
mininet> h1 ping h2

# Captura de tramas que pasan por una interfaz determinada
# La -e es para mostrar las cabeceras de la capa de enlace
# -nn es para no traducir de IP a nombre y que vaya más rápido.
sudo tcpdump -i <nombre de interfaz> -e -nn
```

### Código eBPF básico y organización del repositorio
**Objetivo:** Construir un código eBPF básico, compilarlo en bytecode, inyectarlo en el Kernel y verificar que funciona. Además, organizar el repositorio y construir un `Makefile` adecuado.

#### Tareas realizadas
- Programa `bridge_kern.c` creado, un programa eBPF muy simple que deja pasar los paquetes de red interceptados e imprime en la salida un mensaje de depuración.
- `Makefile` escalable creado que permite compilar directamente el bytecode (con los flags adecuados)

#### Notas técnicas
- Debido a que eBPF intercepta los paquetes antes de que el Kernel los trate no se pueden utilizar las llamadas al sistema estándar. Por tanto, en lugar de `printf` usamos `bpf_printk`. 
- En eBPF se suele preferir utilizar un `struct` para encapsular las estructuras globales que directamente una variable global debido a que estas se almacenan en un mapa especial y dificulta su tratamiento. Es más eficiente así.
- En `bridge_kern.c`, los punteros al contexto primero se castean a `long` debido a que estos en la máquina virtual de eBPF son estructuras de 32 bits pero en la mayoría de máquinas actuales (x86, AMD64, etc.) los punteros son de 64 bits. De ahí el casteo. Debido a que el paquete aún no ha pasado por la pila de red del Kernel que es la que distingue las cabeceras, este es una secuencia de bytes sin formato.
- Las tres acciones posibles de un programa XDP con un paquete eBPF son: `XDP_PASS`, que deja pasar el paquete a la pila de red normal del Kernel, `XDP_DROP`, que no deja pasar al paquete y `XDP_REDIRECT`, que permite redirigir el paquete a un programa de usuario.
- Para inyectar un programa eBPF(XDP) en el Kernel este debe pasar el proceso de verificación del Kernel que exige entre otras cosas un código compacto y eficiente, sin bucles que no considere que vayan a terminar pronto y con la licencia adecuada. Es por eso que, usando `clang` añadimos el flag `-O2` para un mayor nivel de optimización.
- La opción `-g` a la hora de compilar el código eBPF es para incluir metadatos dentro del fichero objeto. Esto permite utilizar la tecnología BTF(BPF Type Format), que posibilita que el Kernel reporte errores cuando el programa está cargado haciendo referencia al código fuente `bpf_kern.c`
- La opción `-target bpf` le indica a Clang que compile no para la arquitectura de mi ordenador sino para la máquina virtual de eBPF.

#### Comandos clave
```bash
# Comando para limpiar todos los procesos y basura que quede de Mininet
sudo mn -c

# Comando para cargar XDP
# s1-eth1 es la interfaz, xdp indica el modo, obj es el archivo que se quiere cargar.
sudo ip link set dev s1-eth1 xdp obj build/bridge_kern.o sec xdp

# Comando para depurar los mensajes del programa eBPF
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Comando para descargar el programa de la interfaz
sudo ip link set dev s1-eth1 xdp off
```
