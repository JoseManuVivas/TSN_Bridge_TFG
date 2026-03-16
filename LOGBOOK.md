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

## Sesión [16-03-2026]

### Canal de comunicación entre el Kernel y espacio de usuario
**Objetivo:** Conseguir que el programa XDP redirija el flujo a un programa de espacio de usuario y comunicar los datos utilizando mapas.

#### Tareas realizadas
- Entendido el flujo de datos desde que un paquete de red llega a la NIC hasta que el programa de usuario puede tratarlo y marcarlo en el Fill Ring de la UMEM

- Escrito un programa sencillo que construye el `XSK_MAP` para almacenar los descriptores de los XSK necesarios, que extrae el índice para indexar el socket del contexto de XDP(la cola de la NIC por la que ha entrado) y llama al Kernel para que copie el paquete a la UMEM y le conceda permiso al programa de usuario para acceder a ese chunk.

- Escrito un fichero `shared_defs.h` para definiciones comunes del programa XDP y del programa en espacio de usuario

- Se ha comenzado a escribir el programa de espacio de usuario `bridge_user.c` definiendo la estructura que contendrá diversa información sobre la UMEM.


#### Notas técnicas
- Flujo de datos AF_XDP para tratar paquetes de red:
    1. Un paquete llega a una de las colas de la NIC que está atada a un socket AF_XDP, lo que permite que este pueda ser directamente escrito en la UMEM con DMA(memoria de usuario).
    2. Se ejecuta el programa XDP. Accede al mapa`(XSK_MAP)` en el cual se almacena el descriptor del socket(normalmente el índice en el mapa se hace que coincida con la cola de la NIC a la cual está vinculado el socket)
    3. Se ejecuta `bpf_redirect_map`. Esta función ordena al Kernel que escriba en el RX Ring del socket. Este anillo contiene la dirección de memoria de la UMEM donde se encuentra el paquete (no contiene el paquete como tal). Sirve para "oficializar" que hay un nuevo bloque de datos en la UMEM.
    4. El programa de usuario hace *polling* del RX Ring del mismo socket que configura el programa XDP. Cuando el programa XDP escribe en el RX Ring, el programa de usuario puede acceder a la UMEM de forma oficial, tratar el paquete y escribir en el Fill Ring, oficializando que la UMEM está libre.

- La UMEM está formada por un conjunto de chunks del mismo tamaño. Un descriptor dentro de un ring referencia un chunk referenciando su dirección, simplemente un offset dentro de la región UMEM completa.

- Dependiendo del modo de XDP, es posible que el paquete de red se copie mediante el controlador de DMA a la UMEM antes de la ejecución del programa XDP o después. Pero hasta que ese movimiento sea "oficial", tiene que ejecutarse el programa XDP antes obligatoriamente, ya que el Kernel debe validar la redirección del socket AF_XDP mediante la función `bpf_redirect_map`, que es la que asocia el chunk de la UMEM donde está el paquete al descriptor correspondiente en el RX Ring.

- El RX Ring es una estructura del XSK(XDP Socket) y el Fill Ring es una estructura de la UMEM. Describámoslos un poco:
    - El Fill Ring es, como su propio nombre indica, un anillo que tiene un productor y un consumidor. El productor es el programa de usuario y el consumidor es el kernel. Su función es pasar la propiedad de los chunks de la UMEM del programa de usuario al kernel. Para ello, almacena las direcciones de los chunks que el Kernel puede utilizar para colocar frames en la UMEM. (En el modo normal, estas direcciones tienen que estar alineadas al tamaño del chunk, es decir que si el tamaño del chunk es de 2kB, para el Kernel la dirección 2048, 2050 y 3000 serán la misma).
    - El RX Ring es la parte del socket que "recibe" los paquetes. Contiene una serie de descriptores que apuntan a direcciones de la UMEM, así como la longitud de los datos. En este caso, el productor es el Kernel y el consumidor es el programa de usuario. Si no hay frames disponibles en el Fill Ring que el kernel pueda usar, no habrá descriptores en el RX Ring.

- El verificador del Kernel exige que se verifique que el tamaño del paquete es superior al mínimo de una cabecera Ethernet.

- El puntero `buffer` de la estructura `xsk_umem_info` apunta a la dirección inicial de la memoria que se reservará mediante `malloc()` o una llamada similar en el espacio de usuario para la UMEM.



#### Fuentes consultadas
- **Referencia:** [Documentación oficial de AF_XDP](https://docs.kernel.org/networking/af_xdp.html) — Documentación oficial del Kernel sobre la arquitectura de anillos y gestión de memoria UMEM en AF_XDP.
