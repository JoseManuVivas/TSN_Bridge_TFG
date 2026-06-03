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

## Sesión [17-03-2026]
### Canal de comunicación entre el Kernel y espacio de usuario
**Objetivo:** Conseguir que el programa XDP redirija el flujo a un programa de espacio de usuario y comunicar los datos utilizando mapas.

#### Tareas realizadas
- En `bridge_user.c` hemos construido la función `configure_xsk_umem` que inicializa todas las estructuras necesarias para tratar con la UMEM y hemos definido las estructuras correspondientes al socket XSK y las funciones para liberar y solicitar frames: `xsk_alloc_umem_frame` y `xsk_free_umem_frame`.

#### Notas técnicas
- La llamada `xsk_umem_create` no reserva la memoria de `buffer`, esta tiene que ser reservada de antemano. Lo que hace esta llamada con la dirección a la que apunta `buffer` es "proteger" la memoria desde `buffer` hasta `size` como, por ejemplo, haciendo que las páginas de memoria donde está nunca vayan al disco y siempre estén en la RAM física.

- La función `calloc` es la versión limpia de `malloc`. Rellena la memoria reservada con ceros para evitar basura.

- Un recordatorio de C. Cuando definimos una estructura en una función que queremos usar fuera de esta hay que definir un puntero y luego reservar memoria para la estructura. ¿Por qué? Porque dentro de una función las variables se crean en la pila, la cual se destruye cuando se sale de la función. Sin embargo las llamadas de reserva de memoria dinámica la reservan en el heap, un espacio de memoria extenso que puede accederse fuera de la función también.

- La gestión de frames(memoria) en un Bridge de dos puertos (pongamos Sockets A y B) es la historia del traspaso de propiedades entre programa de usuario y Kernel y entre sockets. Describámoslo así, en el proceso de un paquete entrando por el socket A y saliendo por el socket B.

    1. Inicialmente, repartimos la propiedad de los frames entre los dos sockets, de forma que uno de ellos no tenga inanición. Recordemos que el Fill Ring sirve para transmitir la propiedad de los frames del programa de usuario al Kernel. Por ello, podemos suponer que, de 4096 frames, de las direcciones 1 a la 2048 serán del Socket A y de la 2049 a la 4096 serán del Socket B. Así, cada Socket rellenará su estructura `umem_frame_addr` con las direcciones que le tocan. Una vez hecho esto, el programa de usuario rellenará con sus direcciones libres el Fill Ring para que el Kernel pueda utilizar todas esas direcciones. La estructura `umem_frame_free` sirve para identificar la última dirección de un frame libre. ¿Pero a qué nos referimos con un frame libre? Es un frame que el programa de usuario (que es el que crea la UMEM) puede "prestar al Kernel". Todo esto se hace al principio y a medida que llenamos el fill ring va disminuyendo el número de "frames libres", porque "ya han sido prestados". los correspondientes a cada socket, claro.
    2. Llega un paquete al Kernel a través de la interfaz física asociada al Socket A. El Kernel busca en el Fill Ring la primera dirección disponible. El Kernel escribe los datos del paquete en ese frame y coloca un descriptor a esa dirección en el RX Ring. La propiedad vuelve al programa de usuario
    3. El frame todavía no se puede conceder al Kernel debido a que lo está usando el programa de usuario. Una vez lo procesa lo escribe en el TX Ring del Socket B. La propiedad del frame vuelve al Kernel.
    4. El driver de la tarjeta de red lee el TX Ring y reenvía el paquete. Cuando lo hace, escribe un descriptor de dicho en el Completion Ring. La propiedad vuelve al programa de usuario.
    5. El programa de usuario ve que hay un nuevo frame en el Completion Ring y descubre que ese frame está de nuevo libre, porque el paquete ya ha viajado por todas las interfaces. Verifica la dirección a cuál de los dos sockets A o B correspondía y lo añade a su lista de libres. El frame vuelve a estar disponible para ser usado cuando sea necesario.

- El pre-decremento (por ejemplo, `xsk->umem_frame_addr[--xsk->umem_frame_free]`) es una joyita de C que, primero decrementa el valor de la variable y luego la usa. Es muy útil en casos como el expuesto, porque matemáticamente el último frame libre no es el índice del vector, es uno menos y al mismo tiempo, el restarle 1 permite tenerlo ya decrementado para el siguiente uso.

## Sesión [18-03-2026]
### Canal de comunicación entre el Kernel y espacio de usuario
**Objetivo:** Conseguir que el programa XDP redirija el flujo a un programa de espacio de usuario y comunicar los datos utilizando mapas.

#### Tareas realizadas
- Programada función `xsk_configure_socket` que inicializa todo lo necesario para que pueda utilizarse un socket AF_XDP. Entre otros registra todos los frames de los que dispone y concede los adecuados al Kernel mediante el Fill Ring.
- Programada función `process_rx_and_forward` que se encarga de la operación de transmitir los descriptores entre el RX y el TX
- Programada función `handle_tx_completion` que devuelve a la pila del socket correspondiente los frames que ya han terminado su función al haber el Kernel terminado de reenviar el paquete correspondiente.
- Programada función `handle_fill_ring` que sirve para provisionar al fill ring de frames que aun queden libres en las pilas de cada socket.
- Se ha empezado a programar el `main`

#### Notas técnicas
- El flag `XDP_FLAGS_SKB_MODE` obliga al Kernel a procesar el paquete XDP siguiendo el stack genérico de red en lugar de ejecutar el programa XDP directamente en el driver. Esto es necesario debido a que vamos a trabajar con interfaces virtuales de Mininet las cuales no disponen de un driver que soporte XDP. Es más lento pero se puede emular en cualquier ordenador.

- Lo que se almacena en la estructura `umem_frame_addr` son offsets, es decir, desplazamientos dentro de la UMEM, el desplazamiento desde el inicio de la UMEM para cada frame.

- Recordatorio de C. El operador `*` sirve para desreferenciar, es decir, cambia el valor de la dirección de memoria a la que apunta por "el cajón" al que apunta. Permite asignar valores a lo que apuntan los punteros.

- Tanto el RX Ring como el TX Ring lo que almacenan son descriptores, es decir: estructuras que guardan la dirección de inicio del paquete en este caso y su longitud. Es lo que estamos traspasando con la función `process_rx_and_forward`

- En la función `process_rx_and_forward` estamos haciendo un truco para despertar al Kernel y avisarle de que tiene paquetes disponibles, que es utilizar `sendto` con un paquete vacío (y el flag `MSG_DONTWAIT`). Es una forma de "forzar" una syscall, sin que el Kernel vaya a hacer nada realmente porque priorizará la labor de transmisión de paquetes.

- El Kernel de Linux y la NIC utilizan una técnica llamada DMA para transferir datos directamente entre memoria y programa sin pasar por la CPU. Esta tecnología exige que la dirección de inicio del bloque de datos a transferir esté alineada con el comienzo de una página. Además, lo ideal es que el número de frames dentro de una página sea potencia de 2, para ganar rendimiento, ya que si un frame formara parte de dos páginas al mismo tiempo el rendimiento caería en picado. Ahora, otra clave es que el tamaño del frame también es un compromiso. Con un frame más pequeño te caben más en una página, pero por otro lado te arriesgas a que un paquete muy grande no quepa en un frame (y directamente el programa no funcionaría). Es por eso por lo que se ha optado directamente por un frame por página.

## Sesión [19-03-2026]
### Canal de comunicación entre el Kernel y espacio de usuario
**Objetivo:** Conseguir que el programa XDP redirija el flujo a un programa de espacio de usuario y comunicar los datos utilizando mapas.

#### Tareas realizadas
- Hemos cambiado la key del `XSKMAP` de la cola de la interfaz por la que ha entrado al propio índice de la interfaz por la que ha entrado.

- Función `main` completada (falta testear).

#### Notas técnicas
- Recordatorio de C: librerías `stdio`, `stdlib` y `unistd`:
    - `stdio` es la librería de usuario que se encarga de la entrada y salida de forma amigable
    - `stdlib` es la "caja de herramientas" general de la librería estándar para usuario
    - `unistd`(Unix Standard) es la librería de bajo nivel. No "envuelve" nada, proporciona las syscalls en su versión más pura.

- Volantazo: Para indexar los sockets en el mapa, en lugar de usar las colas (dado que para los dos sockets la cola es la misma), usaremos los índices de las interfaces.

- El flag `BPF_ANY` es el más permisivo a la hora de insertar en un mapa. Permite que si un elemento asociado a una llave (o la misma llave) existe, lo cree y que si ya existe lo machaque.

- Ha dado error de compilación en la función `xsk_ring_prod__nb_free`. Por lo visto no está definida en mi versión de `libxdp`. Para arreglarlo, simplemente eliminamos su comprobación y listo, con la de reserva es suficiente.

- Un error bastante estúpido que era liberar la memoria de la estructura `xsk_info` antes de eliminar el socket al que apuntaba.

- Además tenía que corregir cual era la ruta para obtener el mapa. Primero se debía obtener el `bpf_object` que contiene el programa, luego buscar el mapa dentro de ese objeto y luego obtener el descriptor de ese mapa.

#### REPORTE DE LA PRIMERA EJECUCIÓN
- Tras poder compilar se ha ejecutado el bridge. Ha fallado, dando error de fallo al inicializar los sockets. Para depurar se incluirá el siguiente print de error:
    - `fprintf(stderr, "Fallo en %s: %s (errno: %d)\n", ifname, strerror(errno), errno);`

- Vale, pudiendo depurar se ha obtenido que el error era del socket B llamado `Bad address`. Presumiblemente es porque el offset de su UMEM se sale de los límites.

- No es eso, porque hemos comprobado a poner de offset 0 también al socket B y sigue sin ir. Es posible que el problema sea al cebar el Fill Ring mientras estamos creando un socket, ya que hay otro abierto que puede que lo esté utilizando. Vamos a aislar la creación del socket y el cebado del Fill Ring.

- Se ha intentado el aislamiento y sigue dando error de Bad Address. El problema parece ser que los drivers virtuales de Mininet no permiten una UMEM compartida para dos interfaces de red distintas. El modo shared_umem se hizo pensando en las distintas colas de un mismo dispositivo de red. Por lo tanto, lo que se va a hacer va a ser una UMEM para cada interfaz. La función de `configure_xsk_umem` se va a la mierda.

- Después de haber implementado el aislamiento y la UMEM para cada socket correctamente (cada socket está asociado a una interfaz), el programa ha logrado ejecutarse, pero no conseguí que el ping fuera y después de unos segundos me ha dado el fatídico Kernel Panic. El motivo probablemente fuera porque los dos sockets compartían el mismo mapa y al estar en interfaces diferentes pues lo volvía loco, ya que el ifindex podía ser el que le saliera del níspero a Mininet.

- Creando dos mapas y cargando un programas XDP en cada interfaz, aunque el ping sigue sin funcionar, ya no da Kernel Panic. Vamos a depurar por qué no se completa el ping.

- Esto es interesante. El mensaje de debug nos revela que los paquetes se están capturando, pero el ping no se completa.

- No ha habido suerte y han vuelto a dar Kernel Panics. Se sospechaba que podía ser por un offset que añade el Kernel al propio frame como espacio para cabeceras pero no ha sido así.

#### Comandos clave
```bash
# Comando para ver los enlaces de mininet
mininet> links

# Comando para abrir dos terminales en cada uno de los hosts
mininet> xterm h1 h2
```

## Sesión [20-03-2026]
### Diagnóstico de Estabilidad y resolución del Kernel Panic en AF_XDP
**Objetivo:** Aislar, diagnosticar y resolver el fallo fatal del sistema (`Fatal exception from interrupt`/Kernel Panic) que ocurría al arrancar el programa de usuario `bridge_user.c`.

### Tareas realizadas
- Análisis de logs: `dmesg/journalctl`. Se analizó el volcado de memoria de sesiones previas utilizando `journalctl -b -1 -r` para identificar el origen del cuelgue del sistema. Se confirmó que el pánico no era un error de segmentación sino una excepción fatal en contexto `softirq` del Kernel.

- Implementación de la Alineación de Memoria: Se modificó la lógica de recepción para confirmar que cualquier dirección extraída del anillo RX estuviera alineada perfectamente al inicio del frame antes de liberarla a la UMEM del otro socket.

- Aislamiento del entorno: Linux Bridge vs OVS: Se modificó el script `topo.py` de Mininet para reemplazar `OVSSwitch` por el `LinuxBridge` nativo buscando el mismo datapath que el Kernel.

- Se rediseñaron las funciones `handle_fill_ring` y `process_rx_and_forward` para que las operaciones de reserva de huecos para frames y envío siempre reservaran el tamaño exacto de frames disponibles para utilizar evitando dejar huecos en los anillos.

- Se eliminó la configuración por defecto en la creación de la UMEM con `xsk_umem__create` que, al utilizar `NULL` forzaba frames de 4096 cuando habíamos definido como tamaño de frame 2048.

- A la hora de retransmitir los paquetes se implementó la suma del margen de 256 para dar espacio a las estructuras que añade el Kernel de Linux al crear el `skb`.

- Prueba de interfaces Dummy: Para descartar un fallo propio del código de C se ejecutó el programa `bridge_user` sobre interfaces `dummy` de Linux, con las que no daba Kernel Panic.

#### Comandos clave
```bash
# Comando para buscar el Call Trace de sesiones previas al provocarse el Kernel Panic
sudo journalctl -b -1 -r | grep -iA 50 "Oops\|panic\|Exception"

# Creación manual de interfaces dummy
sudo ip link add dummy0 type dummy
sudo ip link add dummy1 type dummy
sudo ip link set dummy0 up
sudo ip link set dummy1 up

# Comando para inyectar tráfico artificial en una interfaz sin esperar respuesta
ping -I dummy0 8.8.8.8

```

## Sesión [25-03-2026]
### Ping-pong con la interfaz s1-eth1 del switch
**Objetivo:** Lograr que, al hacer ping a la interfaz s1-eth1 desde uno de los hosts recibir un mensaje ICMP Echo Reply de vuelta.

#### Comandos clave
```bash
# Comando para rellenar la tabla ARP del hosts con la MAC del switch
mininet> h1 arp -s 10.0.0.100 7e:c7:e2:67:9c:69

# Comando para asignarle una dirección IPv4 a la interfaz del switch que por defecto no tiene
mininet> s1 ifconfig s1-eth1 10.0.0.100 up
```

## Sesion [8-03-2026]
### Bridge ya funcionando, buscando paralelismo usando la biblioteca `<pthread>`
**Objetivo:** Conseguir que el polling de cada socket se haga en un thread de forma "paralela", para mejorar la latencia

#### Notas técnicas
- Dado que `global_exit` es escrita por la señal y leída por los dos threads es necesario que nada más actualizarse la variable los threads la vean. Por tanto, hay que hacerla volátil y evitar optimizaciones

- Las funciones de `xsk_alloc_umem_frame` y de `xsk_free_umem_frame` escriben y leen en en una UMEM común paralelamente en cada frame. La UMEM es la única estructura común a los dos sockets, por lo tanto, estas dos funciones deben protegerse con un mutex.

- El bridge no va tan rápido como podría. Evidentemente las limitaciones de Mininet están ahí, pero una opción para mejorar la contención en TCP sería, en lugar de tener un pool compartido de frames para cada socket y tener que usar un mutex que crea mucha contención sería tener un número determinado de frames reservado para cada socket.

## Sesión de tutoría [10-03-2026]

Quiza mejor usar dos UMEM, una por cada interfaz.

TAS es una estructura con 8 colas originalmente, pero rentaria que fuesen 2 inicialmente (con un define o algo del palo).

El TAS va despues de saber por que interfaz reenviarlo. Se determina en qué cola ponerlo. Normalmente se hace con VLANs (vlan 0, cola 0, vlan 1, cola 0).

El frame se va a la cola 0, por ejemplo.

Las colas están unidas por el otro lado a la GCL(Gate Control List)

Del instante 0 al 3, por ejemplo, abrimos una cola. Del 4 al 6 otra. Y luego podemos volver al inicio. Un ejecutivo ciclico en definitiva.

El debate está sobre cuándo hacer la copia en la UMEM o el submit. 

## Sesión [13-05-2026]
### Parseo de VLANs como paso previo al TAS

**Objetivo:** Parsear la etiqueta 802.1Q en el bridge para determinar a qué cola de salida pertenece cada paquete.

#### Notas técnicas

##### Estructura `struct vlan_hdr` y el formato 802.1Q

Un header 802.1Q son exactamente 4 bytes que se insertan entre la cabecera Ethernet y el EtherType original:

```
Sin etiqueta VLAN (frame normal):

  0     6     12    14
  ┌─────┬─────┬─────┬──────────────────────────────────────┐
  │ DST │ SRC │Type │         Payload (IP, ARP...)         │
  │ MAC │ MAC │0800 │                                      │
  └─────┴─────┴─────┴──────────────────────────────────────┘
   6B    6B    2B


Con etiqueta 802.1Q (frame VLAN):

  0     6     12    14         16    18
  ┌─────┬─────┬─────┬──────────┬─────┬──────────────────────────┐
  │ DST │ SRC │8100 │   TCI    │0800 │   Payload (IP, ARP...)   │
  │ MAC │ MAC │     │          │     │                          │
  └─────┴─────┴─────┴──────────┴─────┴──────────────────────────┘
   6B    6B    2B       2B       2B
              │         │         │
              │         │         └─ h_vlan_encapsulated_proto
              │         │            (EtherType real: IP, ARP...)
              │         │
              │         └─ h_vlan_TCI (2 bytes):
              │              ┌───┬───┬───┬─────────────────────┐
              │              │ P │ P │ P │ D │ V  V  V  V  V   │
              │              │ C │ C │ C │ E │ I  I  I  I  I   │
              │              │ P │ P │ P │ I │ D  D  D  D  D   │
              │              └───┴───┴───┴───┴─────────────────┘
              │               bit15       bit12 bit11        bit0
              │               └───3b───┘  └b┘  └────12b────┘
              │                 Prioridad  DEI     VLAN ID
              │
              └─ eth->h_proto = 0x8100
                 ("lo que sigue es una cabecera VLAN")
```

- **PCP** (Priority Code Point, 3 bits): prioridad del tráfico, de 0 a 7. Fundamental para TSN — aquí es donde se mapea la clase de tráfico.
- **DEI** (Drop Eligible Indicator, 1 bit): indica si el frame puede descartarse en caso de congestión. Casi siempre 0.
- **VID** (VLAN Identifier, 12 bits): el número de VLAN, de 0 a 4095. Se extrae con `ntohs(vhdr->h_vlan_TCI) & 0x0FFF`.
- **`h_vlan_encapsulated_proto`**: el EtherType real (IPv4, ARP...) que sin etiqueta estaría en el byte 12-13 y con etiqueta se desplaza al byte 16-17.

`<linux/if_vlan.h>` no exporta `struct vlan_hdr` en espacio de usuario en kernels modernos, por lo que se define manualmente (son 4 bytes fijos del estándar 802.1Q).

##### Problema: TX VLAN Offloading en interfaces veth

Al usar `VLANHost` en Mininet, el kernel activa **TX VLAN offloading** en las interfaces de los hosts: en lugar de incrustar los 4 bytes del header 802.1Q en los datos de la trama, los mueve a un metadato interno del SKB (`skb->vlan_tci`). Cuando la trama cruza el par veth hacia el switch, llega sin la etiqueta en los datos. El programa AF_XDP en modo copia solo copia los datos del paquete, no los metadatos del SKB, por lo que recibe tramas de 42 bytes (ARP sin VLAN) en lugar de 46 bytes.

Consecuencia: el bridge reenvía el ARP sin etiqueta, h2 lo recibe en `h2-eth0` (sin IP configurada) y no responde. El ping nunca completa.

**Solución:** Deshabilitar el offloading VLAN explícitamente en `topo.py`:
```bash
ethtool -K <intf> txvlan off rxvlan off
```
- `txvlan off` en los hosts: obliga al kernel a incrustar los 4 bytes del header 802.1Q en los datos de la trama.
- `rxvlan off` en el switch: evita que el receptor extraiga la etiqueta antes de que XDP la vea.

##### Cuándo hacer la copia a la UMEM de salida

La copia al frame de salida debe hacerse **en el momento del encolado**, no cuando la puerta TAS se abra. La razón: al final de cada iteración del bucle de recepción, el frame de entrada se libera inmediatamente a la Fill Queue para que el kernel pueda reutilizarlo. Si se difiere la copia hasta el flush de la cola, el frame original ya podría estar siendo sobreescrito con un paquete nuevo.

Flujo correcto:
1. Llega paquete → `process_packet` parsea VLAN → obtiene `queue_idx`
2. `xsk_alloc_umem_frame(xsk_out)` → reserva frame en la UMEM de salida
3. `memcpy` del paquete al frame de salida → **copia inmediata**
4. Descriptor `(addr, len)` se encola en `sw_queue[queue_idx]`
5. Frame de entrada se libera (`xsk_free_umem_frame`)
6. Cuando la puerta TAS abra: `flush_sw_queue` hace el `submit` al TX ring

Lo que controlará el TAS no es cuándo se copia, sino cuándo se hace el `submit` al TX ring.

## Sesión [19-05-2026]
### Implementación de las 2 colas de TX
**Objetivo:** Implementar las dos colas, con las funciones correspondientes para que los paquetes, al copiarse al frame de salida, se encolen en ella y esperen a que su ventana de tiempo se abra.

#### Notas técnicas

##### Arquitectura de colas software

Actualmente, en `process_packet`, cuando copiamos un frame en la UMEM del socket de salida, directamente añadimos su descriptor al TX ring de salida. Con el TAS queremos retener ese descriptor en una cola hasta que su ventana de tiempo se abra.

Flujo nuevo:
```
RX ring → process_packet() → sw_queue (según VLAN) → hilo GCL → TX ring kernel
```

##### struct sw_queue — cola SPSC lock-free

Diseño SPSC (Single Producer, Single Consumer): el hilo RX es el único productor, el hilo GCL el único consumidor. Con variables `_Atomic` no hace falta mutex, lo que evita bloqueos en el camino de datos.

```c
struct sw_queue {
    struct xdp_desc ring[NUM_FRAMES];  // reutilizamos xdp_desc de libxdp
    _Atomic uint32_t head;   // solo el productor escribe aquí
    _Atomic uint32_t tail;   // solo el consumidor escribe aquí
    _Atomic uint32_t drops;  // paquetes descartados por cola llena
};
```

`head` y `tail` nunca decrementan — la posición real en el array se obtiene con `% NUM_FRAMES`. La cola está vacía cuando `head == tail` y llena cuando `head - tail >= NUM_FRAMES`.

**Memory ordering:** el productor lee `tail` con `acquire` (para ver los huecos liberados por el consumidor) y escribe `head` con `release` (para que el consumidor vea el slot escrito). El consumidor hace lo simétrico. La regla general: el que escribe una variable usa `release`; el que lee lo que otro escribe usa `acquire`. Las variables que solo toca un hilo se leen con `relaxed`.

No hace falta inicializar `head`, `tail` ni `drops` ya que `calloc` inicializa todos los bytes a 0.

Si la cola está llena, el paquete se descarta (drop silencioso) y se incrementa `drops`. Es la decisión correcta para TSN: un paquete que no cabe en su ventana ya llegará tarde de todas formas. El contador `drops` permite diagnosticar si el GCL está bien dimensionado.

##### struct gcl_entry — Gate Control List

Cada entrada representa una ventana de tiempo:

```c
struct gcl_entry {
    uint8_t  gate_mask;   // bitmask: bit N = cola N abierta
    uint64_t duration_ns;
};
```

Con `uint8_t` soportamos hasta 8 colas, que es exactamente lo que define IEEE 802.1Qbv. La tabla GCL es un array estático que se repite cíclicamente. La duración de cada slot se define con `#define GCL_SLOT_NS` para poder ajustarla sin tocar la lógica.

Tabla inicial (ciclo de 2ms):
```
slot 0: gate_mask=0x01 (cola 0 abierta) — 1ms
slot 1: gate_mask=0x02 (cola 1 abierta) — 1ms
```

##### Hilo GCL

Un tercer hilo (además de los dos de RX) implementa el ejecutivo cíclico:

1. Lee `CLOCK_TAI` — el reloj que exige TSN porque no tiene saltos de segundo como `CLOCK_REALTIME`.
2. Calcula la posición dentro del ciclo: `pos = now_ns % cycle_ns`.
3. Busca el slot activo recorriendo la tabla GCL acumulando duraciones.
4. Para cada socket y cada cola cuyo bit esté abierto en `gate_mask`, drena la cola hacia el TX ring del kernel.
5. Llama a `complete_tx` para reciclar frames de la CQ.
6. Duerme con `nanosleep` hasta el final del slot actual.

**Guardia de tiempo dentro del drenado:** antes de enviar cada frame se comprueba si el slot sigue activo:
```c
if (pos2 >= slot_start + gcl[slot].duration_ns || pos2 < slot_start)
    // slot expirado → descartar frame y parar
```
La segunda condición (`pos2 < slot_start`) es necesaria para detectar el wraparound del último slot: cuando el ciclo da la vuelta, `pos2` salta a 0, que es menor que `slot_start` del último slot. Sin esta condición, el último slot nunca expiraría.

Si el TX ring del kernel está lleno al intentar enviar, el frame se descarta y se para el drenado de esa cola.

##### Bugs encontrados y corregidos

1. **Race condition en `complete_tx`**: `handle_receive_packets` seguía llamando a `complete_tx(xsk_out)` aunque el TX ring ya no lo tocaba. El hilo GCL también llamaba a `complete_tx` sobre los mismos sockets → acceso concurrente a `xsk->cq` y `xsk->outstanding_tx`. Solución: eliminar la llamada de `handle_receive_packets`.

2. **Wraparound del último slot en la guardia de tiempo**: la condición `pos2 >= slot_start + duration` nunca se cumple para el último slot porque `slot_start + duration == cycle_ns` y `pos2` siempre es menor que `cycle_ns`. Solución: añadir `|| pos2 < slot_start`.

3. **Mapeo VLAN → cola invertido**: `vlan_id % NUM_TX_QUEUES` da VLAN 1 → cola 1 y VLAN 2 → cola 0. Corregido con `(vlan_id - 1) % NUM_TX_QUEUES` para que VLAN 1 → cola 0 y VLAN 2 → cola 1.

4. **`clock_gettime` sin verificar**: si fallara, `now_ns` sería basura y el slot calculado incorrecto. Añadida verificación del retorno en ambas llamadas del hilo GCL.

5. **`printf` en el camino caliente**: varios prints por paquete en `process_packet` que bloquean en el buffer de stdout, destruyendo la latencia. Eliminados; solo queda el print de clasificación VLAN para depuración.

##### Topología actualizada

`topo.py` ahora crea hosts con **dos interfaces VLAN** cada uno:
- `h1-eth0.1` → 10.0.0.1/24 (VLAN 1, cola 0)
- `h1-eth0.2` → 10.0.1.1/24 (VLAN 2, cola 1)
- `h2-eth0.1` → 10.0.0.2/24 (VLAN 1, cola 0)
- `h2-eth0.2` → 10.0.1.2/24 (VLAN 2, cola 1)

Esto permite dos flujos concurrentes entre los mismos hosts, cada uno en una VLAN distinta, para verificar el gating del TAS.

##### Verificación

Prueba realizada con dos pings concurrentes desde h1:
```
h1 ping 10.0.0.2   # VLAN 1 → cola 0
h1 ping 10.0.1.2   # VLAN 2 → cola 1
```

Resultado: ambos flujos llegan a destino. La salida del bridge muestra clasificación correcta:
```
[VLAN] ID=1  cola=0
[VLAN] ID=2  cola=1
```

Se observan picos de latencia esporádicos, esperables en Mininet con SKB mode por tres motivos:
- Un paquete que llega justo cuando su slot se cierra espera hasta el siguiente ciclo (≤2ms)
- `nanosleep` no es exacto sin `SCHED_FIFO`/`SCHED_RR`
- SKB mode añade variabilidad inherente al pasar por el stack del kernel

En hardware real con XDP nativo y `PREEMPT_RT` los picos serían predecibles y periódicos.

## Sesión [20-05-2026]
### Medición de latencia del TAS
**Objetivo:** Demostrar cuantitativamente que el GCL gatea el tráfico correctamente: medir la distribución de RTT de dos flujos VLAN concurrentes y verificar que la latencia de cada flujo refleja el comportamiento esperado del TAS.

#### Tareas realizadas

- Diseño e implementación del script `scripts/analyze_latency.py` para analizar la salida de hping3
- Identificación y corrección del bug de hping3 sin interfaz explícita (raw sockets no aplican etiqueta VLAN)
- Primera prueba con GCL simétrico (1ms/1ms): gating no observable por encima del ruido de Mininet
- Identificación del bug de latencia excesiva al pasar a GCL asimétrico (9ms/1ms): el hilo GCL dormía el slot completo
- Corrección del hilo GCL: polling cada 100µs en lugar de dormir hasta el final del slot
- Prueba definitiva con GCL asimétrico (9ms/1ms): diferencia de medias de 5ms, gating demostrado

#### Notas técnicas

##### Diseño del experimento

Se eligió `hping3` sobre `ping` por dos motivos: permite enviar a frecuencia arbitraria (`-i u700` = cada 700µs) y da el RTT de cada paquete individual en la salida, facilitando el análisis estadístico.

La frecuencia de 700µs es incomensurable con el ciclo GCL (10ms), por lo que los paquetes barren todas las fases del ciclo y la distribución observada refleja el comportamiento real del gating.

**Incidencia con hping3:** cuando se lanza sin especificar interfaz (`-I`), hping3 usa raw sockets y no pasa por la interfaz VLAN del kernel (`h1-eth0.2`), por lo que el paquete sale sin etiqueta VLAN 2. El bridge lo clasifica como VLAN 0 → cola 0, y h2 no puede responder (no tiene IP sin etiquetar). Solución: forzar la interfaz con `-I h1-eth0.1` y `-I h1-eth0.2`.

##### Bug: hilo GCL dormía el slot completo

Con GCL simétrico (1ms/slot) este comportamiento era aceptable: un paquete esperaba como mucho 1ms. Al cambiar a slots asimétricos (9ms/1ms), los paquetes de VLAN 1 debían esperar hasta 9ms aunque su gate estuviese abierto, porque el hilo GCL drenaba al inicio del slot y luego dormía 9ms sin volver a drenar.

Resultado: VLAN 1 pasó de ~3ms a ~16ms de media, peor que antes.

**Solución:** en lugar de dormir hasta el final del slot, el hilo GCL duerme en intervalos cortos de 100µs (`GCL_POLL_NS`) y vuelve a drenar en cada iteración. Si el slot termina antes de los 100µs, duerme solo lo que queda:

```c
#define GCL_POLL_NS 100000ULL  /* 100 µs */
uint64_t remaining_ns = slot_start + gcl[slot].duration_ns - pos;
uint64_t sleep_ns = remaining_ns < GCL_POLL_NS ? remaining_ns : GCL_POLL_NS;
```

Con esto, un paquete espera como máximo 100µs dentro de su slot antes de ser enviado. El gate sigue controlando qué cola puede transmitir — solo cambia la granularidad del polling.

##### GCL asimétrico para demostrar el gating

Para que el efecto del gating sea visible por encima del ruido de Mininet (~2ms de variabilidad en SKB mode), se configuró el GCL con slots muy asimétricos:

```c
static const struct gcl_entry gcl[] = {
    { .gate_mask = 0x01, .duration_ns = 9000000 }, /* slot 0: cola 0, 9ms */
    { .gate_mask = 0x02, .duration_ns = 1000000 }, /* slot 1: cola 1, 1ms */
};
```

Cola 0 (VLAN 1) tiene gate abierto el 90% del ciclo → los paquetes esperan como mucho 100µs → latencia baja.
Cola 1 (VLAN 2) tiene gate abierto solo el 10% del ciclo → un paquete que llega en mal momento espera hasta 9ms → latencia alta y variable.

##### Resultados — GCL simétrico 1ms/1ms (experimento previo)

Con slots iguales de 1ms, la variabilidad de Mininet (rango ~4ms) superaba la duración del slot, haciendo invisible el efecto del gating. Ambos flujos mostraban distribuciones similares (~3-6ms).

##### Resultados — GCL asimétrico 9ms/1ms (experimento definitivo)

| Métrica | VLAN 1 (cola 0, 9ms) | VLAN 2 (cola 1, 1ms) |
|---|---|---|
| Muestras | 999 | 1000 |
| Mínimo | 0.2ms | 0.4ms |
| Media | 2.4ms | 7.4ms |
| p50 | 1.4ms | 5.3ms |
| p95 | 2.4ms | 9.9ms |
| p99 | 3.1ms | 10.7ms |
| Máximo | ~3.4ms* | ~11ms* |
| Outliers (timeout) | 1 | 2 |

*excluyendo timeouts de hping3 (~1000ms)

**Diferencia de medias: 5ms.**

##### Interpretación

La diferencia de 5ms entre las medias está muy por encima del ruido de Mininet (~2ms). Esto demuestra inequívocamente que el GCL está gateando el tráfico de forma diferenciada por cola.

VLAN 1 muestra una distribución compacta (0.2-3.4ms) porque su gate está abierto el 90% del tiempo y el polling de 100µs garantiza que los paquetes se envían rápidamente en cuanto llegan.

VLAN 2 muestra una distribución muy ancha (0.4-11ms) con media 5ms más alta: la mayoría de paquetes llegan durante los 9ms en que su gate está cerrado y tienen que esperar hasta el siguiente slot de 1ms.

No se observa distribución bimodal limpia porque el ruido de Mininet en SKB mode (~2ms de variabilidad) difumina los dos modos teóricos. En hardware real con XDP nativo y latencia base <100µs, el efecto sería un desplazamiento limpio de ~9ms entre los dos picos.

Los outliers (~1000ms) son paquetes descartados por la guardia de tiempo del GCL (slot expirado durante el drenado) o por el TX ring lleno, en los que hping3 agota su timeout de 1 segundo.

#### Comandos clave
```bash
# Lanzar los dos flujos concurrentes desde xterm de h1
hping3 -1 -I h1-eth0.1 -i u700 -c 1000 10.0.0.2 > ~/vlan1.txt 2>&1 & \
hping3 -1 -I h1-eth0.2 -i u700 -c 1000 10.0.1.2 > ~/vlan2.txt 2>&1 & \
wait

# Copiar resultados y analizar
cp ~/vlan1.txt ~/vlan2.txt /ruta/al/proyecto/
python3 scripts/analyze_latency.py vlan1.txt vlan2.txt
```

## Sesión [23-05-2026]
### Clasificación por PCP y nueva topología

**Objetivo:** Cambiar la clasificación de tráfico de VLAN ID a campo PCP (conforme al estándar IEEE 802.1Q) y adaptar la topología de Mininet para generar tráfico con distintos valores de PCP.

#### Tareas realizadas

- Cambio de clasificación en `af_xdp_user.c`: de VLAN ID a PCP
- `NUM_TX_QUEUES` ampliado de 2 a 8 (conforme al estándar, 3 bits PCP = 8 clases)
- Rediseño de `topo.py` para marcar PCP mediante `egress-qos-map`
- Actualización de etiquetas en `analyze_latency.py` (VLAN 1/2 → PCP=0/PCP=1)
- Experimento de validación repetido con la nueva clasificación

#### Notas técnicas

##### Cambio de VLAN ID a PCP

El director confirmó que la clasificación de tráfico debe hacerse por el campo **PCP** (Priority Code Point) de la etiqueta 802.1Q, no por el VLAN ID. PCP ocupa los 3 bits más significativos del campo TCI y toma valores 0-7, que mapean directamente a las 8 colas del estándar IEEE 802.1Q.

Cambio en `process_packet`:
```c
/* Antes */
vlan_id = ntohs(vhdr->h_vlan_TCI) & 0x0FFF;
int q = vlan_id > 0 ? (vlan_id - 1) % NUM_TX_QUEUES : 0;

/* Ahora */
uint8_t pcp = (ntohs(vhdr->h_vlan_TCI) >> 13) & 0x07;
int q = pcp;  /* PCP 0-7 mapea directamente a cola 0-7 */
```

`NUM_TX_QUEUES` se amplió a 8 para representar el estándar completo. Para el experimento del TFG solo se usan las colas 0 y 1; las colas 2-7 existen pero el GCL nunca abre sus puertas.

##### Topología: marcado de PCP con egress-qos-map

Para generar tráfico con PCP=0 y PCP=1 desde hping3 (que no permite configurar PCP directamente) se exploró el uso de `tc skbedit priority` sobre una interfaz VLAN única, pero falló por módulos del kernel no disponibles en el entorno.

Solución adoptada: **dos interfaces VLAN con distintos VLAN IDs, cada una con `egress-qos-map` fijo**:
- `h1-eth0.100` con `egress-qos-map 0:0` → todo el tráfico sale con PCP=0
- `h1-eth0.101` con `egress-qos-map 0:1` → todo el tráfico sale con PCP=1

El mecanismo `egress-qos-map` del driver VLAN de Linux traduce `skb->priority` al campo PCP de la etiqueta 802.1Q al construirla. Con `0:1` se fuerza que cualquier paquete (que tiene `skb->priority=0` por defecto) salga con PCP=1. El bridge clasifica por PCP, no por VLAN ID, así que el resultado es funcionalmente equivalente a tener una sola VLAN con dos clases de tráfico.

##### Resultados — GCL asimétrico 9ms/1ms con clasificación por PCP

| Métrica | PCP=0 (cola 0, 9ms) | PCP=1 (cola 1, 1ms) |
|---|---|---|
| Muestras | 1000 | 999 |
| Mínimo | 0.2ms | 0.4ms |
| Media | 2.5ms | 6.9ms |
| p50 | 1.5ms | 6.0ms |
| p95 | 3.0ms | 10.4ms |
| p99 | 3.5ms | 11.3ms |

**Diferencia de medias: 4.4ms.** El gating se demuestra con la nueva clasificación por PCP. Histograma de PCP=1 uniforme entre 0 y 11ms (firma del gating: todos los tiempos de espera son equiprobables dentro del ciclo de 10ms).

#### Comandos clave
```bash
# Lanzar los dos flujos concurrentes desde xterm de h1
hping3 -1 -I h1-eth0.100 10.0.0.2 -i u700 -c 1000 > /tmp/pcp0.txt 2>&1 &
hping3 -1 -I h1-eth0.101 10.0.1.2 -i u700 -c 1000 > /tmp/pcp1.txt 2>&1 &
wait

# Analizar resultados
python3 scripts/analyze_latency.py
```

