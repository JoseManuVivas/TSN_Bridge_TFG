#include <linux/bpf.h>
#include <linux/if_link.h>
#include <errno.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include <sys/socket.h>
#include <signal.h>
#include <poll.h>
#include <unistd.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "shared_defs.h"

static bool exiting = false;

// Manejador de la señal (Ctrl+C)
static void signal_handler(int sig) {
    exiting = true;
}

// Estructura para almacenar información sobre la UMEM.
struct xsk_umem_info {
    struct xsk_ring_prod fq; // Fill Ring
    struct xsk_ring_cons cq; // Completion Ring
    struct xsk_umem *umem; // Puntero a la UMEM
    void *buffer; // Puntero a la dirección inicial de memoria reservada para la UMEM
};

// Estructura para almacenar información sobre el socket XSK.
struct xsk_socket_info {
    struct xsk_ring_cons rx; // RX Ring
    struct xsk_ring_prod tx; // TX Ring
    struct xsk_umem_info *umem; // Puntero a la UMEM asociada a este socket
    struct xsk_socket *xsk; // Puntero al socket XSK

    // Para gestión de memoria

    // En XDP cada segundo cuenta. Por ello, para la gestión de frames libres usamos la 
    // estructura más eficiente, una pila LIFO, que simepre apuntará al último frame libre
    uint64_t umem_frame_addr[NUM_FRAMES]; // Array para almacenar las direcciones de cada frame
    uint32_t umem_frame_free; // Contador que apunta al ultimo frame libre
    uint32_t umem_frame_origin; // Dentro de todos los frames, el índice del primer frame gestionado por este socket

    uint32_t outstanding_tx; // Contador de frames enviados que aún no han llegado al Kernel.

};

// Funciones auxiliares de gestión de frames

// Función para sacar un frame de la lista de frames libres y devolver su dirección.
static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
    if (xsk->umem_frame_free == 0) {
        // No hay frames libres
        return UINT64_MAX; // Valor especial para indicar que no hay frames disponibles
    }
    return xsk->umem_frame_addr[--xsk->umem_frame_free]; // Devolvemos la dirección del frame libre y actualizamos el contador
}

// Función para liberar un frame, añadiéndolo de nuevo a la lista de frames libres.
static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
    // Si falla esta condición, a la mierda, porque estamos intentando liberar más frames de los que tenemos o liberar un frame que no pertenece a esta UMEM
	assert(xsk->umem_frame_free < NUM_FRAMES);

    // Añadimos el frame a la lista de frames libres y actualizamos el contador
	xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

// Función para configurar el socket XSK.
static struct xsk_socket_info *xsk_configure_socket(const char *ifname)
{
    struct xsk_socket_config xsk_cfg; // Estructura que almacena configuraciones del socket
    struct xsk_socket_info *xsk_info; // Puntero a la estructura xsk_socket_info

    int ret;

    // Reservamos memoria para la estructura xsk_socket_info
    xsk_info = calloc(1, sizeof(*xsk_info));
    if (!xsk_info) return NULL;

    // Ahora tocará crear la UMEM (cambio radical)
    uint64_t buffer_size = (uint64_t)NUM_FRAMES * FRAME_SIZE; // Tamaño total de la memoria para la UMEM
    void *buffer; // es void porque todavía no sabemos lo que es, son bytes crudos

    // Reservamos la memoria
    if (posix_memalign(&buffer, getpagesize(), buffer_size)) return NULL;

    // Dado que ya no la pasamos como argumento, debemos reservar la memoria en el heap
    xsk_info->umem = calloc(1, sizeof(struct xsk_umem_info));
    xsk_info->umem->buffer = buffer;

    ret = xsk_umem__create(&xsk_info->umem->umem, buffer, buffer_size, 
                           &xsk_info->umem->fq, &xsk_info->umem->cq, NULL);
    if (ret) return NULL;

    // Asignamos los flags de configuración del socket
    xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xsk_cfg.xdp_flags = XDP_FLAGS_SKB_MODE; 
    xsk_cfg.bind_flags = 0;


    // Para no cargar el programa XDP otra vez, ya se hará manualmente.
    xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;

    // Creamos el socket XSK
    ret = xsk_socket__create(&xsk_info->xsk, ifname, 0, 
                             xsk_info->umem->umem, &xsk_info->rx, &xsk_info->tx, &xsk_cfg);
    if (ret) { goto error_exit; }

    // Inicializar la lista de frames
    for (int i = 0; i < NUM_FRAMES; i++) {
        xsk_info->umem_frame_addr[i] = (uint64_t)i * FRAME_SIZE; 
    }

    // Inicialmente todos los frames están libres
    xsk_info->umem_frame_free = NUM_FRAMES;

    return xsk_info;
    
    error_exit:
        // Capturamos el error antes de liberar nada
        int save_errno = -ret; 
        if (xsk_info) {
            if (xsk_info->xsk) xsk_socket__delete(xsk_info->xsk);
            free(xsk_info);
        }
        errno = save_errno;
        return NULL;
}

// Función de "gasolina", recargar continuamente el Fill Ring para asegurarnos que siempre hay
static void handle_fill_ring(struct xsk_socket_info *xsk)
{
    uint32_t idx;
    unsigned int i, to_fill;

    to_fill = 64; // tamaño de ráfaga bastante común
    // Reservamos esos huecos en el Fill Ring
    if (xsk_ring_prod__reserve(&xsk->umem->fq, to_fill, &idx) != to_fill)
        return;

    // Vamos retirando los frames de nuestra pila y añadiendolos al Fill Ring
    for (i = 0; i < to_fill; i++) {

        // Sacamos la dirección del frame libre
        uint64_t addr = xsk_alloc_umem_frame(xsk);
        if (addr == UINT64_MAX) break; // Por si nos quedamos sin frames en la pila
        
        // Añadimos la dirección al Fill Ring
        *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx++) = addr;
    }

    // Hacemos commit
    xsk_ring_prod__submit(&xsk->umem->fq, i);
}

// Función para revisar el Completion Ring de un socket y devolver los frames pertinentes a la pila del socket
static void handle_tx_completion(struct xsk_socket_info *xsk) 
{
    uint32_t idx_cq;
    unsigned int completed, i;

    // Comprobamos si hay algun descriptor en el completion ring, indicando que ha sido completado
    completed = xsk_ring_cons__peek(&xsk->umem->cq, 64, &idx_cq);
    if (!completed)
        return;

     for (i = 0; i < completed; i++) {
        
        // Obtenemos la dirección del primer frame completado
        uint64_t addr = *xsk_ring_cons__comp_addr(&xsk->umem->cq, idx_cq++);
   
        xsk_free_umem_frame(xsk, addr);
        // No nos olvidemos de actualizar el contador de frames pendientes de enviar
        if (xsk->outstanding_tx > 0) xsk->outstanding_tx--;

    }   

    // Liberamos los descriptores deL Completion Ring
    xsk_ring_cons__release(&xsk->umem->cq, completed);
}


// Función para procesar la recepción de paquetes por un socket y reenviarlos por el otro.
// Ya no hay Zero Copy, ahora usaremos memcpy
static void process_rx_and_forward(struct xsk_socket_info *rx_socket,
                                   struct xsk_socket_info *tx_socket)
{
    uint32_t idx_rx, idx_tx;
    unsigned int rcvd, packets_to_submit = 0;

    // Miramos si hay paquetes esperando en el RX Ring del socket A
    // Tomaremos como máximo ráfagas de 64 paquetes
    rcvd = xsk_ring_cons__peek(&rx_socket->rx, 64, &idx_rx);
    if (!rcvd) {
        // No hay paquetes por procesar
        return;
    }

    printf("DEBUG: He capturado %u paquetes. Reenvio\n", rcvd);

    // Intentamos reservar el mismo número de entradas en el TX Ring del socket B
    if (xsk_ring_prod__reserve(&tx_socket->tx, rcvd, &idx_tx) != rcvd) {

        // Si no hay espacio lo que mas cunde es liberar el RX Ring para no bloquear
        // Mejor perder paquetes que mandar a la mierda el programa
        xsk_ring_cons__release(&rx_socket->rx, rcvd);
        return;
    }

    // Copia de frames de la UMEM del socket RX al socket TX, actualizando los descriptores del TX Ring
    for (unsigned int i = 0; i < rcvd; i++) {

        // Definimos los descriptores de RX y TX para este paquete
        const struct xdp_desc *rx_desc = xsk_ring_cons__rx_desc(&rx_socket->rx, idx_rx++);

        // ¡¡LA MAGIA NEGRA!! Limpiamos la dirección (le quitamos el offset) para no envenenar el Kernel
        uint64_t clean_rx_addr = rx_desc->addr & ~((uint64_t)FRAME_SIZE - 1);

        // Comprobación de seguridad
        if (rx_desc->len > FRAME_SIZE || rx_desc->len == 0) {
            xsk_free_umem_frame(rx_socket, clean_rx_addr); // Usamos la limpia
            continue; 
        }

        struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&tx_socket->tx, idx_tx++);

        // Para LEER los datos, SÍ usamos la original (con el offset)
        void *rx_data = xsk_umem__get_data(rx_socket->umem->buffer, rx_desc->addr);
        
        uint64_t new_addr = xsk_alloc_umem_frame(tx_socket);
        if (new_addr == UINT64_MAX) {
            xsk_free_umem_frame(rx_socket, clean_rx_addr); // Usamos la limpia
            break; 
        }
        
        void *tx_data = xsk_umem__get_data(tx_socket->umem->buffer, new_addr);

        // Copiamos el contenido
        memcpy(tx_data, rx_data, rx_desc->len);

        // Configuramos TX (las nuevas direcciones siempre están limpias de serie)
        tx_desc->addr = new_addr;
        tx_desc->len = rx_desc->len;

        packets_to_submit++;
        tx_socket->outstanding_tx++;
        
        // Devolvemos LA LIMPIA a nuestra UMEM
        xsk_free_umem_frame(rx_socket, clean_rx_addr);
    }

    // Liberamos los descriptores del RX Ring
    xsk_ring_cons__release(&rx_socket->rx, rcvd);

    // ENVIAMOS SOLO LO QUE HEMOS ESCRITO
    if (packets_to_submit > 0) {
        xsk_ring_prod__submit(&tx_socket->tx, packets_to_submit);
        if (xsk_ring_prod__needs_wakeup(&tx_socket->tx)) {
            sendto(xsk_socket__fd(tx_socket->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        }
    }

}

int main() {

    // Capturamos Ctrl+C(SIGINT) para salir limpiamente
    signal(SIGINT, signal_handler);

    // Definimos los dos sockets
    struct xsk_socket_info *xsk_A = xsk_configure_socket("s1-eth1");
    struct xsk_socket_info *xsk_B = xsk_configure_socket("s1-eth2");

    if (!xsk_A || !xsk_B) {
        fprintf(stderr, "Error inicializando sockets. ¿Ulimit? ¿Interfaces?\n");
        return 1;
    }

    // Cebamos el fill ring de las dos UMEM
    for (int i = 0; i < 16; i++) { // Metemos 64 * 16 = 1024 frames al principio
    handle_fill_ring(xsk_A);
    handle_fill_ring(xsk_B);
}

    // Cargamos dos programas XDP, uno por interfaz, asignándoles el socket correspondiente y creándoles un mapa
    struct xdp_program *prog_A = xdp_program__open_file("build/bridge_kern.o", "xdp", NULL);
    xdp_program__attach(prog_A, if_nametoindex("s1-eth1"), XDP_MODE_SKB, 0);
    
    // MAPA A
    // Obtener el mapa exclusivo del Programa A y poner el Socket A en el índice 0
    int map_fd_A = bpf_map__fd(bpf_object__find_map_by_name(xdp_program__bpf_obj(prog_A), "xsk_map"));
    uint32_t key = if_nametoindex("s1-eth1"); // Índice de la interfaz s1-eth1, que es el que usará el programa A para redirigir los paquetes
    int fd_A = xsk_socket__fd(xsk_A->xsk);
    bpf_map_update_elem(map_fd_A, &key, &fd_A, BPF_ANY);

    // MAPA B
    // Al llamar a open_file otra vez, creamos una SEGUNDA instancia de todo
    struct xdp_program *prog_B = xdp_program__open_file("build/bridge_kern.o", "xdp", NULL);
    xdp_program__attach(prog_B, if_nametoindex("s1-eth2"), XDP_MODE_SKB, 0);
    
    // Obtener el mapa exclusivo del Programa B y poner el Socket B en el índice 0
    int map_fd_B = bpf_map__fd(bpf_object__find_map_by_name(xdp_program__bpf_obj(prog_B), "xsk_map"));
    key = if_nametoindex("s1-eth2"); // Índice de la interfaz s1-eth2
    int fd_B = xsk_socket__fd(xsk_B->xsk);
    bpf_map_update_elem(map_fd_B, &key, &fd_B, BPF_ANY);

    struct pollfd fds[2] = { {.fd = fd_A, .events = POLLIN}, {.fd = fd_B, .events = POLLIN} };

    printf("Bridge iniciado (Arquitectura UMEM Independiente). Ctrl+C para salir.\n");
    while (!exiting) {
        if (poll(fds, 2, 10) <= 0) continue;
        if (fds[0].revents & POLLIN) process_rx_and_forward(xsk_A, xsk_B);
        if (fds[1].revents & POLLIN) process_rx_and_forward(xsk_B, xsk_A);
        handle_tx_completion(xsk_A); handle_tx_completion(xsk_B);
        handle_fill_ring(xsk_A); handle_fill_ring(xsk_B);
    }

    printf("Limpiando y saliendo...\n");
    return 0;
}