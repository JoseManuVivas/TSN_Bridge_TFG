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

// Función para configurar la UMEM.
static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{

    // Creamos el puntero que apuntará a la estructura xsk_umem_info
	struct xsk_umem_info *umem;
	int ret;
    // Reservamos memoria para la estructura xsk_umem_info
    // Usamos calloc que es la versión limpia de malloc, reserva memoria e inicializa a 0
	umem = calloc(1, sizeof(*umem));

	if (!umem)
		return NULL;

    
    // Creamos la UMEM
	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       NULL);

    // Verificamos si la creación de la UMEM fue exitosa               
	if (ret) {
		errno = -ret;
		return NULL;
	}

    // Como xsk_umem_create no asigna el buffer a xsk_umem_info lo hacemos a mano
	umem->buffer = buffer;
	return umem;
}

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
static struct xsk_socket_info *xsk_configure_socket(struct xsk_umem_info *umem,
                                                    const char *ifname, 
                                                    uint32_t queue,
                                                    uint64_t frame_offset)
{
    struct xsk_socket_config xsk_cfg; // Estructura que almacena configuraciones del socket
    struct xsk_socket_info *xsk_info; // Puntero a la estructura xsk_socket_info

    // Este es el puntero que indexará el cebado del Fill Ring, al pasarselo a una función determinada
    // apuntará inteligentemente al primer frame libre, y se irá actualizando a medida que se vayan usando frames
    uint32_t idx;
    int i, ret;

    // Reservamos memoria para la estructura xsk_socket_info
    xsk_info = calloc(1, sizeof(*xsk_info));
    if (!xsk_info) return NULL;

    xsk_info->umem = umem; // Asociamos la UMEM al socket

    // Asignamos los flags de configuración del socket
    xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xsk_cfg.xdp_flags = XDP_FLAGS_SKB_MODE; 
    xsk_cfg.bind_flags = 0;

    // Para no cargar el programa XDP otra vez, ya se hará manualmente.
    xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;

    // Creamos el socket XSK
    ret = xsk_socket__create(&xsk_info->xsk, ifname, queue, 
                             umem->umem, &xsk_info->rx, &xsk_info->tx, &xsk_cfg);
    if (ret) { goto error_exit; }

    // Reparto de frames entre sockets
    uint32_t num_frames_per_socket = NUM_FRAMES / 2; // Hardcodeado para 2 sockets
    for (i = 0; i < num_frames_per_socket; i++) {
        xsk_info->umem_frame_addr[i] = frame_offset + (uint64_t)i * FRAME_SIZE; 
    }

    // Inicialmente todos los frames están libres
    xsk_info->umem_frame_free = num_frames_per_socket;

    // Cebamos justamente el fill ring
    uint32_t initial_fill = XSK_RING_PROD__DEFAULT_NUM_DESCS / 2;

    // Cebamos el Fill Ring con los frames asignados a este socket
    ret = xsk_ring_prod__reserve(&umem->fq, initial_fill, &idx);

    // Concesión de frames al Kernel
    if (ret == initial_fill) {
        for (i = 0; i < initial_fill; i++) {
            // Sacamos de nuestra pila y lo añadimos al Fill Ring
            *xsk_ring_prod__fill_addr(&umem->fq, idx++) = xsk_alloc_umem_frame(xsk_info);
        }

        // Hacemos commit de los frames añadidos al Fill Ring
        xsk_ring_prod__submit(&umem->fq, initial_fill);
    } else {
        goto error_exit;
    }

    return xsk_info;
    
    error_exit:
        errno = -ret;
        free(xsk_info);
        // Cerramos el socket si se había creado
        if (xsk_info->xsk) xsk_socket__delete(xsk_info->xsk);
        return NULL;

}

// Función para procesar la recepción de paquetes por un socket y reenviarlos por el otro
static void process_rx_and_forward(struct xsk_socket_info *rx_socket,
                                   struct xsk_socket_info *tx_socket)
{
    uint32_t idx_rx, idx_tx;
    unsigned int rcvd, i;

    // Miramos si hay paquetes esperando en el RX Ring del socket A
    // Tomaremos como máximo ráfagas de 64 paquetes
    rcvd = xsk_ring_cons__peek(&rx_socket->rx, 64, &idx_rx);
    if (!rcvd) {
        // No hay paquetes por procesar
        return;
    }

    // Intentamos reservar el mismo número de entradas en el TX Ring del socket B
    if (xsk_ring_prod__reserve(&tx_socket->tx, rcvd, &idx_tx) != rcvd) {

        // Si no hay espacio lo que mas cunde es liberar el RX Ring para no bloquear
        // Mejor perder paquetes que mandar a la mierda el programa
        xsk_ring_cons__release(&rx_socket->rx, rcvd);
        return;
    }

    // Pasamanos de descriptores del RX Ring al TX Ring
    for (i = 0; i < rcvd; i++) {
        // Obtenemos el descriptor (addr y len) del paquete que ha llegado al RX
        const struct xdp_desc *rx_desc = xsk_ring_cons__rx_desc(&rx_socket->rx, idx_rx++);
        
        // Obtenemos el hueco en el anillo de salida (TX)
        struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&tx_socket->tx, idx_tx++);

        // En AF_XDP cada segundo cuenta, por lo que solo copiamos la dirección del paquete y su longitud
        tx_desc->addr = rx_desc->addr;
        tx_desc->len = rx_desc->len;

        // Actualizamos el contador de paquetes que el Kernel tiene pendientes de enviar.
        tx_socket->outstanding_tx++;
    }

    // Liberamos los descriptores del RX Ring
    xsk_ring_cons__release(&rx_socket->rx, rcvd);

    // Enviamos los descriptores al anillo TX
    xsk_ring_prod__submit(&tx_socket->tx, rcvd);

    // Por si las moscas, avisaremos al Kernel de que tiene paquetes
    if (xsk_ring_prod__needs_wakeup(&tx_socket->tx)) {
        // Usamos sendto con un mensaje vacío; es la forma estándar de avisar al socket AF_XDP.
        sendto(xsk_socket__fd(tx_socket->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    }

}

// Función para revisar el Completion Ring de un socket y devolver los frames pertinentes a la pila del socket
static void handle_tx_completion(struct xsk_socket_info *xsk_a, struct xsk_socket_info *xsk_b) 
{
    uint32_t idx_cq;
    unsigned int completed, i;

    // Daba igual usar el socket A o el B porque el Completion Ring es compartido
    completed = xsk_ring_cons__peek(&xsk_a->umem->cq, 64, &idx_cq);
    if (!completed)
        return;

     for (i = 0; i < completed; i++) {
        
        // Obtenemos la dirección del primer frame completado
        uint64_t addr = *xsk_ring_cons__comp_addr(&xsk_a->umem->cq, idx_cq++);

        // Determinamos el límite entre sockets para saber a cuál de las pilas hay que liberarlo
        uint64_t offset_B = (uint64_t)(NUM_FRAMES / 2) * FRAME_SIZE;

        if (addr < offset_B) {
            
            xsk_free_umem_frame(xsk_a, addr);
            // No nos olvidemos de actualizar el contador de frames pendientes de enviar
            if (xsk_a->outstanding_tx > 0) xsk_a->outstanding_tx--;
        } else {
            
            xsk_free_umem_frame(xsk_b, addr);
            if (xsk_b->outstanding_tx > 0) xsk_b->outstanding_tx--;
        }
    }   

    // Liberamos los descriptores deL Completion Ring
    xsk_ring_cons__release(&xsk_a->umem->cq, completed);
}

// Función de "gasolina", recargar continuamente el Fill Ring para asegurarnos que siempre hay
static void handle_fill_ring(struct xsk_socket_info *xsk)
{
    uint32_t idx;
    unsigned int i, to_fill;

    // Miramos cuantos frames libres tiene el Fill Ring (queremos tener hasta 1024 por socket)
    to_fill = xsk_ring_prod__nb_free(&xsk->umem->fq, 1024);
    if (!to_fill)
        return;

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

int main(int argc, char **argv)
{
    // Capturamos Ctrl+C(SIGINT)
    signal(SIGINT, signal_handler);

    // Reservamos memoria para la UMEM
    void *buffer; // es void porque todavía no sabemos lo que es, son bytes crudos
    uint64_t buffer_size = NUM_FRAMES * FRAME_SIZE; // Tamaño total de la memoria para la UMEM

    // Es importante que el tamaño total de la UMEM sea múltiplo del tamaño de página, debido a que esta tendrá
    // que estar alineada
    if (posix_memalign(&buffer, getpagesize(), buffer_size)) {
        fprintf(stderr, "Error reservando memoria alineada\n");
        return 1;
    }

    // Inicializamos la UMEM
    struct xsk_umem_info *umem = configure_xsk_umem(buffer, buffer_size);
    if (!umem) {
        fprintf(stderr, "Error inicializando la UMEM\n");
        return 1;
    }

    // Configuramos los dos sockets(puertos del bridge)
    // (hardcodeamos el nombre de las interfaces)
    struct xsk_socket_info *xsk_A = xsk_configure_socket(umem, "s1-eth1", 0, 0);
    struct xsk_socket_info *xsk_B = xsk_configure_socket(umem, "s1-eth2", 0, (NUM_FRAMES / 2) * FRAME_SIZE);

    if (!xsk_A || !xsk_B) {
        fprintf(stderr, "Error inicializando los sockets\n");
        return 1;
    }

    // Cargar el programa XDP
    struct xdp_program *prog = xdp_program__open_file("bridge_kern.o", "bridge_prog", NULL);
    if (!prog) {
        fprintf(stderr, "Error al abrir el programa BPF bridge_kern.o\n");
        return 1;
    }

    // Attach en modo SKB, el compatible con Mininet
    xdp_program__attach(prog, if_nametoindex("s1-eth1"), XDP_MODE_SKB, 0);
    xdp_program__attach(prog, if_nametoindex("s1-eth2"), XDP_MODE_SKB, 0);

    // Buscamos el mapa (el nombre del mapa esta hardcodeado)
    int map_fd = bpf_map__fd(xdp_program__find_map_by_name(prog, "xsk_map"));
    if (map_fd < 0) {
        fprintf(stderr, "Error: No se encontró el mapa xsk_map en el programa BPF\n");
        return 1;
    }

    // Vinculamos cada socket al mapa usando el ifindex como llave
    uint32_t key_A = if_nametoindex("s1-eth1");
    uint32_t key_B = if_nametoindex("s1-eth2");

    // Obtenemos los descriptores de cada socket
    int fd_A = xsk_socket__fd(xsk_A->xsk);
    int fd_B = xsk_socket__fd(xsk_B->xsk);

    if (bpf_map_update_elem(map_fd, &key_A, &fd_A, BPF_ANY) ||
        bpf_map_update_elem(map_fd, &key_B, &fd_B, BPF_ANY)) {
        fprintf(stderr, "Error actualizando el mapa XSKMAP\n");
        return 1;
    }

    // Configuramos el sistema de polling
    struct pollfd fds[2] = {0};
    fds[0].fd = fd_A;
    fds[0].events = POLLIN;
    fds[1].fd = fd_B;
    fds[1].events = POLLIN;

    printf("Bridge AF_XDP iniciado entre s1-eth1, de ifindex %u, y s1-eth2, de ifindex %u\n", key_A, key_B);
    printf("Presiona Ctrl+C para salir...\n");

    // Bucle principal de reenvío
    while (!exiting) {
        // Esperamos o 100ms o a que haya actividad en alguno de los sockets
        int ret = poll(fds, 2, 100);

        if (ret <= 0) continue;

        // Si entra por A lo mandamos por B y si entra por B lo mandamos por A
        if (fds[0].revents & POLLIN) {
            process_rx_and_forward(xsk_A, xsk_B);
        }

        if (fds[1].revents & POLLIN) {
            process_rx_and_forward(xsk_B, xsk_A);
        }

        // Mantenimiento: revisamos el Completion Ring y recauchutamos el Fill Ring
        handle_tx_completion(xsk_A, xsk_B);
        handle_fill_ring(xsk_A);
        handle_fill_ring(xsk_B);
    }

    // Limpieza final
    printf("Cerrando Bridge y limpiando recursos...\n");

    // Desvinculamos el programa XDP de las interfaces
    xdp_program__detach(prog, if_nametoindex("s1-eth1"), XDP_MODE_SKB, 0);
    xdp_program__detach(prog, if_nametoindex("s1-eth2"), XDP_MODE_SKB, 0);

    // Eliminamos los sockets
    xsk_socket__delete(xsk_A->xsk);
    xsk_socket__delete(xsk_B->xsk);

    // Liberamos la UMEM
    xsk_umem__delete(umem->umem);

    // Liberamos la memoria de las estructuras
    free(buffer);
    free(xsk_A);
    free(xsk_B);
    free(umem);

    printf("Limpieza finalizada. ¡¡Adios!!\n");
    return 0;
} 