#include <linux/bpf.h>
#include <errno.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include "shared_defs.h"

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
