#include <linux/bpf.h>
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

