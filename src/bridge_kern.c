#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include "shared_defs.h" 

// Mapa que almacenará los descriptores de los sockets XSK para cada cola de la NIC.
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, MAX_SOCKETS); // Capacidad para 1024 sockets
    __type(key, __u32); // Indexaremos los sockets según el número de cola (0, 1, 2, ...)
    __type(value, __u32); // Descriptor del socket XSK
} xsk_map SEC(".maps");

struct hdr_cursor {
    void *pos;
};

SEC("xdp")
int bridge_prog(struct xdp_md *ctx) {
    // Primero obtenemos el índice del mapa del socket XSK correspondiente a la cola
    __u32 index = ctx->ingress_ifindex; // Índice de la interfaz de entrada

    // Verificación de tamaño de paquete para que sea superior al tamaño mínimo de Ethernet
    // Para castear a void, primero convertimos a long ya que en x86_64 los punteros son de 64 bits y los de la estructura xdp_md son de 32 bits
    void *data = (void *)(long)ctx->data; // dirección de inicio del paquete
    void *data_end = (void *)(long)ctx->data_end; // dirección de fin del paquete
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }

    return bpf_redirect_map(&xsk_map, index, XDP_PASS); // Redirigimos el paquete al socket XSK correspondiente
}


    

char __license[] SEC("license") = "GPL";