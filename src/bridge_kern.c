#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>

struct hdr_cursor {
    void *pos;
};

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh;
    nh.pos = data;
    // Línea de debug para verificar que se está ejecutando el programa XDP
    bpf_printk("Programa XDP ejecutado!!\n");
    return XDP_PASS;
}
    

char __license[] SEC("license") = "GPL";