/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/in.h>

/* Registro de timestamp: numero de secuencia ICMP + instante de llegada */
struct ts_record {
	__u64 ts_ns;
	__u16 pkt_seq;
	__u16 vlan_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB */
} ts_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* --- Timestamp ICMP (best-effort, no bloquea el forwarding) --- */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) <= data_end) {
		__u16 proto   = eth->h_proto;
		void *next    = (void *)(eth + 1);
		__u16 vlan_id = 0;

		/* Desencapsular VLAN 802.1Q si la hay */
		if (proto == bpf_htons(ETH_P_8021Q) && next + 4 <= data_end) {
			vlan_id = bpf_ntohs(*(__u16 *)next) & 0x0FFF;
			proto   = *(__u16 *)(next + 2);
			next   += 4;
		}

		if (proto == bpf_htons(ETH_P_IP)) {
			struct iphdr *ip = next;
			if ((void *)(ip + 1) <= data_end && ip->protocol == IPPROTO_ICMP) {
				/* Asumimos IHL=5 (sin opciones IP) */
				struct icmphdr *icmp = (void *)ip + sizeof(struct iphdr);
				if ((void *)(icmp + 1) <= data_end) {
					struct ts_record *rec = bpf_ringbuf_reserve(&ts_map, sizeof(*rec), 0);
					if (rec) {
						rec->ts_ns    = bpf_ktime_get_ns();
						rec->pkt_seq = bpf_ntohs(icmp->un.echo.sequence);
						rec->vlan_id  = vlan_id;
						bpf_ringbuf_submit(rec, 0);
					}
				}
			}
		}
	}

	/* --- Forwarding a AF_XDP --- */
	int index = ctx->rx_queue_index;
	if (bpf_map_lookup_elem(&xsks_map, &index))
		return bpf_redirect_map(&xsks_map, index, 0);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
