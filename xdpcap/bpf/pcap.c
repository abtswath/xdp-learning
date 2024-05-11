// clang-format off
//go:build ignore

// clang-format on
#include <asm-generic/int-ll64.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <bpf/bpf_helpers.h>
#include <linux/stddef.h>
#include <string.h>
#include <sys/cdefs.h>

#define MAX_CPUS 128
#define min(x, y) ((x) < (y) ? (x) : (y))

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, __u32);
    __uint(max_entries, MAX_CPUS);
} packet_perf SEC(".maps");

struct hdr_cursor {
    void *pos;
};

struct metadata {
    __u16 pkt_len;
};

static __always_inline int validate_ethernet(void *data, void *data_end) {
    if (data + sizeof(struct ethhdr) > data_end) {
        return 0;
    }
    struct ethhdr *eth = data;
    return eth->h_proto == bpf_htons(ETH_P_IP) ||
           eth->h_proto == bpf_htons(ETH_P_IPV6);
}

SEC("xdp")
int capture_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (!validate_ethernet(data, data_end)) {
        goto out;
    }

    __u64 flags = BPF_F_CURRENT_CPU;
    __u16 sample_size = (__u16)(data_end - data);

    flags |= (__u64)sample_size << 32;

    struct metadata metadata = {
        .pkt_len = sample_size,
    };

    int ret = bpf_perf_event_output(ctx, &packet_perf, flags, &metadata,
                                    sizeof(metadata));
    if (ret) {
        bpf_printk("perf_event_output falied: %d", ret);
    }

out:
    return XDP_PASS;
}
