#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

// struct bpf_map_def SEC("maps") my_map = {
//         .type = BPF_MAP_TYPE_ARRAY,
//         .key_size = sizeof(u32),
//         .value_size = sizeof(long),
//         .max_entries = 128,
// };

SEC("ndp1")
int bpf_prog(struct nvme_ndp_data *ctx)
{
	int i = 0;
	char *in = ctx->in_data;
	char *out = ctx->out_data;

	for (int i = 0; i < 1024; i++) {
		out[i] = 'K';
	}

	return 0;
}
char _license[] SEC("license") = "GPL";