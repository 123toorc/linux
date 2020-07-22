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
	int i;
	char *in = ctx->in_data;
	char *out = ctx->out_data;
	
	if (ctx->op) {
		// WRITE
		for (i = 0; i < 1024; i++) {
			out[i] = 'K';
		}
	} else {
		// READ
		for (i = 0; i < 4096; i++) {
			out[i] = i < 512 ? 'Y' : in[i];
		}
	}

	return 0;
}
char _license[] SEC("license") = "GPL";