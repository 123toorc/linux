#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("nvme_ndpm")
int nvme_ndpm(struct nvme_ndp_context *ctx)
{
	int i;
	char *in = ctx->in_data;
	char *out = ctx->out_data;
	unsigned int len = ctx->out_data_len;
	
	if (ctx->op) {
		// WRITE
		for (i = 0; i < len; i++) {
			out[i] = 'K';
		}
	} else {
		// READ
		for (i = 0; i < 4096; i++) {
			out[i] = i < 512 ? 'Y' : in[i];
		}
	}

	ctx->flag = 1;
	return 0;
}
char _license[] SEC("license") = "GPL";