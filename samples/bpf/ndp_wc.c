#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("nvme_ndpm")
int module(struct nvme_ndp_context *ctx)
{
	int i;
	char *in = ctx->in_data;
	u32 in_len = ctx->in_data_len;
	u32 *out = ctx->out_data;
	u32 n_newlines, n_words;
	
	if (ctx->out_data_len < 16) {
		// need four u32
		return 1;
	}

	n_newlines = 0;
	n_words = 0;
	for (i = 0; i < ctx->in_data_len; ++i) {
		if (in[i] == '\0') break;
		if (in[i] == '\n') { n_newlines++; n_words++; }
		if (in[i] == ' ') { n_words++; }
	}
	
	out[0] = in_len;
	out[1] = n_newlines;
	out[2] = n_words;
	out[3] = i;

	ctx->flag = 1;
	return 0;
}
char _license[] SEC("license") = "GPL";