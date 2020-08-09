#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("nvme_ndpm")
int nvme_ndpm(struct nvme_ndp_context *ctx)
{
	int i;
	char *in = ctx->in_data;
	unsigned int *n_newlines, *n_words;
	
	if (ctx->out_data_len < 8) {
		// need two u32
		return 1;
	}

	n_newlines = (unsigned int *)ctx->out_data;
	n_words = (unsigned int *)ctx->out_data + 1;

	for (i = 0; i < ctx->in_data_len; ++i) {
		if (in[i] == '\n') { *n_newlines++; *n_words++; }
		if (in[i] == ' ') { *n_words++; }
	}

	ctx->flag = 1;
	return 0;
}
char _license[] SEC("license") = "GPL";