#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define PATTERN "search_pattern"
#define PATTERN_LEN 14

SEC("nvme_ndpm")
int module(struct nvme_ndp_context *ctx)
{
	unsigned int i, j, k, o = 0, b = 0;
	char *in = ctx->in_data;
	char *out = ctx->out_data;
	unsigned int len = ctx->out_data_len;
    char skipping = 0;

    const char *pattern = PATTERN;
    ctx->flag = 1;

	for (i = 0; i < ctx->in_data_len; ++i) {
		if (skipping) {
            if (in[i] == '\n') {
                skipping = 0;
                for (k = b; k < i; ++k) {
                    if (o >= len - 1) return 0;
                    out[o++] = in[k];
                }
                if (o >= len - 1) return 0;
                out[o++] = '\n';
            }
        } else {
            skipping = 1;
            for (j = 0; j < PATTERN_LEN; ++j) {
                if (i+j >= ctx->in_data_len || in[i+j] != pattern[j]) {
                    skipping = 0;
                    break;
                }
            }
        }
        if (in[i] == '\n') {
            b = i + 1;
        }
	}

    if (skipping) {
        for (k = b; k < ctx->in_data_len; ++k) {
            if (o >= len - 1) return 0;
            out[o++] = in[k];
        }
        if (o >= len - 1) return 0;
        out[o++] = '\n';
    }
	return 0;
}
char _license[] SEC("license") = "GPL";