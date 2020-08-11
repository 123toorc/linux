#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("nvme_ndpm")
int module(struct nvme_ndp_context *ctx)
{

	ctx->flag = 1;
	return 0;
}
char _license[] SEC("license") = "GPL";