#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

// struct bpf_map_def SEC("maps") my_map = {
//         .type = BPF_MAP_TYPE_ARRAY,
//         .key_size = sizeof(u32),
//         .value_size = sizeof(long),
//         .max_entries = 128,
// };

SEC("ndp1")
int bpf_prog(void * ctx)
{
	int index = 0;
	long *value;
    
    ctx[0] = 'A';

	return 0;
}
char _license[] SEC("license") = "GPL";