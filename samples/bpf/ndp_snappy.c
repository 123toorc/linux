#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef __inline
# define __inline                         \
   inline __attribute__((always_inline))
#endif

#define LITERAL 0
#define COPY_1_BYTE_OFFSET 1
#define COPY_2_BYTE_OFFSET 2
#define COPY_4_BYTE_OFFSET 3

static __inline u16 char_table(int i) {
	int type = i % 4;
	int v = i / 4;
	if (type == 0) {
		if (v == 0x3c) return 0x0801;
		if (v == 0x3d) return 0x1001;
		if (v == 0x3e) return 0x1801;
		if (v == 0x3f) return 0x2001;
		return v + 1;
	}

	if (type == 1) {
		int b = v % 8 + 4;
		int a = (v / 8 + 8) << 8;
		return a + b;
	}

	return ((type - 1) << 12) + v + 1;
}

struct source {
	const char *ptr;
	size_t left;
};

struct writer {
	char *base;
	char *op;
	char *op_limit;
};

static __inline void movedata(void *dest, const void* src, u32 len)
{
	int i = 0;
	char *d = (char*)dest, *s = (char*)src;
	for (i = 0; i < len; ++i) {
		d[i] = s[i];
	}
}

static __inline void writer_set_expected_length(struct writer *w, size_t len)
{
	w->op_limit = w->op + len;
}

static __inline bool writer_append_from_self(struct writer *w, u32 offset,
					   u32 len)
{
	char *const op = w->op;
	const u32 space_left = w->op_limit - op;

	if (op - w->base <= offset - 1u)
		return false;
	if (space_left < len)
		return false;

	movedata(op, op - offset, len);
	w->op = op + len;
	return true;
}

static __inline bool writer_append(struct writer *w, const char *ip, u32 len)
{
	char *const op = w->op;
	const u32 space_left = w->op_limit - op;
	if (space_left < len)
		return false;
	movedata(op, ip, len);
	w->op = op + len;
	return true;
}

struct snappy_decompressor {
	struct source *reader;	/* Underlying source of bytes to decompress */
	const char *ip;		/* Points to next buffered byte */
	const char *ip_limit;	/* Points just past buffered bytes */
	u32 peeked;		/* Bytes peeked from reader (need to skip) */
	bool eof;		/* Hit end of input without an error? */
	char scratch[5];	/* Temporary buffer for peekfast boundaries */
};

static __inline const char *peek(struct source *s, size_t * len)
{
	*len = s->left;
	return s->ptr;
}

static __inline void skip(struct source *s, size_t n)
{
	s->left -= n;
	s->ptr += n;
}

static __inline void
init_snappy_decompressor(struct snappy_decompressor *d, struct source *reader)
{
	d->reader = reader;
	d->ip = NULL;
	d->ip_limit = NULL;
	d->peeked = 0;
	d->eof = false;
}

static __inline bool read_uncompressed_length(struct snappy_decompressor *d,
				     u32 * result)
{
	*result = 0;
	u32 shift = 0;
	while (true) {
		if (shift >= 32)
			return false;
		size_t n;
		const char *ip = peek(d->reader, &n);
		if (n == 0)
			return false;
		const unsigned char c = *(const unsigned char *)(ip);
		skip(d->reader, 1);
		*result |= (u32) (c & 0x7f) << shift;
		if (c < 128) {
			break;
		}
		shift += 7;
	}
	return true;
}

static __inline bool refill_tag(struct snappy_decompressor *d)
{
	const char *ip = d->ip;

	if (ip == d->ip_limit) {
		size_t n;
	
		skip(d->reader, d->peeked);
		ip = peek(d->reader, &n);
		d->peeked = n;
		if (n == 0) {
			d->eof = true;
			return false;
		}
		d->ip_limit = ip + n;
	}

	const unsigned char c = *(const unsigned char *)(ip);
	const u32 entry = char_table(c);
	const u32 needed = (entry >> 11) + 1;

	u32 nbuf = d->ip_limit - ip;

	if (nbuf < needed) {
		movedata(d->scratch, ip, nbuf);
		skip(d->reader, d->peeked);
		d->peeked = 0;
		while (nbuf < needed) {
			size_t length;
			const char *src = peek(d->reader, &length);
			if (length == 0)
				return false;
			u32 to_add = (needed - nbuf) < length ? (needed - nbuf) : length;
			movedata(d->scratch + nbuf, src, to_add);
			nbuf += to_add;
			skip(d->reader, to_add);
		}

		d->ip = d->scratch;
		d->ip_limit = d->scratch + needed;
	} else if (nbuf < 5) {
		movedata(d->scratch, ip, nbuf);
		skip(d->reader, d->peeked);
		d->peeked = 0;
		d->ip = d->scratch;
		d->ip_limit = d->scratch + nbuf;
	} else {
		d->ip = ip;
	}
	return true;
}

static __inline void decompress_all_tags(struct snappy_decompressor *d,
				struct writer *writer)
{
	const u32 wordmask[] = {
		0u, 0xffu, 0xffffu, 0xffffffu, 0xffffffffu
	};
	const char *ip = d->ip;

#define MAYBE_REFILL() \
        if (d->ip_limit - ip < 5) {		\
		d->ip = ip;			\
		if (!refill_tag(d)) return;	\
		ip = d->ip;			\
        }


	MAYBE_REFILL();
	for (;;) {
		if (d->ip_limit - ip < 5) {
			d->ip = ip;
			if (!refill_tag(d))
				return;
			ip = d->ip;
		}

		const unsigned char c = *(const unsigned char *)(ip++);

		if ((c & 0x3) == LITERAL) {
			u32 literal_length = (c >> 2) + 1;
			if (literal_length >= 61) {
				const u32 literal_ll = literal_length - 60;
				literal_length = (*((u32 *)(ip)) &
						  wordmask[literal_ll]) + 1;
				ip += literal_ll;
			}

			u32 avail = d->ip_limit - ip;
			while (avail < literal_length) {
				if (!writer_append(writer, ip, avail))
					return;
				literal_length -= avail;
				skip(d->reader, d->peeked);
				size_t n;
				ip = peek(d->reader, &n);
				avail = n;
				d->peeked = avail;
				if (avail == 0)
					return;
				d->ip_limit = ip + avail;
			}
			if (!writer_append(writer, ip, literal_length))
				return;
			ip += literal_length;
			MAYBE_REFILL();
		} else {
			const u32 entry = char_table(c);
			const u32 trailer = *((u32 *)(ip)) &
				wordmask[entry >> 11];
			const u32 length = entry & 0xff;
			ip += entry >> 11;

			const u32 copy_offset = entry & 0x700;
			if (!writer_append_from_self(writer,
						     copy_offset + trailer,
						     length))
				return;
			MAYBE_REFILL();
		}
	}
}

#undef MAYBE_REFILL

static __inline int internal_uncompress(struct source *r,
			       struct writer *writer, u32 max_len)
{
	struct snappy_decompressor decompressor;
	u32 uncompressed_len = 0;

	init_snappy_decompressor(&decompressor, r);

	if (!read_uncompressed_length(&decompressor, &uncompressed_len))
		return 1;

	if ((u64) (uncompressed_len) > max_len)
		return 1;

	writer_set_expected_length(writer, uncompressed_len);

	decompress_all_tags(&decompressor, writer);
	
	return 0;
}

int module(struct nvme_ndp_context *ctx)
{
	struct source reader = {
		.ptr = ctx->in_data,
		.left = ctx->in_data_len
	};
	struct writer output = {
		.base = ctx->out_data,
		.op = ctx->out_data
	};

	ctx->flag = 1;
	return internal_uncompress(&reader, &output, ctx->out_data_len);
}
char _license[] SEC("license") = "GPL";