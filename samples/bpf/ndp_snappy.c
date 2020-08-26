#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define LITERAL 0
#define COPY_1_BYTE_OFFSET 1
#define COPY_2_BYTE_OFFSET 2
#define COPY_4_BYTE_OFFSET 3

struct source {
	const char *ptr;
	size_t left;
};

struct writer {
	char *base;
	char *op;
	char *op_limit;
};

static u16 char_table(int i) {
	int type = i % 4;
	int v = i / 4;
	if (type == 0) {
		if (v == 0x3d) return 0x0801;
		if (v == 0x3e) return 0x1001;
		if (v == 0x3f) return 0x1801;
		if (v == 0x40) return 0x2001;
		return v;
	}

	if (type == 1) {
		int b = v % 8 + 4;
		int a = (v / 8 + 8) << 8;
		return a + b;
	}

	return ((type - 1) << 12) + v;
}

static inline void copy64(const void *src, void *dst)
{
	*((long*)dst) = *((long*)src);
}

static void incremental_copy_fast_path(const char *src, char *op,
					      int len)
{
	while (op - src < 8) {
		copy64(src, op);
		len -= op - src;
		op += op - src;
	}
	while (len > 0) {
		copy64(src, op);
		src += 8;
		op += 8;
		len -= 8;
	}
}

static void incremental_copy(const char *src, char *op, int len)
{
	do {
		*op++ = *src++;
	} while (--len > 0);
}
static inline void writer_set_expected_length(struct writer *w, size_t len)
{
	w->op_limit = w->op + len;
}

static inline bool writer_check_length(struct writer *w)
{
	return w->op == w->op_limit;
}

static void movedata(void *dest, const void* src, u32 len)
{
	int i = 0;
	char *d = (char*)dest, *s = (char*)src;
	for (i = 0; i < len; ++i) {
		d[i] = s[i];
	}
}

static bool writer_append_from_self(struct writer *w, u32 offset,
					   u32 len)
{
	char *const op = w->op;
	const u32 space_left = w->op_limit - op;

	if (op - w->base <= offset - 1u)	/* -1u catches offset==0 */
		return false;
	if (len <= 16 && offset >= 8 && space_left >= 16) {
		/* Fast path, used for the majority (70-80%) of dynamic
		 * invocations. */
		copy64(op - offset, op);
		copy64(op - offset + 8, op + 8);
	} else {
		if (space_left >= len + 10) {
			incremental_copy_fast_path(op - offset, op, len);
		} else {
			if (space_left < len) {
				return false;
			}
			incremental_copy(op - offset, op, len);
		}
	}

	w->op = op + len;
	return true;
}

static inline bool writer_append(struct writer *w, const char *ip, u32 len)
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

static const char *peek(struct source *s, size_t * len)
{
	*len = s->left;
	return s->ptr;
}

static void skip(struct source *s, size_t n)
{
	s->left -= n;
	s->ptr += n;
}

static void
init_snappy_decompressor(struct snappy_decompressor *d, struct source *reader)
{
	d->reader = reader;
	d->ip = NULL;
	d->ip_limit = NULL;
	d->peeked = 0;
	d->eof = false;
}

static void exit_snappy_decompressor(struct snappy_decompressor *d)
{
	skip(d->reader, d->peeked);
}

static bool read_uncompressed_length(struct snappy_decompressor *d,
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

static bool refill_tag(struct snappy_decompressor *d)
{
	const char *ip = d->ip;

	if (ip == d->ip_limit) {
		size_t n;
		/* Fetch a new fragment from the reader */
		skip(d->reader, d->peeked); /* All peeked bytes are used up */
		ip = peek(d->reader, &n);
		d->peeked = n;
		if (n == 0) {
			d->eof = true;
			return false;
		}
		d->ip_limit = ip + n;
	}

	/* Read the tag character */
	const unsigned char c = *(const unsigned char *)(ip);
	const u32 entry = char_table(c);
	const u32 needed = (entry >> 11) + 1;	/* +1 byte for 'c' */

	/* Read more bytes from reader if needed */
	u32 nbuf = d->ip_limit - ip;

	if (nbuf < needed) {
		/*
		 * Stitch together bytes from ip and reader to form the word
		 * contents.  We store the needed bytes in "scratch".  They
		 * will be consumed immediately by the caller since we do not
		 * read more than we need.
		 */
		movedata(d->scratch, ip, nbuf);
		skip(d->reader, d->peeked); /* All peeked bytes are used up */
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
		/*
		 * Have enough bytes, but move into scratch so that we do not
		 * read past end of input
		 */
		movedata(d->scratch, ip, nbuf);
		skip(d->reader, d->peeked); /* All peeked bytes are used up */
		d->peeked = 0;
		d->ip = d->scratch;
		d->ip_limit = d->scratch + nbuf;
	} else {
		/* Pass pointer to buffer returned by reader. */
		d->ip = ip;
	}
	return true;
}

static void decompress_all_tags(struct snappy_decompressor *d,
				struct writer *writer)
{
	const u32 wordmask[] = {
		0u, 0xffu, 0xffffu, 0xffffffu, 0xffffffffu
	};

	const char *ip = d->ip;

	/*
	 * We could have put this refill fragment only at the beginning of the loop.
	 * However, duplicating it at the end of each branch gives the compiler more
	 * scope to optimize the <ip_limit_ - ip> expression based on the local
	 * context, which overall increases speed.
	 */
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
				/* Long literal */
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
					return;	/* Premature end of input */
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

			/*
			 * copy_offset/256 is encoded in bits 8..10.
			 * By just fetching those bits, we get
			 * copy_offset (since the bit-field starts at
			 * bit 8).
			 */
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

static int internal_uncompress(struct source *r,
			       struct writer *writer, u32 max_len)
{
	struct snappy_decompressor decompressor;
	u32 uncompressed_len = 0;

	init_snappy_decompressor(&decompressor, r);

	if (!read_uncompressed_length(&decompressor, &uncompressed_len))
		return 1;
	/* Protect against possible DoS attack */
	if ((u64) (uncompressed_len) > max_len)
		return 1;

	writer_set_expected_length(writer, uncompressed_len);

	/* Process the entire input */
	decompress_all_tags(&decompressor, writer);

	exit_snappy_decompressor(&decompressor);
	if (writer_check_length(writer))
		return 0;
	return 1;
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