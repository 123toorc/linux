#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define LITERAL 0
#define COPY_1_BYTE_OFFSET 1
#define COPY_2_BYTE_OFFSET 2
#define COPY_4_BYTE_OFFSET 3

static const u32 wordmask[] = {
	0u, 0xffu, 0xffffu, 0xffffffu, 0xffffffffu
};

static const u16 char_table[256] = {
	0x0001, 0x0804, 0x1001, 0x2001, 0x0002, 0x0805, 0x1002, 0x2002,
	0x0003, 0x0806, 0x1003, 0x2003, 0x0004, 0x0807, 0x1004, 0x2004,
	0x0005, 0x0808, 0x1005, 0x2005, 0x0006, 0x0809, 0x1006, 0x2006,
	0x0007, 0x080a, 0x1007, 0x2007, 0x0008, 0x080b, 0x1008, 0x2008,
	0x0009, 0x0904, 0x1009, 0x2009, 0x000a, 0x0905, 0x100a, 0x200a,
	0x000b, 0x0906, 0x100b, 0x200b, 0x000c, 0x0907, 0x100c, 0x200c,
	0x000d, 0x0908, 0x100d, 0x200d, 0x000e, 0x0909, 0x100e, 0x200e,
	0x000f, 0x090a, 0x100f, 0x200f, 0x0010, 0x090b, 0x1010, 0x2010,
	0x0011, 0x0a04, 0x1011, 0x2011, 0x0012, 0x0a05, 0x1012, 0x2012,
	0x0013, 0x0a06, 0x1013, 0x2013, 0x0014, 0x0a07, 0x1014, 0x2014,
	0x0015, 0x0a08, 0x1015, 0x2015, 0x0016, 0x0a09, 0x1016, 0x2016,
	0x0017, 0x0a0a, 0x1017, 0x2017, 0x0018, 0x0a0b, 0x1018, 0x2018,
	0x0019, 0x0b04, 0x1019, 0x2019, 0x001a, 0x0b05, 0x101a, 0x201a,
	0x001b, 0x0b06, 0x101b, 0x201b, 0x001c, 0x0b07, 0x101c, 0x201c,
	0x001d, 0x0b08, 0x101d, 0x201d, 0x001e, 0x0b09, 0x101e, 0x201e,
	0x001f, 0x0b0a, 0x101f, 0x201f, 0x0020, 0x0b0b, 0x1020, 0x2020,
	0x0021, 0x0c04, 0x1021, 0x2021, 0x0022, 0x0c05, 0x1022, 0x2022,
	0x0023, 0x0c06, 0x1023, 0x2023, 0x0024, 0x0c07, 0x1024, 0x2024,
	0x0025, 0x0c08, 0x1025, 0x2025, 0x0026, 0x0c09, 0x1026, 0x2026,
	0x0027, 0x0c0a, 0x1027, 0x2027, 0x0028, 0x0c0b, 0x1028, 0x2028,
	0x0029, 0x0d04, 0x1029, 0x2029, 0x002a, 0x0d05, 0x102a, 0x202a,
	0x002b, 0x0d06, 0x102b, 0x202b, 0x002c, 0x0d07, 0x102c, 0x202c,
	0x002d, 0x0d08, 0x102d, 0x202d, 0x002e, 0x0d09, 0x102e, 0x202e,
	0x002f, 0x0d0a, 0x102f, 0x202f, 0x0030, 0x0d0b, 0x1030, 0x2030,
	0x0031, 0x0e04, 0x1031, 0x2031, 0x0032, 0x0e05, 0x1032, 0x2032,
	0x0033, 0x0e06, 0x1033, 0x2033, 0x0034, 0x0e07, 0x1034, 0x2034,
	0x0035, 0x0e08, 0x1035, 0x2035, 0x0036, 0x0e09, 0x1036, 0x2036,
	0x0037, 0x0e0a, 0x1037, 0x2037, 0x0038, 0x0e0b, 0x1038, 0x2038,
	0x0039, 0x0f04, 0x1039, 0x2039, 0x003a, 0x0f05, 0x103a, 0x203a,
	0x003b, 0x0f06, 0x103b, 0x203b, 0x003c, 0x0f07, 0x103c, 0x203c,
	0x0801, 0x0f08, 0x103d, 0x203d, 0x1001, 0x0f09, 0x103e, 0x203e,
	0x1801, 0x0f0a, 0x103f, 0x203f, 0x2001, 0x0f0b, 0x1040, 0x2040
};

struct source {
	const char *ptr;
	size_t left;
};

struct writer {
	char *base;
	char *op;
	char *op_limit;
};

static inline void copy64(const void *src, void *dst)
{
	*((long*)dst) = *((long*)src);
}

static inline void incremental_copy_fast_path(const char *src, char *op,
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

static inline void incremental_copy(const char *src, char *op, int len)
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

static inline void movedata(void *dest, const void* src, u32 len)
{
	int i = 0;
	char *d = (char*)dest, *s = (char*)src;
	for (i = 0; i < len; ++i) {
		d[i] = s[i];
	}
}

static inline bool writer_append_from_self(struct writer *w, u32 offset,
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

static inline const char *peek(struct source *s, size_t * len)
{
	*len = s->left;
	return s->ptr;
}

static inline void skip(struct source *s, size_t n)
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
	const u32 entry = char_table[c];
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
			const u32 entry = char_table[c];
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