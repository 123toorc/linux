// SPDX-License-Identifier: GPL-2.0
/*
 * NVMe I/O command implementation.
 * Copyright (c) 2015-2016 HGST, a Western Digital Company.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/blkdev.h>
#include <linux/module.h>
#include "nvmet.h"

#ifdef CONFIG_NVME_TARGET_NDP_MODULE
#include <linux/bpf.h>
#endif

void nvmet_bdev_set_limits(struct block_device *bdev, struct nvme_id_ns *id)
{
	const struct queue_limits *ql = &bdev_get_queue(bdev)->limits;
	/* Number of logical blocks per physical block. */
	const u32 lpp = ql->physical_block_size / ql->logical_block_size;
	/* Logical blocks per physical block, 0's based. */
	const __le16 lpp0b = to0based(lpp);

	/*
	 * For NVMe 1.2 and later, bit 1 indicates that the fields NAWUN,
	 * NAWUPF, and NACWU are defined for this namespace and should be
	 * used by the host for this namespace instead of the AWUN, AWUPF,
	 * and ACWU fields in the Identify Controller data structure. If
	 * any of these fields are zero that means that the corresponding
	 * field from the identify controller data structure should be used.
	 */
	id->nsfeat |= 1 << 1;
	id->nawun = lpp0b;
	id->nawupf = lpp0b;
	id->nacwu = lpp0b;

	/*
	 * Bit 4 indicates that the fields NPWG, NPWA, NPDG, NPDA, and
	 * NOWS are defined for this namespace and should be used by
	 * the host for I/O optimization.
	 */
	id->nsfeat |= 1 << 4;
	/* NPWG = Namespace Preferred Write Granularity. 0's based */
	id->npwg = lpp0b;
	/* NPWA = Namespace Preferred Write Alignment. 0's based */
	id->npwa = id->npwg;
	/* NPDG = Namespace Preferred Deallocate Granularity. 0's based */
	id->npdg = to0based(ql->discard_granularity / ql->logical_block_size);
	/* NPDG = Namespace Preferred Deallocate Alignment */
	id->npda = id->npdg;
	/* NOWS = Namespace Optimal Write Size */
	id->nows = to0based(ql->io_opt / ql->logical_block_size);
}

int nvmet_bdev_ns_enable(struct nvmet_ns *ns)
{
	int ret;

	ns->bdev = blkdev_get_by_path(ns->device_path,
			FMODE_READ | FMODE_WRITE, NULL);
	if (IS_ERR(ns->bdev)) {
		ret = PTR_ERR(ns->bdev);
		if (ret != -ENOTBLK) {
			pr_err("failed to open block device %s: (%ld)\n",
					ns->device_path, PTR_ERR(ns->bdev));
		}
		ns->bdev = NULL;
		return ret;
	}
	ns->size = i_size_read(ns->bdev->bd_inode);
	ns->blksize_shift = blksize_bits(bdev_logical_block_size(ns->bdev));
	return 0;
}

void nvmet_bdev_ns_disable(struct nvmet_ns *ns)
{
	if (ns->bdev) {
		blkdev_put(ns->bdev, FMODE_WRITE | FMODE_READ);
		ns->bdev = NULL;
	}
}

static u16 blk_to_nvme_status(struct nvmet_req *req, blk_status_t blk_sts)
{
	u16 status = NVME_SC_SUCCESS;

	if (likely(blk_sts == BLK_STS_OK))
		return status;
	/*
	 * Right now there exists M : 1 mapping between block layer error
	 * to the NVMe status code (see nvme_error_status()). For consistency,
	 * when we reverse map we use most appropriate NVMe Status code from
	 * the group of the NVMe staus codes used in the nvme_error_status().
	 */
	switch (blk_sts) {
	case BLK_STS_NOSPC:
		status = NVME_SC_CAP_EXCEEDED | NVME_SC_DNR;
		req->error_loc = offsetof(struct nvme_rw_command, length);
		break;
	case BLK_STS_TARGET:
		status = NVME_SC_LBA_RANGE | NVME_SC_DNR;
		req->error_loc = offsetof(struct nvme_rw_command, slba);
		break;
	case BLK_STS_NOTSUPP:
		req->error_loc = offsetof(struct nvme_common_command, opcode);
		switch (req->cmd->common.opcode) {
		case nvme_cmd_dsm:
		case nvme_cmd_write_zeroes:
			status = NVME_SC_ONCS_NOT_SUPPORTED | NVME_SC_DNR;
			break;
		default:
			status = NVME_SC_INVALID_OPCODE | NVME_SC_DNR;
		}
		break;
	case BLK_STS_MEDIUM:
		status = NVME_SC_ACCESS_DENIED;
		req->error_loc = offsetof(struct nvme_rw_command, nsid);
		break;
	case BLK_STS_IOERR:
		/* fallthru */
	default:
		status = NVME_SC_INTERNAL | NVME_SC_DNR;
		req->error_loc = offsetof(struct nvme_common_command, opcode);
	}

	switch (req->cmd->common.opcode) {
	case nvme_cmd_read:
	case nvme_cmd_write:
		req->error_slba = le64_to_cpu(req->cmd->rw.slba);
		break;
	case nvme_cmd_write_zeroes:
		req->error_slba =
			le64_to_cpu(req->cmd->write_zeroes.slba);
		break;
	default:
		req->error_slba = 0;
	}
	return status;
}

static void nvmet_bio_done(struct bio *bio)
{
	struct nvmet_req *req = bio->bi_private;

	nvmet_req_complete(req, blk_to_nvme_status(req, bio->bi_status));
	if (bio != &req->b.inline_bio)
		bio_put(bio);
}

static void nvmet_bdev_execute_rw(struct nvmet_req *req)
{
	int sg_cnt = req->sg_cnt;
	struct bio *bio;
	struct scatterlist *sg;
	struct blk_plug plug;
	sector_t sector;
	int op, i;

	struct sk_filter *filter;
	void *data;
	int res;

	if (!nvmet_check_data_len(req, nvmet_rw_len(req)))
		return;

	if (!req->sg_cnt) {
		nvmet_req_complete(req, 0);
		return;
	}

	if (req->cmd->rw.opcode == nvme_cmd_write) {
		op = REQ_OP_WRITE | REQ_SYNC | REQ_IDLE;
		if (req->cmd->rw.control & cpu_to_le16(NVME_RW_FUA))
			op |= REQ_FUA;
	} else {
		op = REQ_OP_READ;
	}

	if (is_pci_p2pdma_page(sg_page(req->sg)))
		op |= REQ_NOMERGE;

	sector = le64_to_cpu(req->cmd->rw.slba);
	sector <<= (req->ns->blksize_shift - 9);

	if (req->transfer_len <= NVMET_MAX_INLINE_DATA_LEN) {
		bio = &req->b.inline_bio;
		bio_init(bio, req->inline_bvec, ARRAY_SIZE(req->inline_bvec));
	} else {
		bio = bio_alloc(GFP_KERNEL, min(sg_cnt, BIO_MAX_PAGES));
	}
	bio_set_dev(bio, req->ns->bdev);
	bio->bi_iter.bi_sector = sector;
	bio->bi_private = req;
	bio->bi_end_io = nvmet_bio_done;
	bio->bi_opf = op;

	blk_start_plug(&plug);

	printk("HACK: op: %d\n", op);
	if (op & REQ_OP_WRITE) {
		rcu_read_lock();
		filter = rcu_dereference(req->ns->ns_filter);
		if (filter) {
			data = sg_virt(req->sg);
			printk("HACK: getting sg directly.\n");
			res = BPF_PROG_RUN(filter->prog, data);
			printk("HACK: applying filter\n");
		}
		rcu_read_unlock();
	}

	for_each_sg(req->sg, sg, req->sg_cnt, i) {
		while (bio_add_page(bio, sg_page(sg), sg->length, sg->offset)
				!= sg->length) {
			struct bio *prev = bio;

			bio = bio_alloc(GFP_KERNEL, min(sg_cnt, BIO_MAX_PAGES));
			bio_set_dev(bio, req->ns->bdev);
			bio->bi_iter.bi_sector = sector;
			bio->bi_opf = op;

			bio_chain(bio, prev);
			submit_bio(prev);
		}

		sector += sg->length >> 9;
		sg_cnt--;
	}

	submit_bio(bio);
	blk_finish_plug(&plug);
}

static void nvmet_bdev_execute_flush(struct nvmet_req *req)
{
	struct bio *bio = &req->b.inline_bio;

	if (!nvmet_check_data_len(req, 0))
		return;

	bio_init(bio, req->inline_bvec, ARRAY_SIZE(req->inline_bvec));
	bio_set_dev(bio, req->ns->bdev);
	bio->bi_private = req;
	bio->bi_end_io = nvmet_bio_done;
	bio->bi_opf = REQ_OP_WRITE | REQ_PREFLUSH;

	submit_bio(bio);
}

u16 nvmet_bdev_flush(struct nvmet_req *req)
{
	if (blkdev_issue_flush(req->ns->bdev, GFP_KERNEL, NULL))
		return NVME_SC_INTERNAL | NVME_SC_DNR;
	return 0;
}

static u16 nvmet_bdev_discard_range(struct nvmet_req *req,
		struct nvme_dsm_range *range, struct bio **bio)
{
	struct nvmet_ns *ns = req->ns;
	int ret;

	ret = __blkdev_issue_discard(ns->bdev,
			le64_to_cpu(range->slba) << (ns->blksize_shift - 9),
			le32_to_cpu(range->nlb) << (ns->blksize_shift - 9),
			GFP_KERNEL, 0, bio);
	if (ret && ret != -EOPNOTSUPP) {
		req->error_slba = le64_to_cpu(range->slba);
		return errno_to_nvme_status(req, ret);
	}
	return NVME_SC_SUCCESS;
}

static void nvmet_bdev_execute_discard(struct nvmet_req *req)
{
	struct nvme_dsm_range range;
	struct bio *bio = NULL;
	int i;
	u16 status;

	for (i = 0; i <= le32_to_cpu(req->cmd->dsm.nr); i++) {
		status = nvmet_copy_from_sgl(req, i * sizeof(range), &range,
				sizeof(range));
		if (status)
			break;

		status = nvmet_bdev_discard_range(req, &range, &bio);
		if (status)
			break;
	}

	if (bio) {
		bio->bi_private = req;
		bio->bi_end_io = nvmet_bio_done;
		if (status)
			bio_io_error(bio);
		else
			submit_bio(bio);
	} else {
		nvmet_req_complete(req, status);
	}
}

static void nvmet_bdev_execute_dsm(struct nvmet_req *req)
{
	if (!nvmet_check_data_len_lte(req, nvmet_dsm_len(req)))
		return;

	switch (le32_to_cpu(req->cmd->dsm.attributes)) {
	case NVME_DSMGMT_AD:
		nvmet_bdev_execute_discard(req);
		return;
	case NVME_DSMGMT_IDR:
	case NVME_DSMGMT_IDW:
	default:
		/* Not supported yet */
		nvmet_req_complete(req, 0);
		return;
	}
}

static void nvmet_bdev_execute_write_zeroes(struct nvmet_req *req)
{
	struct nvme_write_zeroes_cmd *write_zeroes = &req->cmd->write_zeroes;
	struct bio *bio = NULL;
	sector_t sector;
	sector_t nr_sector;
	int ret;

	if (!nvmet_check_data_len(req, 0))
		return;

	sector = le64_to_cpu(write_zeroes->slba) <<
		(req->ns->blksize_shift - 9);
	nr_sector = (((sector_t)le16_to_cpu(write_zeroes->length) + 1) <<
		(req->ns->blksize_shift - 9));

	ret = __blkdev_issue_zeroout(req->ns->bdev, sector, nr_sector,
			GFP_KERNEL, &bio, 0);
	if (bio) {
		bio->bi_private = req;
		bio->bi_end_io = nvmet_bio_done;
		submit_bio(bio);
	} else {
		nvmet_req_complete(req, errno_to_nvme_status(req, ret));
	}
}

#ifdef CONFIG_NVME_TARGET_NDP_MODULE

// ==================
//        BPF
// ==================
static bool bpf_check_basics_ok(const struct sock_filter *filter,
				unsigned int flen)
{
	if (filter == NULL)
		return false;
	if (flen == 0 || flen > BPF_MAXINSNS)
		return false;

	return true;
}

static int bpf_prog_store_orig_filter(struct bpf_prog *fp,
				      const struct sock_fprog *fprog)
{
	unsigned int fsize = bpf_classic_proglen(fprog);
	struct sock_fprog_kern *fkprog;

	fp->orig_prog = kmalloc(sizeof(*fkprog), GFP_KERNEL);
	if (!fp->orig_prog)
		return -ENOMEM;

	fkprog = fp->orig_prog;
	fkprog->len = fprog->len;

	fkprog->filter = kmemdup(fp->insns, fsize,
				 GFP_KERNEL | __GFP_NOWARN);
	if (!fkprog->filter) {
		kfree(fp->orig_prog);
		return -ENOMEM;
	}

	return 0;
}

static
struct bpf_prog *__get_filter(struct sock_fprog *fprog)
{
	unsigned int fsize = bpf_classic_proglen(fprog);
	struct bpf_prog *prog;
	int err;

	printk("bpf_check\n");
	if (!bpf_check_basics_ok(fprog->filter, fprog->len))
		return ERR_PTR(-EINVAL);

	printk("bpf_alloc\n");
	prog = bpf_prog_alloc(bpf_prog_size(fprog->len), 0);
	if (!prog)
		return ERR_PTR(-ENOMEM);

	printk("bpf_copy\n");
	if (copy_from_user(prog->insns, fprog->filter, fsize)) {
		bpf_prog_free(prog);
		return ERR_PTR(-EFAULT);
	}

	printk("bpf_setlen\n");
	prog->len = fprog->len;

	printk("bpf_prog_store_orig_filter\n");
	err = bpf_prog_store_orig_filter(prog, fprog);

	if (err) {
		bpf_prog_free(prog);
		return ERR_PTR(-ENOMEM);
	}

	printk("bpf_prepare_filter\n");
	return bpf_prepare_filter(prog, NULL);
}

extern int sysctl_optmem_max;

static bool __ns_filter_charge(struct nvmet_ns *ns, struct sk_filter *fp)
{
	u32 filter_size = bpf_prog_size(fp->prog->len);

	if (filter_size <= sysctl_optmem_max &&
	    atomic_read(&ns->ns_omem_alloc) + filter_size < sysctl_optmem_max) {
		atomic_add(filter_size, &ns->ns_omem_alloc);
		return true;
	}
	return false;
}

static void bpf_release_orig_filter(struct bpf_prog *fp)
{
	struct sock_fprog_kern *fprog = fp->orig_prog;

	if (fprog) {
		kfree(fprog->filter);
		kfree(fprog);
	}
}

static void __bpf_prog_release(struct bpf_prog *prog)
{
	if (prog->type == BPF_PROG_TYPE_NVME_NDP) {
		bpf_prog_put(prog);
	} else {
		bpf_release_orig_filter(prog);
		bpf_prog_free(prog);
	}
}

static void __ns_filter_release(struct sk_filter *fp)
{
	__bpf_prog_release(fp->prog);
	kfree(fp);
}

/**
 * 	sk_filter_release_rcu - Release a socket filter by rcu_head
 *	@rcu: rcu_head that contains the sk_filter to free
 */
static void ns_filter_release_rcu(struct rcu_head *rcu)
{
	struct sk_filter *fp = container_of(rcu, struct sk_filter, rcu);

	__ns_filter_release(fp);
}

/**
 *	sk_filter_release - release a socket filter
 *	@fp: filter to remove
 *
 *	Remove a filter from a socket and release its resources.
 */
static void ns_filter_release(struct sk_filter *fp)
{
	if (refcount_dec_and_test(&fp->refcnt))
		call_rcu(&fp->rcu, ns_filter_release_rcu);
}

static void ns_filter_uncharge(struct nvmet_ns *ns, struct sk_filter *fp)
{
	u32 filter_size = bpf_prog_size(fp->prog->len);

	atomic_sub(filter_size, &ns->ns_omem_alloc);
	ns_filter_release(fp);
}

static int __ns_attach_prog(struct bpf_prog *prog, struct nvmet_ns *ns)
{
	struct sk_filter *fp, *old_fp;

	fp = kmalloc(sizeof(*fp), GFP_KERNEL);
	if (!fp)
		return -ENOMEM;

	fp->prog = prog;

	if (!__ns_filter_charge(ns, fp)) {
		kfree(fp);
		return -ENOMEM;
	}
	refcount_set(&fp->refcnt, 1);

	old_fp = rcu_dereference_protected(ns->ns_filter,
					   lockdep_sock_is_held(ns));
	rcu_assign_pointer(ns->ns_filter, fp);

	if (old_fp)
		ns_filter_uncharge(ns, old_fp);

	return 0;
}

int ndp_attach_bpf(struct sock_fprog_kern *fprog, struct nvmet_ns *ns) {
	struct bpf_prog *prog;
	int err, i;

	printk("create bpf prog\n");

	printk("2 prog_len: %d\n",  fprog->len);
	for (i = 0; i < fprog->len; ++i) {
		printk("2 instr: %04X %02X %02X %08X\n", 
			fprog->filter[i].code,
			fprog->filter[i].jt,
			fprog->filter[i].jf,
			fprog->filter[i].k
		);
	}

	err = bpf_prog_create(&prog, fprog);

	printk("create bpf prog error: %d\n", err);

	if (err < 0)
		return err;

	printk("prog type %d\n", prog->type);

	printk("attaching prog\n");
	err = __ns_attach_prog(prog, ns);
	if (err < 0) {
		__bpf_prog_release(prog);
		return err;
	}

	return err;
}

static void ndp_module_dl_volatile(struct nvmet_req *req, struct ndp_module *module) {
	unsigned short code_len = module->prog.len;
	int sg_cnt = req->sg_cnt;
	int sg_len = req->sg->length;
	void *data;
	unsigned short i;

	if (!sg_cnt || code_len * sizeof(struct sock_filter) > sg_len) {
		// not enough data
		printk("not enough data\n");
		nvmet_req_complete(req, NVME_SC_INVALID_FIELD);
		return;
	}

	data = sg_virt(req->sg);
	module->prog.filter = (struct sock_filter *)vmalloc(code_len * sizeof(struct sock_filter));
	memcpy(module->prog.filter, data, code_len * sizeof(struct sock_filter));
	module->prog.len = code_len;

	printk("prog_len: %d\n",  module->prog.len);
	for (i = 0; i < code_len; ++i) {
		printk("instr: %04X %02X %02X %08X\n", 
			module->prog.filter[i].code,
			module->prog.filter[i].jt,
			module->prog.filter[i].jf,
			module->prog.filter[i].k
		);
	}

	module->loaded = true;
	if (ndp_attach_bpf(&(module->prog), req->ns)) {
		// FIXME: free
		printk("attach failed\n");
		nvmet_req_complete(req, NVME_SC_INVALID_FIELD);
		return;
	}
	nvmet_req_complete(req, 0);
}

static void ndp_module_remove(struct nvmet_req *req, struct ndp_module *module) {
	nvmet_code_module.loaded = false;
	if (nvmet_code_module.loaded) {
		vfree(nvmet_code_module.prog.filter);
	}
	nvmet_req_complete(req, 0);
}

static void nvmet_bdev_execute_ndp_module_mgmt(struct nvmet_req *req)
{
	u32 cdw10 = le32_to_cpu(req->cmd->common.cdw10);
	u32 cdw11 = le32_to_cpu(req->cmd->common.cdw11);
	u8 eft = cdw11 & 0xFFFF;
	u8 persist = (cdw11 >> 4) & 0xFF;
	u8 shared = (cdw11 >> 6) & 0xFF;
	u8 sub_cmd = (cdw11 >> 8) & 0xFFFF;
	// TODO: add Privilege level

	switch (sub_cmd) {
	case 0:
		// Download
		if (persist) {
			// TODO: persist
			printk("TODO: persist\n");
			nvmet_req_complete(req, NVME_SC_INVALID_FIELD);
			return;
		} else {
			if (nvmet_code_module.loaded) {
				// module not available
				printk("module already loaded\n");
				nvmet_req_complete(req, NVME_SC_INVALID_FIELD);
				return;
			}

			if (cdw10 > U16_MAX) {
				// filter blocks limit
				printk("filter blocks limit\n");
				nvmet_req_complete(req, NVME_SC_INVALID_FIELD);
				return;
			}

			nvmet_code_module.eft = eft;
			nvmet_code_module.persist = persist;
			nvmet_code_module.shared = shared;
			nvmet_code_module.prog.len = cdw10;
			nvmet_code_module.priv_level = 0;
			ndp_module_dl_volatile(req, &nvmet_code_module);
			return;
		}
	case 1:
		// Remove
		ndp_module_remove(req, &nvmet_code_module);
		return;
	default:
		nvmet_req_complete(req, NVME_SC_INVALID_FIELD);
		return;
	}
}
#endif

u16 nvmet_bdev_parse_io_cmd(struct nvmet_req *req)
{
	struct nvme_command *cmd = req->cmd;

	switch (cmd->common.opcode) {
	case nvme_cmd_read:
	case nvme_cmd_write:
		req->execute = nvmet_bdev_execute_rw;
		return 0;
	case nvme_cmd_flush:
		req->execute = nvmet_bdev_execute_flush;
		return 0;
	case nvme_cmd_dsm:
		req->execute = nvmet_bdev_execute_dsm;
		return 0;
	case nvme_cmd_write_zeroes:
		req->execute = nvmet_bdev_execute_write_zeroes;
		return 0;
#ifdef CONFIG_NVME_TARGET_NDP_MODULE
	case nvme_cmd_ndp_module_mgmt:
		req->execute = nvmet_bdev_execute_ndp_module_mgmt;
		return 0;
#endif
	default:
		pr_err("unhandled cmd %d on qid %d\n", cmd->common.opcode,
		       req->sq->qid);
		req->error_loc = offsetof(struct nvme_common_command, opcode);
		return NVME_SC_INVALID_OPCODE | NVME_SC_DNR;
	}
}
