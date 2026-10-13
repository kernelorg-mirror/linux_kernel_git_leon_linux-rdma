// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2022-2023 Fujitsu Ltd. All rights reserved.
 */

#include <linux/hmm.h>
#include <linux/libnvdimm.h>

#include <rdma/ib_umem_odp.h>

#include "rxe.h"

#define RXE_PAGEFAULT_DEFAULT 0
#define RXE_PAGEFAULT_RDONLY BIT(0)
#define RXE_PAGEFAULT_SNAPSHOT BIT(1)
static int rxe_odp_do_pagefault_and_lock(struct rxe_mr *mr, u64 user_va, u64 bcnt, u32 flags)
{
	struct ib_umem_odp *umem_odp = to_ib_umem_odp(mr->umem);
	bool fault = !(flags & RXE_PAGEFAULT_SNAPSHOT);
	u64 access_mask = 0;
	int np;

	if (umem_odp->umem.writable && !(flags & RXE_PAGEFAULT_RDONLY))
		access_mask |= HMM_PFN_WRITE;

	/*
	 * ib_umem_odp_map_dma_and_lock() locks umem_mutex on success.
	 * Callers must release the lock later to let invalidation handler
	 * do its work again.
	 */
	np = ib_umem_odp_map_dma_and_lock(umem_odp, user_va, bcnt,
					  access_mask, fault);
	return np;
}

static int rxe_odp_init_pages(struct rxe_mr *mr)
{
	struct ib_umem_odp *umem_odp = to_ib_umem_odp(mr->umem);
	int ret;

	ret = rxe_odp_do_pagefault_and_lock(mr, mr->umem->address,
					    mr->umem->length,
					    RXE_PAGEFAULT_SNAPSHOT);

	if (ret >= 0)
		mutex_unlock(&umem_odp->umem_mutex);

	return ret >= 0 ? 0 : ret;
}

int rxe_odp_mr_init_user(struct rxe_dev *rxe, u64 start, u64 length,
			 u64 iova, int access_flags, struct rxe_mr *mr)
{
	struct ib_umem_odp *umem_odp;
	int err;

	if (!IS_ENABLED(CONFIG_INFINIBAND_ON_DEMAND_PAGING))
		return -EOPNOTSUPP;

	rxe_mr_init(access_flags, mr);

	/* Implicit ODP (start=0, length=U64_MAX) is not implemented. */
	if (!start && length == U64_MAX)
		return -EOPNOTSUPP;

	umem_odp = ib_umem_odp_get_cpu(&rxe->ib_dev, start, length, access_flags);
	if (IS_ERR(umem_odp)) {
		rxe_dbg_mr(mr, "Unable to create umem_odp err = %d\n",
			   (int)PTR_ERR(umem_odp));
		return PTR_ERR(umem_odp);
	}

	mr->umem = &umem_odp->umem;
	mr->access = access_flags;
	mr->ibmr.length = length;
	mr->ibmr.iova = iova;

	err = rxe_odp_init_pages(mr);
	if (err) {
		ib_umem_odp_release(umem_odp);
		mr->umem = NULL;
		return err;
	}

	mr->state = RXE_MR_STATE_VALID;
	mr->ibmr.type = IB_MR_TYPE_USER;

	return err;
}

/* PFNs describe userspace addresses, independently of the MR's IOVA. */
static int rxe_odp_user_va(struct rxe_mr *mr, u64 iova, u64 length,
			   u64 *user_va)
{
	int err;

	err = mr_check_range(mr, iova, length);
	if (err)
		return err;

	*user_va = mr->umem->address + (iova - mr->ibmr.iova);
	return 0;
}

static int rxe_odp_prefetch_and_lock(struct rxe_mr *mr, u64 iova,
				   u64 length, u32 flags)
{
	u64 user_va;
	int err;

	err = rxe_odp_user_va(mr, iova, length, &user_va);
	if (err)
		return err;

	return rxe_odp_do_pagefault_and_lock(mr, user_va, length, flags);
}

static inline bool rxe_check_pagefault(struct ib_umem_odp *umem_odp, u64 user_addr,
				       u64 length, bool write)
{
	bool need_fault = false;
	u64 access = HMM_PFN_VALID;
	u64 addr;
	unsigned long idx;

	if (write)
		access |= HMM_PFN_WRITE;

	addr = user_addr & PAGE_MASK;

	/* Skim through all pages that are to be accessed. */
	while (addr < user_addr + length) {
		idx = (addr - ib_umem_start(umem_odp)) >> PAGE_SHIFT;

		if ((umem_odp->map.pfn_list[idx] & access) != access) {
			need_fault = true;
			break;
		}

		addr += PAGE_SIZE;
	}
	return need_fault;
}

static unsigned long rxe_odp_va_to_index(struct ib_umem_odp *umem_odp, u64 user_addr)
{
	return (user_addr - ib_umem_start(umem_odp)) >> PAGE_SHIFT;
}

static unsigned long rxe_odp_va_to_page_offset(u64 user_addr)
{
	return offset_in_page(user_addr);
}

static int rxe_odp_map_range_and_lock(struct rxe_mr *mr, u64 iova,
				    u64 length, u32 flags, u64 *user_va)
{
	struct ib_umem_odp *umem_odp = to_ib_umem_odp(mr->umem);
	bool write = !(flags & RXE_PAGEFAULT_RDONLY);
	bool need_fault;
	int err;

	if (unlikely(!length))
		return -EINVAL;

	err = rxe_odp_user_va(mr, iova, length, user_va);
	if (err)
		return err;

	mutex_lock(&umem_odp->umem_mutex);

	need_fault = rxe_check_pagefault(umem_odp, *user_va, length, write);
	if (need_fault) {
		mutex_unlock(&umem_odp->umem_mutex);

		/* umem_mutex is locked on success. */
		err = rxe_odp_do_pagefault_and_lock(mr, *user_va, length,
						    flags);
		if (err < 0)
			return err;

		need_fault = rxe_check_pagefault(umem_odp, *user_va, length, write);
		if (need_fault) {
			mutex_unlock(&umem_odp->umem_mutex);
			return -EFAULT;
		}
	}

	return 0;
}

static int __rxe_odp_mr_copy(struct rxe_mr *mr, u64 user_addr, void *addr,
			     int length, enum rxe_mr_copy_dir dir)
{
	struct ib_umem_odp *umem_odp = to_ib_umem_odp(mr->umem);
	struct page *page;
	unsigned long idx;
	int bytes;
	size_t offset;
	u8 *user_va;

	idx = rxe_odp_va_to_index(umem_odp, user_addr);
	offset = rxe_odp_va_to_page_offset(user_addr);

	while (length > 0) {
		u8 *src, *dest;

		page = hmm_pfn_to_page(umem_odp->map.pfn_list[idx]);
		if (is_page_hwpoison(page))
			return -EHWPOISON;
		user_va = kmap_local_page(page);

		src = (dir == RXE_TO_MR_OBJ) ? addr : user_va + offset;
		dest = (dir == RXE_TO_MR_OBJ) ? user_va + offset : addr;

		bytes = PAGE_SIZE - offset;
		if (bytes > length)
			bytes = length;

		memcpy(dest, src, bytes);
		if (dir == RXE_TO_MR_OBJ)
			flush_dcache_page(page);
		kunmap_local(user_va);

		length -= bytes;
		addr += bytes;
		idx++;
		offset = 0;
	}

	return 0;
}

int rxe_odp_mr_copy(struct rxe_mr *mr, u64 iova, void *addr, int length,
		    enum rxe_mr_copy_dir dir)
{
	struct ib_umem_odp *umem_odp = to_ib_umem_odp(mr->umem);
	u32 flags = RXE_PAGEFAULT_DEFAULT;
	u64 user_va;
	int err;

	if (length == 0)
		return 0;

	if (unlikely(!mr->umem->is_odp))
		return -EOPNOTSUPP;

	switch (dir) {
	case RXE_TO_MR_OBJ:
		break;

	case RXE_FROM_MR_OBJ:
		flags |= RXE_PAGEFAULT_RDONLY;
		break;

	default:
		return -EINVAL;
	}

	err = rxe_odp_map_range_and_lock(mr, iova, length, flags, &user_va);
	if (err)
		return err;

	err =  __rxe_odp_mr_copy(mr, user_va, addr, length, dir);

	mutex_unlock(&umem_odp->umem_mutex);

	return err;
}

static enum resp_states rxe_odp_do_atomic_op(struct rxe_mr *mr, u64 user_addr,
					     int opcode, u64 compare,
					     u64 swap_add, u64 *orig_val)
{
	struct ib_umem_odp *umem_odp = to_ib_umem_odp(mr->umem);
	unsigned int page_offset;
	struct page *page;
	unsigned long idx;
	u64 value;
	u64 *va;

	if (unlikely(mr->state != RXE_MR_STATE_VALID)) {
		rxe_dbg_mr(mr, "mr not in valid state\n");
		return RESPST_ERR_RKEY_VIOLATION;
	}

	page_offset = rxe_odp_va_to_page_offset(user_addr);
	if (unlikely(page_offset & 0x7)) {
		rxe_dbg_mr(mr, "user_addr not aligned\n");
		return RESPST_ERR_MISALIGNED_ATOMIC;
	}

	idx = rxe_odp_va_to_index(umem_odp, user_addr);
	page = hmm_pfn_to_page(umem_odp->map.pfn_list[idx]);
	if (is_page_hwpoison(page))
		return RESPST_ERR_RKEY_VIOLATION;

	va = kmap_local_page(page);

	spin_lock_bh(&atomic_ops_lock);
	value = *orig_val = va[page_offset >> 3];

	if (opcode == IB_OPCODE_RC_COMPARE_SWAP) {
		if (value == compare)
			va[page_offset >> 3] = swap_add;
	} else {
		value += swap_add;
		va[page_offset >> 3] = value;
	}
	spin_unlock_bh(&atomic_ops_lock);
	flush_dcache_page(page);

	kunmap_local(va);

	return RESPST_NONE;
}

enum resp_states rxe_odp_atomic_op(struct rxe_mr *mr, u64 iova, int opcode,
				   u64 compare, u64 swap_add, u64 *orig_val)
{
	struct ib_umem_odp *umem_odp = to_ib_umem_odp(mr->umem);
	u64 user_va;
	int err;

	err = rxe_odp_map_range_and_lock(mr, iova, sizeof(*orig_val),
					 RXE_PAGEFAULT_DEFAULT, &user_va);
	if (err < 0)
		return RESPST_ERR_RKEY_VIOLATION;

	err = rxe_odp_do_atomic_op(mr, user_va, opcode, compare, swap_add,
				   orig_val);
	mutex_unlock(&umem_odp->umem_mutex);

	return err;
}

int rxe_odp_flush_pmem_iova(struct rxe_mr *mr, u64 iova,
			    unsigned int length)
{
	struct ib_umem_odp *umem_odp = to_ib_umem_odp(mr->umem);
	unsigned int page_offset;
	unsigned long index;
	struct page *page;
	unsigned int bytes;
	u64 user_va;
	int err;
	u8 *va;

	/* A flush never modifies memory; read-only access suffices. */
	err = rxe_odp_map_range_and_lock(mr, iova, length,
					 RXE_PAGEFAULT_RDONLY, &user_va);
	if (err)
		return err;

	while (length > 0) {
		index = rxe_odp_va_to_index(umem_odp, user_va);
		page_offset = rxe_odp_va_to_page_offset(user_va);

		page = hmm_pfn_to_page(umem_odp->map.pfn_list[index]);
		if (is_page_hwpoison(page)) {
			mutex_unlock(&umem_odp->umem_mutex);
			return -EHWPOISON;
		}

		bytes = min_t(unsigned int, length,
			      PAGE_SIZE - page_offset);

		va = kmap_local_page(page);
		arch_wb_cache_pmem(va + page_offset, bytes);
		kunmap_local(va);

		length -= bytes;
		user_va += bytes;
	}

	mutex_unlock(&umem_odp->umem_mutex);

	return 0;
}

enum resp_states rxe_odp_do_atomic_write(struct rxe_mr *mr, u64 iova, u64 value)
{
	struct ib_umem_odp *umem_odp = to_ib_umem_odp(mr->umem);
	unsigned int page_offset;
	unsigned long index;
	struct page *page;
	u64 user_va;
	int err;
	u64 *va;

	/* See IBA oA19-28 */
	err = mr_check_range(mr, iova, sizeof(value));
	if (unlikely(err)) {
		rxe_dbg_mr(mr, "iova out of range\n");
		return RESPST_ERR_RKEY_VIOLATION;
	}

	err = rxe_odp_map_range_and_lock(mr, iova, sizeof(value),
					 RXE_PAGEFAULT_DEFAULT, &user_va);
	if (err)
		return RESPST_ERR_RKEY_VIOLATION;

	page_offset = rxe_odp_va_to_page_offset(user_va);
	/* See IBA A19.4.2 */
	if (unlikely(page_offset & 0x7)) {
		mutex_unlock(&umem_odp->umem_mutex);
		rxe_dbg_mr(mr, "misaligned address\n");
		return RESPST_ERR_MISALIGNED_ATOMIC;
	}

	index = rxe_odp_va_to_index(umem_odp, user_va);
	page = hmm_pfn_to_page(umem_odp->map.pfn_list[index]);
	if (is_page_hwpoison(page)) {
		mutex_unlock(&umem_odp->umem_mutex);
		return RESPST_ERR_RKEY_VIOLATION;
	}

	va = kmap_local_page(page);
	/* Do atomic write after all prior operations have completed */
	smp_store_release(&va[page_offset >> 3], value);
	flush_dcache_page(page);
	kunmap_local(va);

	mutex_unlock(&umem_odp->umem_mutex);

	return RESPST_NONE;
}

struct rxe_odp_prefetch {
	struct rxe_mr *mr;
	u64 user_va;
	size_t length;
};

static int rxe_ib_prefetch_sg_list(struct ib_pd *ibpd,
				   enum ib_uverbs_advise_mr_advice advice,
				   u32 pf_flags, struct ib_sge *sg_list,
				   u32 num_sge)
{
	struct rxe_pd *pd = container_of(ibpd, struct rxe_pd, ibpd);
	int ret = 0;
	int access = IB_ACCESS_ON_DEMAND;
	u32 i;

	if (advice == IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_WRITE)
		access |= IB_ACCESS_LOCAL_WRITE;

	for (i = 0; i < num_sge; ++i) {
		struct rxe_mr *mr;
		struct ib_umem_odp *umem_odp;

		mr = lookup_mr(pd, access, sg_list[i].lkey, RXE_LOOKUP_LOCAL);

		if (!mr) {
			rxe_dbg_pd(pd, "mr with lkey %x not found\n",
				   sg_list[i].lkey);
			return -EINVAL;
		}

		if (advice == IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_WRITE &&
		    !mr->umem->writable) {
			rxe_dbg_mr(mr, "missing write permission\n");
			rxe_put(mr);
			return -EPERM;
		}

		ret = rxe_odp_prefetch_and_lock(
			mr, sg_list[i].addr, sg_list[i].length, pf_flags);
		if (ret < 0) {
			rxe_dbg_mr(mr, "failed to prefetch the mr\n");
			rxe_put(mr);
			return ret;
		}

		umem_odp = to_ib_umem_odp(mr->umem);
		mutex_unlock(&umem_odp->umem_mutex);

		rxe_put(mr);
	}

	return 0;
}

static int rxe_ib_advise_mr_prefetch(struct ib_pd *ibpd,
				     enum ib_uverbs_advise_mr_advice advice,
				     u32 flags, struct ib_sge *sg_list,
				     u32 num_sge)
{
	struct rxe_pd *pd = container_of(ibpd, struct rxe_pd, ibpd);
	u32 pf_flags = RXE_PAGEFAULT_DEFAULT;
	struct rxe_odp_prefetch *prefetch;
	u32 i, num_mrs = 0;
	int ret = 0;
	int access = IB_ACCESS_ON_DEMAND;

	if (advice == IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH)
		pf_flags |= RXE_PAGEFAULT_RDONLY;

	if (advice == IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_NO_FAULT)
		pf_flags |= RXE_PAGEFAULT_SNAPSHOT;

	if (advice == IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_WRITE)
		access |= IB_ACCESS_LOCAL_WRITE;

	/* Synchronous call */
	if (flags & IB_UVERBS_ADVISE_MR_FLAG_FLUSH)
		return rxe_ib_prefetch_sg_list(ibpd, advice, pf_flags, sg_list,
					       num_sge);

	prefetch = kvcalloc(num_sge, sizeof(*prefetch), GFP_KERNEL);
	if (!prefetch)
		return -ENOMEM;

	/* Validate every fragment before scheduling best-effort prefetch. */
	for (i = 0; i < num_sge; ++i) {
		struct rxe_mr *mr;

		mr = lookup_mr(pd, access, sg_list[i].lkey, RXE_LOOKUP_LOCAL);
		if (!mr) {
			ret = -EINVAL;
			goto out_put;
		}
		prefetch[i].mr = mr;
		num_mrs++;
		if (advice == IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_WRITE &&
		    !mr->umem->writable) {
			ret = -EPERM;
			goto out_put;
		}
		ret = rxe_odp_user_va(mr, sg_list[i].addr, sg_list[i].length,
				      &prefetch[i].user_va);
		if (ret)
			goto out_put;
		prefetch[i].length = sg_list[i].length;
	}

	for (i = 0; i < num_sge; ++i) {
		struct ib_umem_odp *umem_odp =
			to_ib_umem_odp(prefetch[i].mr->umem);
		u64 access_mask = 0;

		if (umem_odp->umem.writable && !(pf_flags & RXE_PAGEFAULT_RDONLY))
			access_mask = HMM_PFN_WRITE;
		ret = ib_umem_odp_queue_prefetch(umem_odp, prefetch[i].user_va,
						 prefetch[i].length, access_mask,
						 !(pf_flags & RXE_PAGEFAULT_SNAPSHOT));
		rxe_put(prefetch[i].mr);
		prefetch[i].mr = NULL;
		if (ret)
			break;
	}

out_put:
	for (i = 0; i < num_mrs; ++i) {
		if (prefetch[i].mr)
			rxe_put(prefetch[i].mr);
	}
	kvfree(prefetch);
	return ret;
}

int rxe_ib_advise_mr(struct ib_pd *ibpd,
		     enum ib_uverbs_advise_mr_advice advice,
		     u32 flags,
		     struct ib_sge *sg_list,
		     u32 num_sge,
		     struct uverbs_attr_bundle *attrs)
{
	if (advice != IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH &&
	    advice != IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_WRITE &&
	    advice != IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_NO_FAULT)
		return -EOPNOTSUPP;

	return rxe_ib_advise_mr_prefetch(ibpd, advice, flags,
					 sg_list, num_sge);
}
