// SPDX-License-Identifier: GPL-2.0

#if IS_ENABLED(CONFIG_INFINIBAND)
#include <linux/atomic.h>
#include <linux/irqflags.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_pmem.h>
#include <rdma/ib_umem.h>
#include <rdma/uverbs_ioctl.h>

__rust_helper bool rust_helper_ib_pmem_range(u64 start, size_t size)
{
	return ib_pmem_range(start, size);
}

__rust_helper void rust_helper_rust_rdma_init_provider_registry(atomic_t *state,
							      void (*init)(void))
{
	unsigned long flags;

	if (atomic_read_acquire(state) == 2)
		return;

	/* Exclude same-CPU reentry while the non-sleeping initializer runs. */
	local_irq_save(flags);
	if (atomic_cmpxchg(state, 0, 1) == 0) {
		init();
		atomic_set_release(state, 2);
	} else {
		atomic_cond_read_acquire(state, VAL == 2);
	}
	local_irq_restore(flags);
}

__rust_helper enum ib_port_state
rust_helper_ib_get_curr_port_state(struct net_device *ndev)
{
	return ib_get_curr_port_state(ndev);
}

#if !IS_ENABLED(CONFIG_INFINIBAND_USER_ACCESS)
__rust_helper int rust_helper__ib_copy_validate_udata_in(struct ib_udata *udata,
						      void *req, size_t size,
						      size_t minimum)
{
	return _ib_copy_validate_udata_in(udata, req, size, minimum);
}
#endif

__rust_helper bool rust_helper_ib_device_try_get(struct ib_device *dev)
{
	return ib_device_try_get(dev);
}

__rust_helper bool rust_helper_rdma_protocol_iwarp(struct ib_device *dev, u32 port)
{
	return rdma_protocol_iwarp(dev, port);
}

/*
 * The identifier union has no member selector. Preserve all eight bytes for
 * scalar wr_id callers. On 32-bit, storing wr_cqe leaves the other union bytes
 * unspecified; the opaque asm output materializes those bits before Rust sees
 * a u64. This does not zero them. Callback consumers read only the initialized
 * pointer bytes, including on big-endian targets.
 */
__rust_helper u64 rust_helper_ib_recv_wr_id(const struct ib_recv_wr *wr)
{
	u64 id = wr->wr_id;

	/* Return an opaque value while preserving the initialized union member. */
	OPTIMIZER_HIDE_VAR(id);
	return id;
}

__rust_helper u64 rust_helper_ib_send_wr_id(const struct ib_send_wr *wr)
{
	u64 id = wr->wr_id;

	/* Return an opaque value while preserving the initialized union member. */
	OPTIMIZER_HIDE_VAR(id);
	return id;
}

__rust_helper int rust_helper_rdma_is_port_valid(const struct ib_device *dev,
					       u32 port)
{
	return rdma_is_port_valid(dev, port);
}

#ifndef CONFIG_INFINIBAND_USER_MEM
__rust_helper struct ib_umem *
rust_helper_ib_umem_get_attr_or_va(struct ib_device *dev,
				 const struct uverbs_attr_bundle *attrs,
				 u16 attr_id, u64 addr, size_t size, int access)
{
	return ib_umem_get_attr_or_va(dev, attrs, attr_id, addr, size, access);
}

__rust_helper int rust_helper_ib_umem_check_rereg(struct ib_umem *umem,
						int flags, int access)
{
	return ib_umem_check_rereg(umem, flags, access);
}

__rust_helper void rust_helper_ib_umem_release(struct ib_umem *umem)
{
	ib_umem_release(umem);
}
#endif

__rust_helper struct page *rust_helper_ib_virt_dma_to_page(u64 addr)
{
	return ib_virt_dma_to_page(addr);
}
#endif
