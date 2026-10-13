// SPDX-License-Identifier: GPL-2.0

#if IS_ENABLED(CONFIG_INFINIBAND)
#include <linux/once.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_umem.h>
#include <rdma/uverbs_ioctl.h>

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

__rust_helper struct page *rust_helper_ib_virt_dma_to_page(u64 addr)
{
	return ib_virt_dma_to_page(addr);
}
#endif
