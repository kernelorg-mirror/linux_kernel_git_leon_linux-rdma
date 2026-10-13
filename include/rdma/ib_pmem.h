/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
#ifndef IB_PMEM_H
#define IB_PMEM_H

#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/kconfig.h>
#include <linux/overflow.h>

struct ib_pmem_walk {
	u64 next;
	u64 end;
};

static inline int ib_pmem_resource(struct resource *res, void *arg)
{
	struct ib_pmem_walk *walk = arg;

	if (res->start > walk->next)
		return -ENXIO;
	if (res->end >= walk->end - 1) {
		walk->next = walk->end;
		return 1;
	}
	walk->next = res->end + 1;
	return 0;
}

/*
 * Persistent coverage with cache writeback support for ordinary page mappings.
 * Process context: the resource walker takes a non-IRQ-safe lock.
 */
static inline bool ib_pmem_range(u64 start, size_t size)
{
	struct ib_pmem_walk walk = { .next = start };

	if (!size)
		return true;
	if (!IS_ENABLED(CONFIG_ARCH_HAS_PMEM_API))
		return false;
	if (check_add_overflow(start, size, &walk.end))
		return false;
	/* The walker requires start < end. Search through the exclusive end
	 * and stop the callback as soon as the requested bytes are covered.
	 */
	return walk_iomem_res_desc(IORES_DESC_PERSISTENT_MEMORY, IORESOURCE_MEM,
				   start, walk.end, &walk, ib_pmem_resource) == 1;
}

#endif /* IB_PMEM_H */
