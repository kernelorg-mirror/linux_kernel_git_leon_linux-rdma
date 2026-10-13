/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
#ifndef IB_VIRT_DMA_H
#define IB_VIRT_DMA_H

#include <linux/dma-direction.h>
#include <linux/types.h>

/* Maximum distinct tuples retained by one page-sized capture. */
#define IB_VIRT_DMA_MAX_CAPTURE_MAPPINGS 256

struct ib_device;
struct ib_virt_dma;
struct ib_virt_dma_range;

enum ib_virt_dma_atomic_op {
	IB_VIRT_DMA_CMP_SWAP,
	IB_VIRT_DMA_FETCH_ADD,
	IB_VIRT_DMA_WRITE,
};

u64 ib_virt_dma_map(struct ib_device *dev, void *addr, size_t size,
		    enum dma_data_direction direction);
void ib_virt_dma_unmap(struct ib_device *dev, u64 addr, size_t size,
		       enum dma_data_direction direction);
int ib_virt_dma_read(struct ib_device *dev, u64 addr, void *buf, size_t size);
int ib_virt_dma_write(struct ib_device *dev, u64 addr, const void *buf,
		      size_t size);
int ib_virt_dma_atomic(struct ib_device *dev, u64 addr,
		       enum ib_virt_dma_atomic_op op, u64 compare, u64 value,
		       u64 *original);
struct ib_virt_dma_range *ib_virt_dma_range_alloc(struct ib_device *dev,
					       u64 addr, size_t size);
void ib_virt_dma_range_get(struct ib_virt_dma_range *range);
void ib_virt_dma_range_free(struct ib_virt_dma_range *range);
/* Range operations retain the buffer disjointness requirements above. */
int ib_virt_dma_range_read(const struct ib_virt_dma_range *range, size_t offset,
			   void *buf, size_t size);
int ib_virt_dma_range_write(const struct ib_virt_dma_range *range, size_t offset,
			    const void *buf, size_t size);
int ib_virt_dma_range_atomic(const struct ib_virt_dma_range *range, size_t offset,
			     enum ib_virt_dma_atomic_op op, u64 compare,
			     u64 value, u64 *original);
int ib_virt_dma_range_flush(const struct ib_virt_dma_range *range, size_t offset,
			    size_t size);
bool ib_virt_dma_range_is_persistent(const struct ib_virt_dma_range *range,
				     size_t offset, size_t size);
#ifdef CONFIG_INFINIBAND_VIRT_DMA
int ib_virt_dma_enable(struct ib_device *dev);
void ib_virt_dma_release(struct ib_device *dev);
#else
static inline void ib_virt_dma_release(struct ib_device *dev)
{
}
#endif

#endif /* IB_VIRT_DMA_H */
