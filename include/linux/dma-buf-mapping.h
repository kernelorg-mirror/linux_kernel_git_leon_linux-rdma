/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * DMA BUF Mapping Helpers
 *
 */
#ifndef __DMA_BUF_MAPPING_H__
#define __DMA_BUF_MAPPING_H__
#include <linux/dma-buf.h>

enum pci_p2pdma_map_type
dma_buf_p2pdma_map_type(struct dma_buf_attachment *attach,
			unsigned int tlp_flags);
struct sg_table *dma_buf_phys_vec_to_sgt(struct dma_buf_attachment *attach,
					 struct phys_vec *phys_vec,
					 size_t nr_ranges, size_t size,
					 enum dma_data_direction dir);
void dma_buf_free_sgt(struct dma_buf_attachment *attach, struct sg_table *sgt,
		      enum dma_data_direction dir);
#endif
