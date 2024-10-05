/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BLK_MQ_DMA_H
#define BLK_MQ_DMA_H

#include <linux/blk-mq.h>
#include <linux/pci-p2pdma.h>

struct blk_dma_iter {
	struct req_iterator		iter;
	struct pci_p2pdma_map_state	p2pdma;

	dma_addr_t			addr;
	u32				len;

	blk_status_t			status;
};

bool blk_rq_dma_map_iter_start(struct request *req, struct device *dma_dev,
		struct dma_iova_state *state, struct blk_dma_iter *iter);
bool blk_rq_dma_map_iter_next(struct request *req, struct device *dma_dev,
		struct dma_iova_state *state, struct blk_dma_iter *iter);

enum blk_dma_unmap {
	BLK_DMA_UNMAP_NONE,
	BLK_DMA_UNMAP_IOVA,
	BLK_DMA_UNMAP_SINGLE,
};

static inline enum blk_dma_unmap blk_rq_dma_unmap(struct request *req,
		struct device *dma_dev, struct dma_iova_state *state)
{
	if (!(req->cmd_flags & REQ_P2PDMA)) {
		if (dma_can_use_iova(state))
			return BLK_DMA_UNMAP_IOVA;
		if (dma_need_unmap(dma_dev))
			return BLK_DMA_UNMAP_SINGLE;
	}

	return BLK_DMA_UNMAP_NONE;
}

#endif /* BLK_MQ_DMA_H */
