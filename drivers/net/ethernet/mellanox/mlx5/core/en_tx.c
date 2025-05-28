// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2015-2016, Mellanox Technologies. All rights reserved.
 * Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All righ reserved.
 */

#include <linux/tcp.h>
#include <linux/if_vlan.h>
#include <net/geneve.h>
#include <net/dsfield.h>
#include "en.h"
#include "en/txrx.h"
#include "en_accel/en_accel.h"
#include "en_accel/ipsec_rxtx.h"
#include "en_accel/macsec.h"
#include "en/ptp.h"
#include <net/ipv6.h>

#define MLX5_UNSAFE_MEMCPY_DISCLAIMER				\
	"This copy has been bounds-checked earlier in "		\
	"mlx5i_sq_calc_wqe_attr() and intentionally "		\
	"crosses a flex array boundary. Since it is "		\
	"performance sensitive, splitting the copy is "		\
	"undesirable."

static inline void mlx5e_insert_vlan(void *start, struct sk_buff *skb, u16 ihs)
{
	struct vlan_ethhdr *vhdr = (struct vlan_ethhdr *)start;
	int cpy1_sz = 2 * ETH_ALEN;
	int cpy2_sz = ihs - cpy1_sz;

	memcpy(&vhdr->addrs, skb->data, cpy1_sz);
	vhdr->h_vlan_proto = skb->vlan_proto;
	vhdr->h_vlan_TCI = cpu_to_be16(skb_vlan_tag_get(skb));
	unsafe_memcpy(&vhdr->h_vlan_encapsulated_proto,
		      skb->data + cpy1_sz,
		      cpy2_sz,
		      MLX5_UNSAFE_MEMCPY_DISCLAIMER);
}

static inline void
mlx5e_txwqe_build_eseg_csum(struct mlx5e_txqsq *sq, struct sk_buff *skb,
			    struct mlx5e_accel_tx_state *accel,
			    struct mlx5_wqe_eth_seg *eseg)
{
	if (unlikely(mlx5e_ipsec_txwqe_build_eseg_csum(sq, skb, eseg)))
		return;

	if (likely(skb->ip_summed == CHECKSUM_PARTIAL)) {
		eseg->cs_flags = MLX5_ETH_WQE_L3_CSUM;
		if (skb->encapsulation) {
			eseg->cs_flags |= MLX5_ETH_WQE_L3_INNER_CSUM |
					  MLX5_ETH_WQE_L4_INNER_CSUM;
			sq->stats->csum_partial_inner++;
		} else {
			eseg->cs_flags |= MLX5_ETH_WQE_L4_CSUM;
			sq->stats->csum_partial++;
		}
#ifdef CONFIG_MLX5_EN_TLS
	} else if (unlikely(accel && accel->tls.tls_tisn)) {
		eseg->cs_flags = MLX5_ETH_WQE_L3_CSUM | MLX5_ETH_WQE_L4_CSUM;
		sq->stats->csum_partial++;
#endif
	} else
		sq->stats->csum_none++;
}

static u8
mlx5e_tx_wqe_inline_mode(struct mlx5e_txqsq *sq, struct sk_buff *skb,
			 struct mlx5e_accel_tx_state *accel)
{
	u8 mode;

#ifdef CONFIG_MLX5_EN_TLS
	if (accel && accel->tls.tls_tisn)
		return MLX5_INLINE_MODE_TCP_UDP;
#endif

	mode = sq->min_inline_mode;

	if (skb_vlan_tag_present(skb) &&
	    test_bit(MLX5E_SQ_STATE_VLAN_NEED_L2_INLINE, &sq->state))
		mode = max_t(u8, MLX5_INLINE_MODE_L2, mode);

	return mode;
}

static void mlx5e_sq_xmit_prepare(struct mlx5e_txqsq *sq, struct sk_buff *skb,
				  struct mlx5e_accel_tx_state *accel,
				  struct mlx5e_tx_attr *attr)
{
	struct mlx5e_sq_stats *stats = sq->stats;

	if (skb_is_gso(skb)) {
		int hopbyhop;
		u16 ihs = mlx5e_tx_get_gso_ihs(sq, skb, &hopbyhop);

		*attr = (struct mlx5e_tx_attr) {
			.opcode    = MLX5_OPCODE_LSO,
			.mss       = cpu_to_be16(skb_shinfo(skb)->gso_size),
			.ihs       = ihs,
			.num_bytes = skb->len + (skb_shinfo(skb)->gso_segs - 1) * ihs,
			.headlen   = skb_headlen(skb) - ihs - hopbyhop,
			.hopbyhop  = hopbyhop,
		};

		stats->packets += skb_shinfo(skb)->gso_segs;
	} else {
		u8 mode = mlx5e_tx_wqe_inline_mode(sq, skb, accel);
		u16 ihs = mlx5e_calc_min_inline(mode, skb);

		*attr = (struct mlx5e_tx_attr) {
			.opcode    = MLX5_OPCODE_SEND,
			.mss       = cpu_to_be16(0),
			.ihs       = ihs,
			.num_bytes = max_t(unsigned int, skb->len, ETH_ZLEN),
			.headlen   = skb_headlen(skb) - ihs,
		};

		stats->packets++;
	}

	attr->insz = mlx5e_accel_tx_ids_len(sq, accel);
	stats->bytes += attr->num_bytes;
}

static void mlx5e_sq_calc_wqe_attr(struct sk_buff *skb, const struct mlx5e_tx_attr *attr,
				   struct mlx5e_tx_wqe_attr *wqe_attr)
{
	u16 ds_cnt = MLX5E_TX_WQE_EMPTY_DS_COUNT;
	u16 ds_cnt_inl = 0;
	u16 ds_cnt_ids = 0;

	/* Sync the calculation with MLX5E_MAX_TX_WQEBBS. */

	if (attr->insz)
		ds_cnt_ids = DIV_ROUND_UP(sizeof(struct mlx5_wqe_inline_seg) + attr->insz,
					  MLX5_SEND_WQE_DS);

	ds_cnt += !!attr->headlen + skb_shinfo(skb)->nr_frags + ds_cnt_ids;
	if (attr->ihs) {
		u16 inl = attr->ihs - INL_HDR_START_SZ;

		if (skb_vlan_tag_present(skb))
			inl += VLAN_HLEN;

		ds_cnt_inl = DIV_ROUND_UP(inl, MLX5_SEND_WQE_DS);
		if (WARN_ON_ONCE(ds_cnt_inl > MLX5E_MAX_TX_INLINE_DS))
			netdev_warn(skb->dev, "ds_cnt_inl = %u > max %u\n", ds_cnt_inl,
				    (u16)MLX5E_MAX_TX_INLINE_DS);
		ds_cnt += ds_cnt_inl;
	}

	*wqe_attr = (struct mlx5e_tx_wqe_attr) {
		.ds_cnt     = ds_cnt,
		.ds_cnt_inl = ds_cnt_inl,
		.ds_cnt_ids = ds_cnt_ids,
		.num_wqebbs = DIV_ROUND_UP(ds_cnt, MLX5_SEND_WQEBB_NUM_DS),
	};
}

static void mlx5e_tx_skb_update_ts_flags(struct sk_buff *skb)
{
	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP))
		skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
	skb_tx_timestamp(skb);
}

static void mlx5e_tx_check_stop(struct mlx5e_txqsq *sq)
{
	if (unlikely(!mlx5e_wqc_has_room_for(&sq->wq, sq->cc, sq->pc, sq->stop_room))) {
		netif_tx_stop_queue(sq->txq);
		sq->stats->stopped++;
	}
}

void mlx5e_tx_flush(struct mlx5e_txqsq *sq)
{
	struct mlx5e_tx_wqe_info *wi;
	struct mlx5e_tx_wqe *wqe;
	u16 pi;

	/* Must not be called when a MPWQE session is active but empty. */
	mlx5e_tx_mpwqe_ensure_complete(sq);

	pi = mlx5_wq_cyc_ctr2ix(&sq->wq, sq->pc);
	wi = &sq->db.wqe_info[pi];

	*wi = (struct mlx5e_tx_wqe_info) {
		.num_wqebbs = 1,
	};

	wqe = mlx5e_post_nop(&sq->wq, sq->sqn, &sq->pc);
	mlx5e_notify_hw(&sq->wq, sq->pc, sq->uar_map, &wqe->ctrl);
}
EXPORT_SYMBOL(mlx5e_tx_flush);

void mlx5e_txwqe_complete(struct mlx5e_txqsq *sq, struct sk_buff *skb,
			  const struct mlx5e_tx_attr *attr,
			  const struct mlx5e_tx_wqe_attr *wqe_attr, u8 num_dma,
			  struct mlx5e_tx_wqe_info *wi,
			  struct mlx5_wqe_ctrl_seg *cseg,
			  struct mlx5_wqe_eth_seg *eseg, bool xmit_more)
{
	struct mlx5_wq_cyc *wq = &sq->wq;
	bool send_doorbell;

	*wi = (struct mlx5e_tx_wqe_info) {
		.skb = skb,
		.num_bytes = attr->num_bytes,
		.num_dma = num_dma,
		.num_wqebbs = wqe_attr->num_wqebbs,
		.num_fifo_pkts = 0,
	};

	cseg->opmod_idx_opcode = cpu_to_be32((sq->pc << 8) | attr->opcode);
	cseg->qpn_ds           = cpu_to_be32((sq->sqn << 8) | wqe_attr->ds_cnt);

	mlx5e_tx_skb_update_ts_flags(skb);

	sq->pc += wi->num_wqebbs;

	mlx5e_tx_check_stop(sq);

	if (unlikely(sq->ptpsq &&
		     (skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP))) {
		u8 metadata_index = be32_to_cpu(eseg->flow_table_metadata);

		mlx5e_ptp_metadata_fifo_pop(&sq->ptpsq->metadata_freelist);

		mlx5e_skb_cb_hwtstamp_init(skb);
		mlx5e_ptp_metadata_map_put(&sq->ptpsq->metadata_map, skb,
					   metadata_index);
		/* ensure skb is put on metadata_map before tracking the index */
		wmb();
		mlx5e_ptpsq_track_metadata(sq->ptpsq, metadata_index);
		if (!netif_tx_queue_stopped(sq->txq) &&
		    mlx5e_ptpsq_metadata_freelist_empty(sq->ptpsq)) {
			netif_tx_stop_queue(sq->txq);
			sq->stats->stopped++;
		}
		skb_get(skb);
	}

	send_doorbell = __netdev_tx_sent_queue(sq->txq, attr->num_bytes, xmit_more);
	if (send_doorbell)
		mlx5e_notify_hw(wq, sq->pc, sq->uar_map, cseg);
}
EXPORT_SYMBOL(mlx5e_txwqe_complete);

static void
mlx5e_sq_xmit_wqe(struct mlx5e_txqsq *sq, struct sk_buff *skb,
		  const struct mlx5e_tx_attr *attr, const struct mlx5e_tx_wqe_attr *wqe_attr,
		  struct mlx5e_tx_wqe *wqe, u16 pi, bool xmit_more)
{
	struct mlx5_wqe_ctrl_seg *cseg;
	struct mlx5_wqe_eth_seg  *eseg;
	struct mlx5_wqe_data_seg *dseg;
	struct mlx5e_tx_wqe_info *wi;
	u16 ihs = attr->ihs;
	struct ipv6hdr *h6;
	struct mlx5e_sq_stats *stats = sq->stats;
	int num_dma;

	stats->xmit_more += xmit_more;

	/* fill wqe */
	wi   = &sq->db.wqe_info[pi];
	cseg = &wqe->ctrl;
	eseg = &wqe->eth;
	dseg =  wqe->data;

	eseg->mss = attr->mss;

	if (ihs) {
		u8 *start = eseg->inline_hdr.start;

		if (unlikely(attr->hopbyhop)) {
			/* remove the HBH header.
			 * Layout: [Ethernet header][IPv6 header][HBH][TCP header]
			 */
			if (skb_vlan_tag_present(skb)) {
				mlx5e_insert_vlan(start, skb, ETH_HLEN + sizeof(*h6));
				ihs += VLAN_HLEN;
				h6 = (struct ipv6hdr *)(start + sizeof(struct vlan_ethhdr));
			} else {
				unsafe_memcpy(start, skb->data,
					      ETH_HLEN + sizeof(*h6),
					      MLX5_UNSAFE_MEMCPY_DISCLAIMER);
				h6 = (struct ipv6hdr *)(start + ETH_HLEN);
			}
			h6->nexthdr = IPPROTO_TCP;
			/* Copy the TCP header after the IPv6 one */
			memcpy(h6 + 1,
			       skb->data + ETH_HLEN + sizeof(*h6) +
					sizeof(struct hop_jumbo_hdr),
			       tcp_hdrlen(skb));
			/* Leave ipv6 payload_len set to 0, as LSO v2 specs request. */
		} else if (skb_vlan_tag_present(skb)) {
			mlx5e_insert_vlan(start, skb, ihs);
			ihs += VLAN_HLEN;
			stats->added_vlan_packets++;
		} else {
			unsafe_memcpy(eseg->inline_hdr.start, skb->data,
				      attr->ihs,
				      MLX5_UNSAFE_MEMCPY_DISCLAIMER);
		}
		eseg->inline_hdr.sz |= cpu_to_be16(ihs);
		dseg += wqe_attr->ds_cnt_inl;
	} else if (skb_vlan_tag_present(skb)) {
		eseg->insert.type = cpu_to_be16(MLX5_ETH_WQE_INSERT_VLAN);
		if (skb->vlan_proto == cpu_to_be16(ETH_P_8021AD))
			eseg->insert.type |= cpu_to_be16(MLX5_ETH_WQE_SVLAN);
		eseg->insert.vlan_tci = cpu_to_be16(skb_vlan_tag_get(skb));
		stats->added_vlan_packets++;
	}

	dseg += wqe_attr->ds_cnt_ids;
	num_dma = mlx5e_txwqe_build_dsegs(sq, skb, skb->data + attr->ihs + attr->hopbyhop,
					  attr->headlen, dseg);
	if (unlikely(num_dma < 0))
		goto err_drop;

	mlx5e_txwqe_complete(sq, skb, attr, wqe_attr, num_dma, wi, cseg, eseg, xmit_more);

	return;

err_drop:
	stats->dropped++;
	dev_kfree_skb_any(skb);
	mlx5e_tx_flush(sq);
}

static bool mlx5e_tx_skb_supports_mpwqe(struct sk_buff *skb, struct mlx5e_tx_attr *attr)
{
	return !skb_is_nonlinear(skb) && !skb_vlan_tag_present(skb) && !attr->ihs &&
	       !attr->insz && !mlx5e_macsec_skb_is_offload(skb);
}

static bool mlx5e_tx_mpwqe_same_eseg(struct mlx5e_txqsq *sq, struct mlx5_wqe_eth_seg *eseg)
{
	struct mlx5e_tx_mpwqe *session = &sq->mpwqe;

	/* Assumes the session is already running and has at least one packet. */
	return !memcmp(&session->wqe->eth, eseg, MLX5E_ACCEL_ESEG_LEN);
}

static void mlx5e_tx_mpwqe_session_start(struct mlx5e_txqsq *sq,
					 struct mlx5_wqe_eth_seg *eseg)
{
	struct mlx5e_tx_mpwqe *session = &sq->mpwqe;
	struct mlx5e_tx_wqe *wqe;
	u16 pi, num_wqebbs;

	pi = mlx5e_txqsq_get_next_pi_anysize(sq, &num_wqebbs);
	wqe = MLX5E_TX_FETCH_WQE(sq, pi);
	net_prefetchw(wqe->data);

	*session = (struct mlx5e_tx_mpwqe) {
		.wqe = wqe,
		.bytes_count = 0,
		.ds_count = MLX5E_TX_WQE_EMPTY_DS_COUNT,
		.ds_count_max = num_wqebbs * MLX5_SEND_WQEBB_NUM_DS,
		.pkt_count = 0,
		.inline_on = 0,
	};

	memcpy(&session->wqe->eth, eseg, MLX5E_ACCEL_ESEG_LEN);

	sq->stats->mpwqe_blks++;
}

static bool mlx5e_tx_mpwqe_session_is_active(struct mlx5e_txqsq *sq)
{
	return sq->mpwqe.wqe;
}

static void mlx5e_tx_mpwqe_add_dseg(struct mlx5e_txqsq *sq, struct mlx5e_xmit_data *txd)
{
	struct mlx5e_tx_mpwqe *session = &sq->mpwqe;
	struct mlx5_wqe_data_seg *dseg;

	dseg = (struct mlx5_wqe_data_seg *)session->wqe + session->ds_count;

	session->pkt_count++;
	session->bytes_count += txd->len;

	dseg->addr = cpu_to_be64(txd->dma_addr);
	dseg->byte_count = cpu_to_be32(txd->len);
	dseg->lkey = sq->mkey_be;
	session->ds_count++;

	sq->stats->mpwqe_pkts++;
}

static struct mlx5_wqe_ctrl_seg *mlx5e_tx_mpwqe_session_complete(struct mlx5e_txqsq *sq)
{
	struct mlx5e_tx_mpwqe *session = &sq->mpwqe;
	u8 ds_count = session->ds_count;
	struct mlx5_wqe_ctrl_seg *cseg;
	struct mlx5e_tx_wqe_info *wi;
	u16 pi;

	cseg = &session->wqe->ctrl;
	cseg->opmod_idx_opcode = cpu_to_be32((sq->pc << 8) | MLX5_OPCODE_ENHANCED_MPSW);
	cseg->qpn_ds = cpu_to_be32((sq->sqn << 8) | ds_count);

	pi = mlx5_wq_cyc_ctr2ix(&sq->wq, sq->pc);
	wi = &sq->db.wqe_info[pi];
	*wi = (struct mlx5e_tx_wqe_info) {
		.skb = NULL,
		.num_bytes = session->bytes_count,
		.num_wqebbs = DIV_ROUND_UP(ds_count, MLX5_SEND_WQEBB_NUM_DS),
		.num_dma = session->pkt_count,
		.num_fifo_pkts = session->pkt_count,
	};

	sq->pc += wi->num_wqebbs;

	session->wqe = NULL;

	mlx5e_tx_check_stop(sq);

	return cseg;
}

static void
mlx5e_sq_xmit_mpwqe(struct mlx5e_txqsq *sq, struct sk_buff *skb,
		    struct mlx5_wqe_eth_seg *eseg, bool xmit_more)
{
	struct mlx5_wqe_ctrl_seg *cseg;
	struct mlx5e_xmit_data txd;

	txd.data = skb->data;
	txd.len = skb->len;

	txd.dma_addr = dma_map_single(sq->pdev, txd.data, txd.len, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(sq->pdev, txd.dma_addr)))
		goto err_unmap;

	if (!mlx5e_tx_mpwqe_session_is_active(sq)) {
		mlx5e_tx_mpwqe_session_start(sq, eseg);
	} else if (!mlx5e_tx_mpwqe_same_eseg(sq, eseg)) {
		mlx5e_tx_mpwqe_session_complete(sq);
		mlx5e_tx_mpwqe_session_start(sq, eseg);
	}

	sq->stats->xmit_more += xmit_more;

	mlx5e_dma_push(sq, txd.dma_addr, txd.len, MLX5E_DMA_MAP_SINGLE);
	mlx5e_skb_fifo_push(&sq->db.skb_fifo, skb);
	mlx5e_tx_mpwqe_add_dseg(sq, &txd);
	mlx5e_tx_skb_update_ts_flags(skb);

	if (unlikely(mlx5e_tx_mpwqe_is_full(&sq->mpwqe))) {
		/* Might stop the queue and affect the retval of __netdev_tx_sent_queue. */
		cseg = mlx5e_tx_mpwqe_session_complete(sq);

		if (__netdev_tx_sent_queue(sq->txq, txd.len, xmit_more))
			mlx5e_notify_hw(&sq->wq, sq->pc, sq->uar_map, cseg);
	} else if (__netdev_tx_sent_queue(sq->txq, txd.len, xmit_more)) {
		/* Might stop the queue, but we were asked to ring the doorbell anyway. */
		cseg = mlx5e_tx_mpwqe_session_complete(sq);

		mlx5e_notify_hw(&sq->wq, sq->pc, sq->uar_map, cseg);
	}

	return;

err_unmap:
	sq->stats->dropped++;
	dev_kfree_skb_any(skb);
	mlx5e_tx_flush(sq);
}

void mlx5e_tx_mpwqe_ensure_complete(struct mlx5e_txqsq *sq)
{
	/* Unlikely in non-MPWQE workloads; not important in MPWQE workloads. */
	if (unlikely(mlx5e_tx_mpwqe_session_is_active(sq)))
		mlx5e_tx_mpwqe_session_complete(sq);
}

static void mlx5e_cqe_ts_id_eseg(struct mlx5e_ptpsq *ptpsq, struct sk_buff *skb,
				 struct mlx5_wqe_eth_seg *eseg)
{
	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP))
		eseg->flow_table_metadata =
			cpu_to_be32(mlx5e_ptp_metadata_fifo_peek(&ptpsq->metadata_freelist));
}

static void mlx5e_txwqe_build_eseg(struct mlx5e_priv *priv, struct mlx5e_txqsq *sq,
				   struct sk_buff *skb, struct mlx5e_accel_tx_state *accel,
				   struct mlx5_wqe_eth_seg *eseg, u16 ihs)
{
	mlx5e_accel_tx_eseg(priv, skb, eseg, ihs);
	mlx5e_txwqe_build_eseg_csum(sq, skb, accel, eseg);
	if (unlikely(sq->ptpsq))
		mlx5e_cqe_ts_id_eseg(sq->ptpsq, skb, eseg);
}

netdev_tx_t mlx5e_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5e_accel_tx_state accel = {};
	struct mlx5e_tx_wqe_attr wqe_attr;
	struct mlx5e_tx_attr attr;
	struct mlx5e_tx_wqe *wqe;
	struct mlx5e_txqsq *sq;
	u16 pi;

	/* All changes to txq2sq are performed in sync with mlx5e_xmit, when the
	 * queue being changed is disabled, and smp_wmb guarantees that the
	 * changes are visible before mlx5e_xmit tries to read from txq2sq. It
	 * guarantees that the value of txq2sq[qid] doesn't change while
	 * mlx5e_xmit is running on queue number qid. smb_wmb is paired with
	 * HARD_TX_LOCK around ndo_start_xmit, which serves as an ACQUIRE.
	 */
	sq = priv->txq2sq[skb_get_queue_mapping(skb)];
	if (unlikely(!sq)) {
		/* Two cases when sq can be NULL:
		 * 1. The HTB node is registered, and mlx5e_select_queue
		 * selected its queue ID, but the SQ itself is not yet created.
		 * 2. HTB SQ creation failed. Similar to the previous case, but
		 * the SQ won't be created.
		 */
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	/* May send SKBs and WQEs. */
	if (unlikely(!mlx5e_accel_tx_begin(dev, sq, skb, &accel)))
		return NETDEV_TX_OK;

	mlx5e_sq_xmit_prepare(sq, skb, &accel, &attr);

	if (test_bit(MLX5E_SQ_STATE_MPWQE, &sq->state)) {
		if (mlx5e_tx_skb_supports_mpwqe(skb, &attr)) {
			struct mlx5_wqe_eth_seg eseg = {};

			mlx5e_txwqe_build_eseg(priv, sq, skb, &accel, &eseg, attr.ihs);
			mlx5e_sq_xmit_mpwqe(sq, skb, &eseg, netdev_xmit_more());
			return NETDEV_TX_OK;
		}

		mlx5e_tx_mpwqe_ensure_complete(sq);
	}

	mlx5e_sq_calc_wqe_attr(skb, &attr, &wqe_attr);
	pi = mlx5e_txqsq_get_next_pi(sq, wqe_attr.num_wqebbs);
	wqe = MLX5E_TX_FETCH_WQE(sq, pi);

	/* May update the WQE, but may not post other WQEs. */
	mlx5e_accel_tx_finish(sq, wqe, &accel,
			      (struct mlx5_wqe_inline_seg *)(wqe->data + wqe_attr.ds_cnt_inl));
	mlx5e_txwqe_build_eseg(priv, sq, skb, &accel, &wqe->eth, attr.ihs);
	mlx5e_sq_xmit_wqe(sq, skb, &attr, &wqe_attr, wqe, pi, netdev_xmit_more());

	return NETDEV_TX_OK;
}

static void mlx5e_tx_wi_dma_unmap(struct mlx5e_txqsq *sq, struct mlx5e_tx_wqe_info *wi,
				  u32 *dma_fifo_cc)
{
	int i;

	for (i = 0; i < wi->num_dma; i++) {
		struct mlx5e_sq_dma *dma = mlx5e_dma_get(sq, (*dma_fifo_cc)++);

		mlx5e_tx_dma_unmap(sq->pdev, dma);
	}
}

static void mlx5e_consume_skb(struct mlx5e_txqsq *sq, struct sk_buff *skb,
			      struct mlx5_cqe64 *cqe, int napi_budget)
{
	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)) {
		struct skb_shared_hwtstamps hwts = {};
		u64 ts = get_cqe_ts(cqe);

		hwts.hwtstamp = mlx5e_cqe_ts_to_ns(sq->ptp_cyc2time, sq->clock, ts);
		if (sq->ptpsq) {
			mlx5e_skb_cb_hwtstamp_handler(skb, MLX5E_SKB_CB_CQE_HWTSTAMP,
						      hwts.hwtstamp, sq->ptpsq->cq_stats);
		} else {
			skb_tstamp_tx(skb, &hwts);
			sq->stats->timestamps++;
		}
	}

	napi_consume_skb(skb, napi_budget);
}

static void mlx5e_tx_wi_consume_fifo_skbs(struct mlx5e_txqsq *sq, struct mlx5e_tx_wqe_info *wi,
					  struct mlx5_cqe64 *cqe, int napi_budget)
{
	int i;

	for (i = 0; i < wi->num_fifo_pkts; i++) {
		struct sk_buff *skb = mlx5e_skb_fifo_pop(&sq->db.skb_fifo);

		mlx5e_consume_skb(sq, skb, cqe, napi_budget);
	}
}

void mlx5e_txqsq_wake(struct mlx5e_txqsq *sq)
{
	if (netif_tx_queue_stopped(sq->txq) &&
	    mlx5e_wqc_has_room_for(&sq->wq, sq->cc, sq->pc, sq->stop_room) &&
	    !mlx5e_ptpsq_metadata_freelist_empty(sq->ptpsq) &&
	    !test_bit(MLX5E_SQ_STATE_RECOVERING, &sq->state)) {
		netif_tx_wake_queue(sq->txq);
		sq->stats->wake++;
	}
}

bool mlx5e_poll_tx_cq(struct mlx5e_cq *cq, int napi_budget)
{
	struct mlx5e_sq_stats *stats;
	struct mlx5e_txqsq *sq;
	struct mlx5_cqe64 *cqe;
	u32 dma_fifo_cc;
	u32 nbytes;
	u16 npkts;
	u16 sqcc;
	int i;

	sq = container_of(cq, struct mlx5e_txqsq, cq);

	if (unlikely(!test_bit(MLX5E_SQ_STATE_ENABLED, &sq->state)))
		return false;

	cqe = mlx5_cqwq_get_cqe(&cq->wq);
	if (!cqe)
		return false;

	stats = sq->stats;

	npkts = 0;
	nbytes = 0;

	/* sq->cc must be updated only after mlx5_cqwq_update_db_record(),
	 * otherwise a cq overrun may occur
	 */
	sqcc = sq->cc;

	/* avoid dirtying sq cache line every cqe */
	dma_fifo_cc = sq->dma_fifo_cc;

	i = 0;
	do {
		struct mlx5e_tx_wqe_info *wi;
		u16 wqe_counter;
		bool last_wqe;
		u16 ci;

		mlx5_cqwq_pop(&cq->wq);

		wqe_counter = be16_to_cpu(cqe->wqe_counter);

		do {
			last_wqe = (sqcc == wqe_counter);

			ci = mlx5_wq_cyc_ctr2ix(&sq->wq, sqcc);
			wi = &sq->db.wqe_info[ci];

			sqcc += wi->num_wqebbs;

			if (likely(wi->skb)) {
				mlx5e_tx_wi_dma_unmap(sq, wi, &dma_fifo_cc);
				mlx5e_consume_skb(sq, wi->skb, cqe, napi_budget);

				npkts++;
				nbytes += wi->num_bytes;
				continue;
			}

			if (unlikely(mlx5e_ktls_tx_try_handle_resync_dump_comp(sq, wi,
									       &dma_fifo_cc)))
				continue;

			if (wi->num_fifo_pkts) {
				mlx5e_tx_wi_dma_unmap(sq, wi, &dma_fifo_cc);
				mlx5e_tx_wi_consume_fifo_skbs(sq, wi, cqe, napi_budget);

				npkts += wi->num_fifo_pkts;
				nbytes += wi->num_bytes;
			}
		} while (!last_wqe);

		if (unlikely(get_cqe_opcode(cqe) == MLX5_CQE_REQ_ERR)) {
			if (!test_and_set_bit(MLX5E_SQ_STATE_RECOVERING,
					      &sq->state)) {
				mlx5e_dump_error_cqe(&sq->cq, sq->sqn,
						     (struct mlx5_err_cqe *)cqe);
				mlx5_wq_cyc_wqe_dump(&sq->wq, ci, wi->num_wqebbs);
				queue_work(cq->workqueue, &sq->recover_work);
			}
			stats->cqe_err++;
		}

	} while ((++i < MLX5E_TX_CQ_POLL_BUDGET) && (cqe = mlx5_cqwq_get_cqe(&cq->wq)));

	stats->cqes += i;

	mlx5_cqwq_update_db_record(&cq->wq);

	/* ensure cq space is freed before enabling more cqes */
	wmb();

	sq->dma_fifo_cc = dma_fifo_cc;
	sq->cc = sqcc;

	netdev_tx_completed_queue(sq->txq, npkts, nbytes);

	mlx5e_txqsq_wake(sq);

	return (i == MLX5E_TX_CQ_POLL_BUDGET);
}

static void mlx5e_tx_wi_kfree_fifo_skbs(struct mlx5e_txqsq *sq, struct mlx5e_tx_wqe_info *wi)
{
	int i;

	for (i = 0; i < wi->num_fifo_pkts; i++)
		dev_kfree_skb_any(mlx5e_skb_fifo_pop(&sq->db.skb_fifo));
}

void mlx5e_free_txqsq_descs(struct mlx5e_txqsq *sq)
{
	struct mlx5e_tx_wqe_info *wi;
	u32 dma_fifo_cc, nbytes = 0;
	u16 ci, sqcc, npkts = 0;

	sqcc = sq->cc;
	dma_fifo_cc = sq->dma_fifo_cc;

	while (sqcc != sq->pc) {
		ci = mlx5_wq_cyc_ctr2ix(&sq->wq, sqcc);
		wi = &sq->db.wqe_info[ci];

		sqcc += wi->num_wqebbs;

		if (likely(wi->skb)) {
			mlx5e_tx_wi_dma_unmap(sq, wi, &dma_fifo_cc);
			dev_kfree_skb_any(wi->skb);

			npkts++;
			nbytes += wi->num_bytes;
			continue;
		}

		if (unlikely(mlx5e_ktls_tx_try_handle_resync_dump_comp(sq, wi, &dma_fifo_cc)))
			continue;

		if (wi->num_fifo_pkts) {
			mlx5e_tx_wi_dma_unmap(sq, wi, &dma_fifo_cc);
			mlx5e_tx_wi_kfree_fifo_skbs(sq, wi);

			npkts += wi->num_fifo_pkts;
			nbytes += wi->num_bytes;
		}
	}

	sq->dma_fifo_cc = dma_fifo_cc;
	sq->cc = sqcc;

	netdev_tx_completed_queue(sq->txq, npkts, nbytes);
}
