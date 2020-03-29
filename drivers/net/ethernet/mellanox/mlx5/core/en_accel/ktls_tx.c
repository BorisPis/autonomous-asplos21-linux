// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2019 Mellanox Technologies.

#include <linux/tls.h>
#include "en.h"
#include "en/txrx.h"
#include "en_accel/ktls.h"
#include "en_accel/ktls_txrx.h"
#include "en_accel/ktls_utils.h"

int mlx5e_ktls_get_sq_room(void)
{
	return MLX5_SEND_WQE_MAX_WQEBBS +
		MLX5E_KTLS_STATIC_WQEBBS + MLX5E_KTLS_SET_PROGRESS_WQEBBS;
}

struct mlx5e_dump_wqe {
	struct mlx5_wqe_ctrl_seg ctrl;
	struct mlx5_wqe_data_seg data;
};

#define MLX5E_KTLS_DUMP_WQEBBS \
	(DIV_ROUND_UP(sizeof(struct mlx5e_dump_wqe), MLX5_SEND_WQE_BB))

u8 mlx5e_ktls_dumps_num_wqebbs(struct mlx5e_txqsq *sq, unsigned int nfrags,
			       unsigned int sync_len)
{
	/* Given the MTU and sync_len, calculates an upper bound for the
	 * number of WQEBBs needed for the TX resync DUMP WQEs of a record.
	 */
	return MLX5E_KTLS_DUMP_WQEBBS *
		(nfrags + DIV_ROUND_UP(sync_len, sq->hw_mtu));
}

static int mlx5e_ktls_create_tis(struct mlx5_core_dev *mdev, u32 *tisn)
{
	u32 in[MLX5_ST_SZ_DW(create_tis_in)] = {};
	void *tisc;

	tisc = MLX5_ADDR_OF(create_tis_in, in, ctx);

	MLX5_SET(tisc, tisc, tls_en, 1);

	return mlx5e_create_tis(mdev, in, tisn);
}

struct mlx5e_ktls_offload_context_tx {
	struct tls_offload_context_tx *tx_ctx;
	struct tls12_crypto_info_aes_gcm_128 crypto_info;
	u32 expected_seq;
	u32 tisn;
	u32 key_id;
	bool ctx_post_pending;
};

static inline void
mlx5e_set_ktls_tx_priv_ctx(struct tls_context *tls_ctx,
			   struct mlx5e_ktls_offload_context_tx *priv_tx)
{
	struct mlx5e_ktls_offload_context_tx **ctx =
		__tls_driver_ctx(tls_ctx, TLS_OFFLOAD_CTX_DIR_TX);

	BUILD_BUG_ON(sizeof(struct mlx5e_ktls_offload_context_tx *) >
		     TLS_OFFLOAD_CONTEXT_SIZE_TX);

	*ctx = priv_tx;
}

static inline struct mlx5e_ktls_offload_context_tx *
mlx5e_get_ktls_tx_priv_ctx(struct tls_context *tls_ctx)
{
	struct mlx5e_ktls_offload_context_tx **ctx =
		__tls_driver_ctx(tls_ctx, TLS_OFFLOAD_CTX_DIR_TX);

	BUILD_BUG_ON(sizeof(struct mlx5e_ktls_offload_context_tx *) >
		     TLS_OFFLOAD_CONTEXT_SIZE_TX);

	return *ctx;
}

void mlx5e_ktls_tx_offload_set_pending(struct mlx5e_ktls_offload_context_tx *priv_tx);

int mlx5e_ktls_add_tx(struct net_device *netdev, struct sock *sk,
			     struct tls_crypto_info *crypto_info, u32 key_id,
			     u32 start_offload_tcp_sn)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct mlx5e_ktls_offload_context_tx *tx_priv;
	struct mlx5_core_dev *mdev = priv->mdev;
	int err;

	tx_priv = kvzalloc(sizeof(*tx_priv), GFP_KERNEL);
	if (!tx_priv) {
		err = -ENOMEM;
		goto fail;
	}

	tx_priv->key_id       = key_id;
	tx_priv->expected_seq = start_offload_tcp_sn;
	tx_priv->crypto_info  =
		*(struct tls12_crypto_info_aes_gcm_128 *)crypto_info;
	tx_priv->tx_ctx = tls_offload_ctx_tx(tls_ctx);

	mlx5e_set_ktls_tx_priv_ctx(tls_ctx, tx_priv);

	/* tc and underlay_qpn values are not in use for tls tis */
	err = mlx5e_ktls_create_tis(mdev, &tx_priv->tisn);
	if (err)
		goto fail;

	mlx5e_ktls_tx_offload_set_pending(tx_priv);

	return 0;

	/* TODO fix error flows */
fail:
/*create_tis_fail:
	kvfree(tx_priv);*/
	return err;
}

void mlx5e_ktls_del_tx(struct net_device *netdev,
			      struct tls_context *tls_ctx)
{
	struct mlx5e_ktls_offload_context_tx *tx_priv =
		mlx5e_get_ktls_tx_priv_ctx(tls_ctx);
	struct mlx5e_priv *priv = netdev_priv(netdev);

	mlx5_ktls_destroy_key(priv->mdev, tx_priv->key_id);
	mlx5e_destroy_tis(priv->mdev, tx_priv->tisn);
	kvfree(tx_priv);
}

static void tx_fill_wi(struct mlx5e_txqsq *sq,
		       u16 pi, u8 num_wqebbs, u32 num_bytes,
		       struct page *page)
{
	struct mlx5e_tx_wqe_info *wi = &sq->db.wqe_info[pi];

	*wi = (struct mlx5e_tx_wqe_info) {
		.num_wqebbs = num_wqebbs,
		.num_bytes  = num_bytes,
		.resync_dump_frag_page = page,
	};
}

void mlx5e_ktls_tx_offload_set_pending(struct mlx5e_ktls_offload_context_tx *priv_tx)
{
	priv_tx->ctx_post_pending = true;
}

static bool
mlx5e_ktls_tx_offload_test_and_clear_pending(struct mlx5e_ktls_offload_context_tx *priv_tx)
{
	bool ret = priv_tx->ctx_post_pending;

	priv_tx->ctx_post_pending = false;

	return ret;
}

static void
post_static_params(struct mlx5e_txqsq *sq,
		   struct mlx5e_ktls_offload_context_tx *priv_tx,
		   bool fence)
{
	struct mlx5e_set_tls_static_params_wqe *wqe;
	u16 pi;

	wqe = mlx5e_sq_fetch_wqe(sq, sizeof(*wqe), &pi);
	mlx5e_ktls_build_static_params(wqe, sq->pc, sq->sqn, &priv_tx->crypto_info,
				       priv_tx->tisn, priv_tx->key_id, fence,
				       TLS_OFFLOAD_CTX_DIR_TX);
	tx_fill_wi(sq, pi, MLX5E_KTLS_STATIC_WQEBBS, 0, NULL);
	sq->pc += MLX5E_KTLS_STATIC_WQEBBS;
}

static void
post_progress_params(struct mlx5e_txqsq *sq,
		     struct mlx5e_ktls_offload_context_tx *priv_tx,
		     bool fence)
{
	struct mlx5e_set_tls_progress_params_wqe *wqe;
	u16 pi;

	wqe = mlx5e_sq_fetch_wqe(sq, sizeof(*wqe), &pi);
	mlx5e_ktls_build_progress_params(wqe, sq->pc, sq->sqn, priv_tx->tisn, fence,
					 TLS_OFFLOAD_CTX_DIR_TX);
	tx_fill_wi(sq, pi, MLX5E_KTLS_SET_PROGRESS_WQEBBS, 0, NULL);
	sq->pc += MLX5E_KTLS_SET_PROGRESS_WQEBBS;
}

static void
mlx5e_ktls_tx_post_param_wqes(struct mlx5e_txqsq *sq,
			      struct mlx5e_ktls_offload_context_tx *priv_tx,
			      bool skip_static_post, bool fence_first_post)
{
	bool progress_fence = skip_static_post || !fence_first_post;
	struct mlx5_wq_cyc *wq = &sq->wq;
	u16 contig_wqebbs_room, pi;

	pi = mlx5_wq_cyc_ctr2ix(wq, sq->pc);
	contig_wqebbs_room = mlx5_wq_cyc_get_contig_wqebbs(wq, pi);
	if (unlikely(contig_wqebbs_room <
		     MLX5E_KTLS_STATIC_WQEBBS + MLX5E_KTLS_SET_PROGRESS_WQEBBS))
		mlx5e_fill_sq_frag_edge(sq, wq, pi, contig_wqebbs_room);

	if (!skip_static_post)
		post_static_params(sq, priv_tx, fence_first_post);

	post_progress_params(sq, priv_tx, progress_fence);
}

struct tx_sync_info {
	u64 rcd_sn;
	u32 sync_len;
	int nr_frags;
	skb_frag_t frags[MAX_SKB_FRAGS];
};

enum mlx5e_ktls_sync_retval {
	MLX5E_KTLS_SYNC_DONE,
	MLX5E_KTLS_SYNC_FAIL,
	MLX5E_KTLS_SYNC_SKIP_NO_DATA,
};

static enum mlx5e_ktls_sync_retval
tx_sync_info_get(struct mlx5e_ktls_offload_context_tx *priv_tx,
		 u32 tcp_seq, int datalen, struct tx_sync_info *info)
{
	struct tls_offload_context_tx *tx_ctx = priv_tx->tx_ctx;
	enum mlx5e_ktls_sync_retval ret = MLX5E_KTLS_SYNC_DONE;
	struct tls_record_info *record;
	int remaining, i = 0;
	unsigned long flags;
	bool ends_before;

	spin_lock_irqsave(&tx_ctx->lock, flags);
	record = tls_get_record(tx_ctx, tcp_seq, &info->rcd_sn);

	if (unlikely(!record)) {
		ret = MLX5E_KTLS_SYNC_FAIL;
		goto out;
	}

	/* There are the following cases:
	 * 1. packet ends before start marker: bypass offload.
	 * 2. packet starts before start marker and ends after it: drop,
	 *    not supported, breaks contract with kernel.
	 * 3. packet ends before tls record info starts: drop,
	 *    this packet was already acknowledged and its record info
	 *    was released.
	 */
	ends_before = before(tcp_seq + datalen, tls_record_start_seq(record));

	if (unlikely(tls_record_is_start_marker(record))) {
		ret = ends_before ? MLX5E_KTLS_SYNC_SKIP_NO_DATA : MLX5E_KTLS_SYNC_FAIL;
		goto out;
	} else if (ends_before) {
		ret = MLX5E_KTLS_SYNC_FAIL;
		goto out;
	}

	info->sync_len = tcp_seq - tls_record_start_seq(record);
	remaining = info->sync_len;
	while (remaining > 0) {
		skb_frag_t *frag = &record->frags[i];

		get_page(skb_frag_page(frag));
		remaining -= skb_frag_size(frag);
		info->frags[i++] = *frag;
	}
	/* reduce the part which will be sent with the original SKB */
	if (remaining < 0)
		skb_frag_size_add(&info->frags[i - 1], remaining);
	info->nr_frags = i;
out:
	spin_unlock_irqrestore(&tx_ctx->lock, flags);
	return ret;
}

static void
tx_post_resync_params(struct mlx5e_txqsq *sq,
		      struct mlx5e_ktls_offload_context_tx *priv_tx,
		      u64 rcd_sn)
{
	struct tls12_crypto_info_aes_gcm_128 *info = &priv_tx->crypto_info;
	__be64 rn_be = cpu_to_be64(rcd_sn);
	bool skip_static_post;
	u16 rec_seq_sz;
	char *rec_seq;

	rec_seq = info->rec_seq;
	rec_seq_sz = sizeof(info->rec_seq);

	skip_static_post = !memcmp(rec_seq, &rn_be, rec_seq_sz);
	if (!skip_static_post)
		memcpy(rec_seq, &rn_be, rec_seq_sz);

	mlx5e_ktls_tx_post_param_wqes(sq, priv_tx, skip_static_post, true);
}

static int
tx_post_resync_dump(struct mlx5e_txqsq *sq, skb_frag_t *frag, u32 tisn, bool first)
{
	struct mlx5_wqe_ctrl_seg *cseg;
	struct mlx5_wqe_data_seg *dseg;
	struct mlx5e_dump_wqe *wqe;
	dma_addr_t dma_addr = 0;
	u16 ds_cnt;
	int fsz;
	u16 pi;

	wqe = mlx5e_sq_fetch_wqe(sq, sizeof(*wqe), &pi);

	ds_cnt = sizeof(*wqe) / MLX5_SEND_WQE_DS;

	cseg = &wqe->ctrl;
	dseg = &wqe->data;

	cseg->opmod_idx_opcode = cpu_to_be32((sq->pc << 8)  | MLX5_OPCODE_DUMP);
	cseg->qpn_ds           = cpu_to_be32((sq->sqn << 8) | ds_cnt);
	cseg->tisn             = cpu_to_be32(tisn << 8);
	cseg->fm_ce_se         = first ? MLX5_FENCE_MODE_INITIATOR_SMALL : 0;

	fsz = skb_frag_size(frag);
	dma_addr = skb_frag_dma_map(sq->pdev, frag, 0, fsz,
				    DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(sq->pdev, dma_addr)))
		return -ENOMEM;

	dseg->addr       = cpu_to_be64(dma_addr);
	dseg->lkey       = sq->mkey_be;
	dseg->byte_count = cpu_to_be32(fsz);
	mlx5e_dma_push(sq, dma_addr, fsz, MLX5E_DMA_MAP_PAGE);

	tx_fill_wi(sq, pi, MLX5E_KTLS_DUMP_WQEBBS, fsz, skb_frag_page(frag));
	sq->pc += MLX5E_KTLS_DUMP_WQEBBS;

	return 0;
}

void mlx5e_ktls_tx_handle_resync_dump_comp(struct mlx5e_txqsq *sq,
					   struct mlx5e_tx_wqe_info *wi,
					   u32 *dma_fifo_cc)
{
	struct mlx5e_sq_stats *stats;
	struct mlx5e_sq_dma *dma;

	if (!wi->resync_dump_frag_page)
		return;

	dma = mlx5e_dma_get(sq, (*dma_fifo_cc)++);
	stats = sq->stats;

	mlx5e_tx_dma_unmap(sq->pdev, dma);
	put_page(wi->resync_dump_frag_page);
	stats->tls_dump_packets++;
	stats->tls_dump_bytes += wi->num_bytes;
}

static void tx_post_fence_nop(struct mlx5e_txqsq *sq)
{
	struct mlx5_wq_cyc *wq = &sq->wq;
	u16 pi = mlx5_wq_cyc_ctr2ix(wq, sq->pc);

	tx_fill_wi(sq, pi, 1, 0, NULL);

	mlx5e_post_nop_fence(wq, sq->sqn, &sq->pc);
}

static enum mlx5e_ktls_sync_retval
mlx5e_ktls_tx_handle_ooo(struct mlx5e_ktls_offload_context_tx *priv_tx,
			 struct mlx5e_txqsq *sq,
			 int datalen,
			 u32 seq)
{
	struct mlx5e_sq_stats *stats = sq->stats;
	struct mlx5_wq_cyc *wq = &sq->wq;
	enum mlx5e_ktls_sync_retval ret;
	struct tx_sync_info info = {};
	u16 contig_wqebbs_room, pi;
	u8 num_wqebbs;
	int i = 0;

	ret = tx_sync_info_get(priv_tx, seq, datalen, &info);
	if (unlikely(ret != MLX5E_KTLS_SYNC_DONE)) {
		if (ret == MLX5E_KTLS_SYNC_SKIP_NO_DATA) {
			stats->tls_skip_no_sync_data++;
			return MLX5E_KTLS_SYNC_SKIP_NO_DATA;
		}
		/* We might get here if a retransmission reaches the driver
		 * after the relevant record is acked.
		 * It should be safe to drop the packet in this case
		 */
		stats->tls_drop_no_sync_data++;
		goto err_out;
	}

	stats->tls_ooo++;

	tx_post_resync_params(sq, priv_tx, info.rcd_sn);

	/* If no dump WQE was sent, we need to have a fence NOP WQE before the
	 * actual data xmit.
	 */
	if (!info.nr_frags) {
		tx_post_fence_nop(sq);
		return MLX5E_KTLS_SYNC_DONE;
	}

	num_wqebbs = mlx5e_ktls_dumps_num_wqebbs(sq, info.nr_frags, info.sync_len);
	pi = mlx5_wq_cyc_ctr2ix(wq, sq->pc);
	contig_wqebbs_room = mlx5_wq_cyc_get_contig_wqebbs(wq, pi);

	if (unlikely(contig_wqebbs_room < num_wqebbs))
		mlx5e_fill_sq_frag_edge(sq, wq, pi, contig_wqebbs_room);

	for (; i < info.nr_frags; i++) {
		unsigned int orig_fsz, frag_offset = 0, n = 0;
		skb_frag_t *f = &info.frags[i];

		orig_fsz = skb_frag_size(f);

		do {
			bool fence = !(i || frag_offset);
			unsigned int fsz;

			n++;
			fsz = min_t(unsigned int, sq->hw_mtu, orig_fsz - frag_offset);
			skb_frag_size_set(f, fsz);
			if (tx_post_resync_dump(sq, f, priv_tx->tisn, fence)) {
				page_ref_add(skb_frag_page(f), n - 1);
				goto err_out;
			}

			skb_frag_off_add(f, fsz);
			frag_offset += fsz;
		} while (frag_offset < orig_fsz);

		page_ref_add(skb_frag_page(f), n - 1);
	}

	return MLX5E_KTLS_SYNC_DONE;

err_out:
	for (; i < info.nr_frags; i++)
		/* The put_page() here undoes the page ref obtained in tx_sync_info_get().
		 * Page refs obtained for the DUMP WQEs above (by page_ref_add) will be
		 * released only upon their completions (or in mlx5e_free_txqsq_descs,
		 * if channel closes).
		 */
		put_page(skb_frag_page(&info.frags[i]));

	return MLX5E_KTLS_SYNC_FAIL;
}

struct sk_buff *mlx5e_ktls_handle_tx_skb(struct net_device *netdev,
					 struct mlx5e_txqsq *sq,
					 struct sk_buff *skb,
					 struct mlx5e_tx_wqe **wqe, u16 *pi)
{
	struct mlx5e_ktls_offload_context_tx *priv_tx;
	struct mlx5e_sq_stats *stats = sq->stats;
	struct mlx5_wqe_ctrl_seg *cseg;
	struct tls_context *tls_ctx;
	int datalen;
	u32 seq;

	if (!skb->sk || !tls_is_sk_tx_device_offloaded(skb->sk))
		goto out;

	datalen = skb->len - (skb_transport_offset(skb) + tcp_hdrlen(skb));
	if (!datalen)
		goto out;

	tls_ctx = tls_get_ctx(skb->sk);
	if (WARN_ON_ONCE(tls_ctx->netdev != netdev))
		goto err_out;

	priv_tx = mlx5e_get_ktls_tx_priv_ctx(tls_ctx);

	if (unlikely(mlx5e_ktls_tx_offload_test_and_clear_pending(priv_tx))) {
		mlx5e_ktls_tx_post_param_wqes(sq, priv_tx, false, false);
		*wqe = mlx5e_sq_fetch_wqe(sq, sizeof(**wqe), pi);
		stats->tls_ctx++;
	}

	seq = ntohl(tcp_hdr(skb)->seq);
	if (unlikely(priv_tx->expected_seq != seq)) {
		enum mlx5e_ktls_sync_retval ret =
			mlx5e_ktls_tx_handle_ooo(priv_tx, sq, datalen, seq);

		switch (ret) {
		case MLX5E_KTLS_SYNC_DONE:
			*wqe = mlx5e_sq_fetch_wqe(sq, sizeof(**wqe), pi);
			break;
		case MLX5E_KTLS_SYNC_SKIP_NO_DATA:
			if (likely(!skb->decrypted))
				goto out;
			WARN_ON_ONCE(1);
			/* fall-through */
		default: /* MLX5E_KTLS_SYNC_FAIL */
			goto err_out;
		}
	}

	priv_tx->expected_seq = seq + datalen;

	cseg = &(*wqe)->ctrl;
	cseg->tisn = cpu_to_be32(priv_tx->tisn << 8);

	stats->tls_encrypted_packets += skb_is_gso(skb) ? skb_shinfo(skb)->gso_segs : 1;
	stats->tls_encrypted_bytes   += datalen;

out:
	return skb;

err_out:
	dev_kfree_skb_any(skb);
	return NULL;
}
