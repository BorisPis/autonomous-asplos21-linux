// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2019 Mellanox Technologies.

#include <linux/tls.h>
#include <net/inet6_hashtables.h>
#include "en.h"
#include "en/txrx.h"
#include "en_accel/en_accel.h"
#include "en_accel/ktls.h"
#include "en_accel/ktls_txrx.h"
#include "en_accel/ktls_utils.h"
#include "en_accel/fs.h"

struct accel_rule {
	struct work_struct      work;
	struct mlx5e_priv	*priv;
	struct mlx5_flow_handle *rule;
/*	struct hlist_node	hlist;
	int			rxq;*/
	struct sock            *sk;
	/*struct arfs_tuple	tuple;*/
};

#define PROGRESS_PARAMS_WRITE_UNIT	(64)
#define PROGRESS_PARAMS_PADDED_SIZE	\
		(ALIGN(sizeof(struct mlx5_seg_tls_progress_params), \
		       PROGRESS_PARAMS_WRITE_UNIT))

struct mlx5e_ktls_rx_resync_ctx {
	struct work_struct work;
	struct mlx5e_priv *priv;

	bool is_response;
	u32 hw_seq;
	u32 sw_seq;
	__be64 sw_rcd_sn_be;

	union {
		struct mlx5_seg_tls_progress_params progress;
		u8 pad[PROGRESS_PARAMS_PADDED_SIZE];
	} ____cacheline_aligned_in_smp;
};

struct mlx5e_ktls_offload_context_rx {
	struct tls12_crypto_info_aes_gcm_128 crypto_info;
	struct accel_rule rule;
	struct tls_offload_context_rx *rx_ctx;
	u32 tirn;
	u32 key_id;
	u32 rxq;
	/* get psv */
	struct mlx5e_ktls_rx_resync_ctx resync;
};

static void mlx5e_ktls_build_direct_tir_ctx(struct mlx5_core_dev *mdev,
					    u32 rqn, u32 *tirc)
{
	MLX5_SET(tirc, tirc, transport_domain, mdev->mlx5e_res.td.tdn);
	MLX5_SET(tirc, tirc, disp_type, MLX5_TIRC_DISP_TYPE_DIRECT);
	MLX5_SET(tirc, tirc, inline_rqn, rqn);
}

static int mlx5e_ktls_create_tir(struct mlx5e_priv *priv, u32 *tirn, u32 rqn)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	int err, inlen;
	void *tirc;
	u32 *in;

	/* TODO do not allocate per socket */
	inlen = MLX5_ST_SZ_BYTES(create_tir_in);
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);
	/* TODO improve: cache the context */
	mlx5e_ktls_build_direct_tir_ctx(mdev, rqn, tirc);
	MLX5_SET(tirc, tirc, tls_en, 1);
	MLX5_SET(tirc, tirc, self_lb_block,
		 MLX5_TIRC_SELF_LB_BLOCK_BLOCK_UNICAST |
		 MLX5_TIRC_SELF_LB_BLOCK_BLOCK_MULTICAST);

	err = mlx5_core_create_tir(mdev, in, inlen, tirn);

	kvfree(in);
	return err;
}

static void accel_handle_work(struct work_struct *work)
{
	struct accel_rule *accel_rule =
		container_of(work, struct accel_rule, work);
	struct mlx5_flow_handle *rule;
	struct mlx5e_ktls_offload_context_rx *priv_rx =
		container_of(accel_rule, struct mlx5e_ktls_offload_context_rx, rule);

	rule = mlx5e_accel_fs_add_flow(accel_rule->priv, accel_rule->sk,
				       priv_rx->tirn, MLX5_FS_DEFAULT_FLOW_TAG);
	if (IS_ERR_OR_NULL(rule))
		/* TODO */
		printk(KERN_DEBUG "TT: accel_add_rule failed!\n");
	else
		accel_rule->rule = rule;
}

static void accel_rule_init(struct accel_rule *rule, struct mlx5e_priv *priv,
			    struct sock *sk)
{
	INIT_WORK(&rule->work, accel_handle_work);
	rule->priv = priv;
	rule->sk   = sk;
}

static void icosq_fill_wi(struct mlx5e_icosq *sq,
			  u16 pi, u8 wqe_type, u8 num_wqebbs,
			  struct mlx5e_ktls_offload_context_rx *priv_rx)
{
	struct mlx5e_icosq_wqe_info *wi = &sq->db.ico_wqe[pi];

	*wi = (struct mlx5e_icosq_wqe_info) {
		.wqe_type      = wqe_type,
		.num_wqebbs    = num_wqebbs,
		.accel.priv_rx = priv_rx,
	};
}

static struct mlx5_wqe_ctrl_seg *
post_static_params(struct mlx5e_icosq *sq,
		   struct mlx5e_ktls_offload_context_rx *priv_rx)
{
	struct mlx5e_set_tls_static_params_wqe *wqe;
	u16 pi;

	wqe = mlx5e_icosq_fetch_wqe(sq, sizeof(*wqe), &pi);
	mlx5e_ktls_build_static_params(wqe, sq->pc, sq->sqn, &priv_rx->crypto_info,
				       priv_rx->tirn, priv_rx->key_id,
				       priv_rx->resync.hw_seq, false,
				       TLS_OFFLOAD_CTX_DIR_RX);
	icosq_fill_wi(sq, pi, MLX5E_ICOSQ_WQE_UMR_TLS, MLX5E_KTLS_STATIC_WQEBBS,
		      priv_rx);
	sq->pc += MLX5E_KTLS_STATIC_WQEBBS;

	return &wqe->ctrl;
}

static struct mlx5_wqe_ctrl_seg *
post_progress_params(struct mlx5e_icosq *sq,
		     struct mlx5e_ktls_offload_context_rx *priv_rx,
		     u32 next_record_tcp_sn)
{
	struct mlx5e_set_tls_progress_params_wqe *wqe;
	u16 pi;

	wqe = mlx5e_icosq_fetch_wqe(sq, sizeof(*wqe), &pi);
	mlx5e_ktls_build_progress_params(wqe, sq->pc, sq->sqn, priv_rx->tirn, false,
					 next_record_tcp_sn,
					 TLS_OFFLOAD_CTX_DIR_RX);
	icosq_fill_wi(sq, pi, MLX5E_ICOSQ_WQE_SET_PSV_TLS, MLX5E_KTLS_SET_PROGRESS_WQEBBS,
		      priv_rx);
	sq->pc += MLX5E_KTLS_SET_PROGRESS_WQEBBS;

	return &wqe->ctrl;
}

static struct mlx5e_get_psv_wqe *
post_get_progress_params(struct mlx5e_icosq *sq,
			 struct mlx5e_ktls_offload_context_rx *priv_rx)
{
	struct mlx5_wqe_ctrl_seg *cseg;
	struct mlx5e_get_psv_wqe *wqe;
	struct mlx5_seg_get_psv *psv;
	struct device *pdev;
	dma_addr_t dma_addr;
	u16 pi;

	pdev = sq->channel->pdev;

	dma_addr = dma_map_single(pdev, &priv_rx->resync.progress,
				  PROGRESS_PARAMS_PADDED_SIZE,
				  DMA_FROM_DEVICE);
	if (unlikely(dma_mapping_error(pdev, dma_addr)))
		return NULL;

	wqe = mlx5e_icosq_fetch_wqe(sq, sizeof(*wqe), &pi);

#define GET_PSV_DS_CNT (DIV_ROUND_UP(sizeof(*wqe), MLX5_SEND_WQE_DS))

	cseg = &wqe->ctrl;
	cseg->opmod_idx_opcode =
		cpu_to_be32((sq->pc << 8) | MLX5_OPCODE_GET_PSV |
			    (MLX5_OPC_MOD_TLS_TIR_PROGRESS_PARAMS << 24));
	cseg->qpn_ds =
		cpu_to_be32((sq->sqn << MLX5_WQE_CTRL_QPN_SHIFT) | GET_PSV_DS_CNT);

	psv = &wqe->psv;
	psv->num_psv      = 1 << 4;
	psv->l_key        = sq->channel->mkey_be;
	psv->psv_index[0] = cpu_to_be32(priv_rx->tirn);
	psv->va           = cpu_to_be64(dma_addr);

	icosq_fill_wi(sq, pi, MLX5E_ICOSQ_WQE_GET_PSV_TLS, 1 /* TODO use macro? */,
		      priv_rx);
	sq->pc++;

	return wqe;
}

void
mlx5e_ktls_rx_post_get_psv(struct mlx5e_priv *priv,
			   struct mlx5e_ktls_offload_context_rx *priv_rx)
{
	struct mlx5e_get_psv_wqe *wqe;
	struct mlx5e_icosq *sq;
	struct mlx5_wq_cyc *wq;
	struct mlx5e_channel *c = priv->channels.c[priv_rx->rxq];

	sq = &c->async_icosq;
	wq = &sq->wq;

	spin_lock(&c->async_icosq_lock);

	if (unlikely(!mlx5e_wqc_has_room_for(wq, sq->cc, sq->pc, mlx5e_ktls_get_sq_room())))
		pr_err("%s no room cc %d pc %d\n", __func__, sq->cc, sq->pc);

	wqe = post_get_progress_params(sq, priv_rx);
	if (likely(wqe))
		mlx5e_notify_hw(wq, sq->pc, sq->uar_map, &wqe->ctrl);

	spin_unlock(&c->async_icosq_lock);
}

static void handle_seq_match(struct mlx5e_ktls_offload_context_rx *priv_rx,
			     struct mlx5e_icosq *sq)
{
	struct tls12_crypto_info_aes_gcm_128 *info = &priv_rx->crypto_info;
	u8 *ctx = priv_rx->resync.progress.ctx;

	u16 contig_wqebbs_room, pi;
	struct mlx5_wqe_ctrl_seg *cseg;
	struct mlx5_wq_cyc *wq;

	u8 tracker_state = MLX5_GET(tls_progress_params, ctx, record_tracker_state);
	u8 auth_state = MLX5_GET(tls_progress_params, ctx, auth_state);

	if (tracker_state != MLX5_TLS_PROGRESS_PARAMS_RECORD_TRACKER_STATE_TRACKING ||
	    auth_state != MLX5_TLS_PROGRESS_PARAMS_AUTH_STATE_NO_OFFLOAD)
		return;

	memcpy(info->rec_seq, &priv_rx->resync.sw_rcd_sn_be, sizeof(info->rec_seq));

	wq = &sq->wq;

	pi = mlx5_wq_cyc_ctr2ix(wq, sq->pc);
	if (unlikely(!mlx5e_wqc_has_room_for(wq, sq->cc, sq->pc, mlx5e_ktls_get_sq_room())))
		pr_err("%s no room cc %d pc %d\n", __func__, sq->cc, sq->pc);
	contig_wqebbs_room = mlx5_wq_cyc_get_contig_wqebbs(wq, pi);
	if (unlikely(contig_wqebbs_room <
		     MLX5E_KTLS_STATIC_WQEBBS + MLX5E_KTLS_SET_PROGRESS_WQEBBS))
		mlx5e_fill_icosq_frag_edge(sq, wq, pi, contig_wqebbs_room);

	cseg = post_static_params(sq, priv_rx);
	mlx5e_notify_hw(wq, sq->pc, sq->uar_map, cseg);

}

static void accel_handle_resync_work(struct work_struct *work)
{
	struct mlx5e_ktls_rx_resync_ctx *resync =
		container_of(work, struct mlx5e_ktls_rx_resync_ctx, work);
	struct mlx5e_ktls_offload_context_rx *priv_rx =
		container_of(resync, struct mlx5e_ktls_offload_context_rx, resync);

	if (resync->is_response) {
		struct mlx5e_channel *c = resync->priv->channels.c[priv_rx->rxq];
		struct mlx5e_icosq *sq = &c->async_icosq;

		spin_lock(&c->async_icosq_lock);
		handle_seq_match(priv_rx, sq);
		spin_unlock(&c->async_icosq_lock);
	} else {
		mlx5e_ktls_rx_post_get_psv(resync->priv, priv_rx);
	}

}

void mlx5e_accel_rx_resync_init(struct mlx5e_ktls_rx_resync_ctx *resync,
				struct mlx5e_priv *priv)
{
	INIT_WORK(&resync->work, accel_handle_resync_work);
	resync->priv = priv;
}

static void
mlx5e_ktls_rx_post_param_wqes(struct mlx5e_channel *c,
			      struct mlx5e_ktls_offload_context_rx *priv_rx,
			      u32 next_record_tcp_sn)
{
	struct mlx5_wqe_ctrl_seg *cseg;
	u16 contig_wqebbs_room, pi;
	struct mlx5e_icosq *sq;
	struct mlx5_wq_cyc *wq;

	spin_lock(&c->async_icosq_lock);

	sq = &c->async_icosq;
	wq = &sq->wq;

	pi = mlx5_wq_cyc_ctr2ix(wq, sq->pc);
	contig_wqebbs_room = mlx5_wq_cyc_get_contig_wqebbs(wq, pi);
	if (unlikely(!mlx5e_wqc_has_room_for(wq, sq->cc, sq->pc, mlx5e_ktls_get_sq_room())))
		pr_err("%s no room cc %d pc %d\n", __func__, sq->cc, sq->pc);
	if (unlikely(contig_wqebbs_room <
		     MLX5E_KTLS_STATIC_WQEBBS + MLX5E_KTLS_SET_PROGRESS_WQEBBS))
		mlx5e_fill_icosq_frag_edge(sq, wq, pi, contig_wqebbs_room);

	post_static_params(sq, priv_rx);
	cseg = post_progress_params(sq, priv_rx, next_record_tcp_sn);
	mlx5e_notify_hw(wq, sq->pc, sq->uar_map, cseg);

	spin_unlock(&c->async_icosq_lock);
}

static inline void
mlx5e_set_ktls_rx_priv_ctx(struct tls_context *tls_ctx,
			   struct mlx5e_ktls_offload_context_rx *priv_rx)
{
	struct mlx5e_ktls_offload_context_rx **ctx =
		__tls_driver_ctx(tls_ctx, TLS_OFFLOAD_CTX_DIR_RX);

	BUILD_BUG_ON(sizeof(struct mlx5e_ktls_offload_context_rx *) >
		     TLS_OFFLOAD_CONTEXT_SIZE_RX);

	*ctx = priv_rx;
}

static inline struct mlx5e_ktls_offload_context_rx *
mlx5e_get_ktls_rx_priv_ctx(struct tls_context *tls_ctx)
{
	struct mlx5e_ktls_offload_context_rx **ctx =
		__tls_driver_ctx(tls_ctx, TLS_OFFLOAD_CTX_DIR_RX);

	BUILD_BUG_ON(sizeof(struct mlx5e_ktls_offload_context_rx *) >
		     TLS_OFFLOAD_CONTEXT_SIZE_RX);

	return *ctx;
}

static struct mlx5e_rq_stats *
ktls_get_rq_stats(struct mlx5e_priv *priv, int rxq)
{
	struct mlx5e_channel *c = priv->channels.c[rxq];

	return c->rq.stats;
}

int mlx5e_ktls_add_rx(struct net_device *netdev, struct sock *sk,
			  struct tls_crypto_info *crypto_info, u32 key_id,
			  u32 start_offload_tcp_sn)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5e_ktls_offload_context_rx *rx_priv;
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	int rxq = mlx5e_accel_sk_get_rxq(sk);
	struct mlx5e_channel *c;
	u32 rqn;
	int err;

	rx_priv = kvzalloc(sizeof(*rx_priv), GFP_KERNEL);
	if (!rx_priv) {
		err = -ENOMEM;
		goto fail;
	}

	rx_priv->rxq          = rxq;
	rx_priv->key_id       = key_id;
	rx_priv->crypto_info  =
		*(struct tls12_crypto_info_aes_gcm_128 *)crypto_info;
	rx_priv->rx_ctx = tls_offload_ctx_rx(tls_ctx);

	mlx5e_set_ktls_rx_priv_ctx(tls_ctx, rx_priv);

	/* tc and underlay_qpn values are not in use for tls tis */
	/* TODO: extract direct rqtn from socket */
	c = priv->channels.c[rxq];
	rqn = c->rq.rqn;

	ktls_get_rq_stats(priv, rxq)->tls_ctx++;
	/* TODO
	stats->tls_ctx++;*/
	err = mlx5e_ktls_create_tir(priv, &rx_priv->tirn, rqn);
	if (err)
		goto fail;

	printk(KERN_DEBUG "TT: %s, %d, rxq = 0x%x, rqn = 0x%x, tir created: 0x%x\n",
	       __func__, __LINE__, rxq, rqn, rx_priv->tirn);
	accel_rule_init(&rx_priv->rule, priv, sk);
	mlx5e_accel_rx_resync_init(&rx_priv->resync, priv);
	mlx5e_ktls_rx_post_param_wqes(priv->channels.c[rxq], rx_priv, start_offload_tcp_sn);

	return 0;

	/* TODO fix error flows */
fail:
/*create_tis_fail:
	kvfree(tx_priv);*/
	return err;
}

void mlx5e_ktls_del_rx(struct net_device *netdev,
			      struct tls_context *tls_ctx)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5e_ktls_offload_context_rx *rx_priv =
		mlx5e_get_ktls_rx_priv_ctx(tls_ctx);

	/* TODO
	ktls_get_rq_stats(priv, rxq)->tls_del++; */
	if (!rx_priv->rule.rule)
		return;

	flush_workqueue(priv->wq);

	mlx5_del_flow_rules(rx_priv->rule.rule);
	rx_priv->rule.rule = NULL;
	mlx5_core_destroy_tir(priv->mdev, rx_priv->tirn);
	mlx5_ktls_destroy_key(priv->mdev, rx_priv->key_id);
	kvfree(rx_priv);
}

void mlx5e_ktls_handle_get_psv_completion(struct mlx5e_icosq_wqe_info *wi,
					  struct mlx5e_icosq *sq)
{
	struct mlx5e_ktls_offload_context_rx *priv_rx = wi->accel.priv_rx;
	struct mlx5_seg_tls_progress_params *progress = &priv_rx->resync.progress;
	struct mlx5e_channel *c = sq->channel;
	struct net_device *netdev = c->netdev;
	struct mlx5e_priv *priv = netdev_priv(netdev);
	u8 *ctx = progress->ctx;

	//print_hex_dump(KERN_WARNING, "", DUMP_PREFIX_OFFSET, 16, 1,
	//	       progress, sizeof(*progress), false);

	priv_rx->resync.hw_seq = MLX5_GET(tls_progress_params, ctx, hw_resync_tcp_sn);
	priv_rx->resync.is_response = true;
	if (priv_rx->resync.hw_seq == priv_rx->resync.sw_seq)
		queue_work(priv->wq, &priv_rx->resync.work);
}

static void queue_get_psv(struct net_device *netdev, struct sock *sk)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct mlx5e_ktls_offload_context_rx *rx_priv =
		mlx5e_get_ktls_rx_priv_ctx(tls_ctx);
	struct mlx5e_ktls_rx_resync_ctx *resync = &rx_priv->resync;
	struct mlx5e_priv *priv = netdev_priv(netdev);

	resync->is_response = false;
	queue_work(priv->wq /* TODO Use separate TLS queue? */ , &resync->work);
}

static int ktls_update_resync_sn(struct net_device *netdev,
				 struct sk_buff *skb)
{
	struct ethhdr *eth = (struct ethhdr *)(skb->data);
	struct sock *sk = NULL;
	int network_depth = 0;
	struct iphdr *iph;
	struct tcphdr *th;

	__vlan_get_protocol(skb, eth->h_proto, &network_depth);
	iph = (struct iphdr *)(skb->data + network_depth);

	if (iph->version == 4) {
		th = (void *)iph + sizeof(struct iphdr);

		sk = inet_lookup_established(dev_net(netdev), &tcp_hashinfo,
					     iph->saddr, th->source, iph->daddr,
					     th->dest, netdev->ifindex);
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		struct ipv6hdr *ipv6h = (struct ipv6hdr *)iph;

		th = (void *)ipv6h + sizeof(struct ipv6hdr);

		sk = __inet6_lookup_established(dev_net(netdev), &tcp_hashinfo,
						&ipv6h->saddr, th->source,
						&ipv6h->daddr, ntohs(th->dest),
						netdev->ifindex, 0);
#endif
	}

	if (unlikely(!sk || sk->sk_state == TCP_TIME_WAIT))
		goto out;

	/* TODO move? */
	queue_get_psv(netdev, sk);

	skb->sk = sk;
	skb->destructor = sock_edemux;

	tls_offload_rx_resync_request(sk, 0, true);

out:
	return 0;
}

void mlx5e_ktls_handle_rx_skb(struct mlx5e_rq *rq, struct mlx5_cqe64 *cqe,
			      u32 cqe_bcnt, struct sk_buff *skb)
{
	u8 tls_offload = get_cqe_tls_offload(cqe);

	switch (tls_offload) {
	case CQE_TLS_OFFLOAD_DECRYPTED:
		skb->decrypted = 1;
		rq->stats->tls_decrypted_packets++;
		rq->stats->tls_decrypted_bytes += cqe_bcnt;
		break;
	case CQE_TLS_OFFLOAD_RESYNC:
		ktls_update_resync_sn(rq->netdev, skb);
		rq->stats->tls_ooo++;
		break;
	case CQE_TLS_OFFLOAD_ERROR:
		/* TODO */
		break;
	default:
		break;
	}
}

void mlx5e_ktls_handle_ctx_completion(struct mlx5e_icosq_wqe_info *wi)
{
	struct accel_rule *rule = &wi->accel.priv_rx->rule;

	queue_work(rule->priv->fs.accel.wq, &rule->work);
}

/* Re-sync */
int mlx5e_ktls_rx_resync(struct net_device *netdev, struct sock *sk,
			 u32 seq, u8 *rcd_sn)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct mlx5e_ktls_offload_context_rx *rx_priv =
		mlx5e_get_ktls_rx_priv_ctx(tls_ctx);
	struct mlx5e_ktls_rx_resync_ctx *resync = &rx_priv->resync;

	resync->sw_rcd_sn_be = *(__be64 *)rcd_sn;
	resync->sw_seq       = seq - (TLS_HEADER_SIZE - 1);

	if (resync->hw_seq == resync->sw_seq) {
		struct mlx5e_priv *priv = netdev_priv(netdev);
		int rxq = mlx5e_accel_sk_get_rxq(sk);
		struct mlx5e_channel *c = priv->channels.c[rxq];
		struct mlx5e_icosq *sq;

		sq = &c->async_icosq;

		spin_lock(&c->async_icosq_lock);

		handle_seq_match(rx_priv, sq);
		spin_unlock(&c->async_icosq_lock);
	} else {
		tls_offload_rx_resync_request(sk, seq, true);
	}

	return 0;
}
