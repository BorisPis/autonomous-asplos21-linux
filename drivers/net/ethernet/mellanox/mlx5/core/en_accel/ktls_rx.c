// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2019 Mellanox Technologies.

#include <linux/tls.h>
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


struct mlx5e_ktls_offload_context_rx {
	struct tls12_crypto_info_aes_gcm_128 crypto_info;
	struct accel_rule rule;
	struct tls_offload_context_rx *rx_ctx;
	u32 tirn;
	u32 key_id;
};

static int mlx5e_ktls_create_tir(struct mlx5e_priv *priv, u32 *tirn, u32 rqtn)
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
	mlx5e_build_direct_tir_ctx(priv, rqtn, tirc);
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
				       priv_rx->tirn, priv_rx->key_id, false,
				       TLS_OFFLOAD_CTX_DIR_RX);
	icosq_fill_wi(sq, pi, MLX5E_ICOSQ_WQE_UMR_TLS, MLX5E_KTLS_STATIC_WQEBBS,
		      priv_rx);
	sq->pc += MLX5E_KTLS_STATIC_WQEBBS;

	return &wqe->ctrl;
}

static struct mlx5_wqe_ctrl_seg *
post_progress_params(struct mlx5e_icosq *sq,
		     struct mlx5e_ktls_offload_context_rx *priv_rx)
{
	struct mlx5e_set_tls_progress_params_wqe *wqe;
	u16 pi;

	wqe = mlx5e_icosq_fetch_wqe(sq, sizeof(*wqe), &pi);
	mlx5e_ktls_build_progress_params(wqe, sq->pc, sq->sqn, priv_rx->tirn, false,
					 TLS_OFFLOAD_CTX_DIR_RX);
	icosq_fill_wi(sq, pi, MLX5E_ICOSQ_WQE_SET_PSV_TLS, MLX5E_KTLS_SET_PROGRESS_WQEBBS,
		      priv_rx);
	sq->pc += MLX5E_KTLS_SET_PROGRESS_WQEBBS;

	return &wqe->ctrl;
}

static void
mlx5e_ktls_rx_post_param_wqes(struct mlx5e_channel *c,
			      struct mlx5e_ktls_offload_context_rx *priv_rx)
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
	if (unlikely(contig_wqebbs_room <
		     MLX5E_KTLS_STATIC_WQEBBS + MLX5E_KTLS_SET_PROGRESS_WQEBBS))
		mlx5e_fill_icosq_frag_edge(sq, wq, pi, contig_wqebbs_room);

	post_static_params(sq, priv_rx);
	cseg = post_progress_params(sq, priv_rx);
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


int mlx5e_ktls_add_rx(struct net_device *netdev, struct sock *sk,
			  struct tls_crypto_info *crypto_info, u32 key_id,
			  u32 start_offload_tcp_sn)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5e_ktls_offload_context_rx *rx_priv;
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	int rxq = mlx5e_accel_sk_get_rxq(sk);
	u32 rqtn;
	int err;

	rx_priv = kvzalloc(sizeof(*rx_priv), GFP_KERNEL);
	if (!rx_priv) {
		err = -ENOMEM;
		goto fail;
	}

	rx_priv->key_id       = key_id;
	rx_priv->crypto_info  =
		*(struct tls12_crypto_info_aes_gcm_128 *)crypto_info;
	rx_priv->rx_ctx = tls_offload_ctx_rx(tls_ctx);

	mlx5e_set_ktls_rx_priv_ctx(tls_ctx, rx_priv);

	/* tc and underlay_qpn values are not in use for tls tis */
	/* TODO: extract direct rqtn from socket */
	rqtn = priv->direct_tir[rxq].rqt.rqtn;

	/* TODO
	stats->tls_ctx++;*/
	err = mlx5e_ktls_create_tir(priv, &rx_priv->tirn, rqtn);
	if (err)
		goto fail;

	accel_rule_init(&rx_priv->rule, priv, sk);
	mlx5e_ktls_rx_post_param_wqes(/*TODO*/priv->channels.c[rxq], rx_priv);

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

	if (!rx_priv->rule.rule)
		return;

	mlx5_del_flow_rules(rx_priv->rule.rule);
	rx_priv->rule.rule = NULL;
	mlx5_ktls_destroy_key(priv->mdev, rx_priv->key_id);
	mlx5_core_destroy_tir(priv->mdev, rx_priv->tirn);
	kvfree(rx_priv);
}


void mlx5e_ktls_handle_rx_skb(struct net_device *netdev, struct mlx5_cqe64 *cqe,
			      struct sk_buff *skb)
{
	u8 tls_offload = get_cqe_tls_offload(cqe);

	switch (tls_offload) {
	case CQE_TLS_OFFLOAD_DECRYPTED:
		skb->decrypted = 1;
		break;
	case CQE_TLS_OFFLOAD_RESYNC:
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
	/* TODO */
	return -EINVAL;
}

