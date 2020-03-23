// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2019 Mellanox Technologies.

#include "en.h"
#include "en_accel/ktls.h"
#include "en_accel/ktls_utils.h"

static int mlx5e_ktls_add(struct net_device *netdev, struct sock *sk,
			  enum tls_offload_ctx_dir direction,
			  struct tls_crypto_info *crypto_info,
			  u32 start_offload_tcp_sn)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	u32 key_id;
	int err;

	if (WARN_ON(!mlx5e_ktls_type_check(mdev, crypto_info)))
		return -EOPNOTSUPP;

	err = mlx5_ktls_create_key(mdev, crypto_info, &key_id);
	if (err)
		goto fail;

	if (direction == TLS_OFFLOAD_CTX_DIR_TX)
		err = mlx5e_ktls_add_tx(netdev, sk, crypto_info, key_id,
					start_offload_tcp_sn);
	else
		err = mlx5e_ktls_add_rx(netdev, sk, crypto_info, key_id,
					start_offload_tcp_sn);

	if (err)
		goto fail;

	return 0;

fail:
	/* TODO */
	return err;
}

static void mlx5e_ktls_del(struct net_device *netdev,
			   struct tls_context *tls_ctx,
			   enum tls_offload_ctx_dir direction)
{
	if (direction == TLS_OFFLOAD_CTX_DIR_TX)
		mlx5e_ktls_del_tx(netdev, tls_ctx);
	else
		mlx5e_ktls_del_rx(netdev, tls_ctx);
}

static int mlx5e_ktls_resync(struct net_device *netdev,
			     struct sock *sk, u32 seq, u8 *rcd_sn,
			     enum tls_offload_ctx_dir direction)
{
	if (unlikely(direction != TLS_OFFLOAD_CTX_DIR_RX))
		return -EINVAL;

	return mlx5e_ktls_rx_resync(netdev, sk, seq, rcd_sn);
}

static const struct tlsdev_ops mlx5e_ktls_ops = {
	.tls_dev_add = mlx5e_ktls_add,
	.tls_dev_del = mlx5e_ktls_del,
	.tls_dev_resync = mlx5e_ktls_resync,
};

void mlx5e_ktls_build_netdev(struct mlx5e_priv *priv)
{
	struct net_device *netdev = priv->netdev;
	struct mlx5_core_dev *mdev = priv->mdev;

	if (!mlx5_accel_is_ktls_device(mdev))
		return;

	if (mlx5_accel_is_ktls_tx(mdev)) {
		netdev->hw_features |= NETIF_F_HW_TLS_TX;
		netdev->features    |= NETIF_F_HW_TLS_TX;
	}

	if (mlx5_accel_is_ktls_rx(mdev)) {
		netdev->hw_features |= NETIF_F_HW_TLS_RX;
		netdev->features    |= NETIF_F_HW_TLS_RX;
	}

	netdev->tlsdev_ops = &mlx5e_ktls_ops;
}
