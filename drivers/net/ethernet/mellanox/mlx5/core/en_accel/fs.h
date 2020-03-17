/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2020, Mellanox Technologies inc. All rights reserved. */

#ifndef __MLX5E_ACCEL_FS_H__
#define __MLX5E_ACCEL_FS_H__

#if defined(CONFIG_MLX5_EN_IPSEC) || defined(CONFIG_MLX5_EN_TLS)

#include "en.h"

int mlx5e_accel_fs_create_tables(struct mlx5e_priv *priv);
void mlx5e_accel_fs_destroy_tables(struct mlx5e_priv *priv);
struct mlx5_flow_handle *mlx5e_accel_fs_add_flow(struct mlx5e_priv *priv,
						 struct sock *sk, u32 tirn,
						 uint32_t flow_tag);
#else
int mlx5e_accel_fs_create_tables(struct mlx5e_priv *priv) { return 0; }
void mlx5e_accel_fs_destroy_tables(struct mlx5e_priv *priv) {}
struct mlx5_flow_handle *mlx5e_accel_fs_add_flow(struct mlx5e_priv *priv,
						 struct sock *sk, u32 tirn,
						 uint32_t flow_tag)
{ return NULL; }
#endif

#endif /* __MLX5E_ACCEL_FS_H__ */

