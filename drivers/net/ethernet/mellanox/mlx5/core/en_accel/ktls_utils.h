#ifndef __MLX5E_KTLS_UTILS_H__
#define __MLX5E_KTLS_UTILS_H__

#include <net/tls.h>
#include "en.h"
#include "accel/tls.h"

int mlx5e_ktls_add_tx(struct net_device *netdev, struct sock *sk,
			  struct tls_crypto_info *crypto_info, u32 key_id,
			  u32 start_offload_tcp_sn);
void mlx5e_ktls_del_tx(struct net_device *netdev,
			      struct tls_context *tls_ctx);

struct mlx5e_set_tls_static_params_wqe {
	struct mlx5_wqe_ctrl_seg          ctrl;
	struct mlx5_wqe_umr_ctrl_seg      uctrl;
	struct mlx5_mkey_seg              mkc;
	struct mlx5_seg_tls_static_params params;
};

struct mlx5e_set_tls_progress_params_wqe {
	struct mlx5_wqe_ctrl_seg            ctrl;
	struct mlx5_seg_tls_progress_params params;
};

#define MLX5E_KTLS_STATIC_WQEBBS \
	(DIV_ROUND_UP(sizeof(struct mlx5e_set_tls_static_params_wqe), MLX5_SEND_WQE_BB))

#define MLX5E_KTLS_SET_PROGRESS_WQEBBS \
	(DIV_ROUND_UP(sizeof(struct mlx5e_set_tls_progress_params_wqe), MLX5_SEND_WQE_BB))

void
mlx5e_ktls_build_static_params(struct mlx5e_set_tls_static_params_wqe *wqe,
			       u16 pc, u32 sqn,
			       struct tls12_crypto_info_aes_gcm_128 *info,
			       u32 tis_tir_num, u32 key_id,
			       bool fence, enum tls_offload_ctx_dir direction);
void
mlx5e_ktls_build_progress_params(struct mlx5e_set_tls_progress_params_wqe *wqe,
				 u16 pc, u32 sqn,
				 u32 tis_tir_num, bool fence,
				 enum tls_offload_ctx_dir direction);

#endif /* __MLX5E_TLS_UTILS_H__ */
