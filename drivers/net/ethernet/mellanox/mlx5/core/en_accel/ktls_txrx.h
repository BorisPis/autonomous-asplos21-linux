#ifndef __MLX5E_KTLS_TXRX_H__
#define __MLX5E_KTLS_TXRX_H__

#ifdef CONFIG_MLX5_EN_TLS

#include "en.h"
#include "en/txrx.h"

int mlx5e_ktls_get_sq_room(void);
u8 mlx5e_ktls_dumps_num_wqebbs(struct mlx5e_txqsq *sq, unsigned int nfrags,
			       unsigned int sync_len);

struct sk_buff *mlx5e_ktls_handle_tx_skb(struct net_device *netdev,
					 struct mlx5e_txqsq *sq,
					 struct sk_buff *skb,
					 struct mlx5e_tx_wqe **wqe, u16 *pi);

void mlx5e_ktls_tx_handle_resync_dump_comp(struct mlx5e_txqsq *sq,
					   struct mlx5e_tx_wqe_info *wi,
					   u32 *dma_fifo_cc);
#else
static inline void
mlx5e_ktls_tx_handle_resync_dump_comp(struct mlx5e_txqsq *sq,
				      struct mlx5e_tx_wqe_info *wi,
				      u32 *dma_fifo_cc) {}

#endif /* CONFIG_MLX5_EN_TLS */

#endif /* __MLX5E_TLS_TXRX_H__ */
