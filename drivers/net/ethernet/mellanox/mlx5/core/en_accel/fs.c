// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2020, Mellanox Technologies inc. All rights reserved. */

#include <linux/netdevice.h>
#include "en_accel/fs.h"
#include "fs_core.h"

static int fs_accel2tt(enum accel_fs_type i)
{
	switch (i) {
	case ACCEL_FS_IPV4_TCP:
		return MLX5E_TT_IPV4_TCP;
	case ACCEL_FS_IPV6_TCP:
		return MLX5E_TT_IPV6_TCP;
	default:
		return -EINVAL;
	}
}

static int accel_fs_add_default_rule(struct mlx5e_priv *priv,
				     enum accel_fs_type type)
{
	struct mlx5_flow_handle **default_rule;
	struct mlx5_flow_destination dest = {};
	enum mlx5e_traffic_types tt = -EINVAL;
	struct mlx5e_flow_table *accel_fs_t;
	MLX5_DECLARE_FLOW_ACT(flow_act);
	struct mlx5_flow_spec *spec;
	int err = 0;

	accel_fs_t = &priv->fs.accel.accel_tables[type];
	default_rule = &priv->fs.accel.default_rules[type];
	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		err = -ENOMEM;
		goto out;
	}

	tt = fs_accel2tt(type);
	if (tt == -EINVAL) {
		netdev_err(priv->netdev, "%s: bad accel_fs_type: %d\n",
			    __func__, type);
		err = -EINVAL;
		goto out;
	}

	dest.type = MLX5_FLOW_DESTINATION_TYPE_TIR;
	dest.tir_num = priv->indir_tir[tt].tirn;

	*default_rule = mlx5_add_flow_rules(accel_fs_t->t, spec, &flow_act,
					    &dest, 1);
	if (IS_ERR(*default_rule)) {
		err = PTR_ERR(*default_rule);
		*default_rule = NULL;
		netdev_err(priv->netdev, "%s: add rule failed, accel_fs type=%d\n",
			   __func__, type);
	}
out:
	kvfree(spec);
	return err;
}

#define MLX5E_ACCEL_FS_NUM_GROUPS	(2)
#define MLX5E_ACCEL_FS_GROUP1_SIZE	(BIT(16) - 1)
#define MLX5E_ACCEL_FS_GROUP2_SIZE	(BIT(0))
#define MLX5E_ACCEL_FS_TABLE_SIZE	(MLX5E_ACCEL_FS_GROUP1_SIZE +\
					 MLX5E_ACCEL_FS_GROUP2_SIZE)
static int accel_fs_create_groups(struct mlx5e_flow_table *ft,
				  enum accel_fs_type type)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	void *outer_headers_c;
	int ix = 0;
	u32 *in;
	int err;
	u8 *mc;

	ft->g = kcalloc(MLX5E_ACCEL_FS_NUM_GROUPS,
			sizeof(*ft->g), GFP_KERNEL);
	in = kvzalloc(inlen, GFP_KERNEL);
	if  (!in || !ft->g) {
		kvfree(ft->g);
		kvfree(in);
		return -ENOMEM;
	}

	mc = MLX5_ADDR_OF(create_flow_group_in, in, match_criteria);
	outer_headers_c = MLX5_ADDR_OF(fte_match_param, mc,
				       outer_headers);
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, ethertype);
	switch (type) {
	case ACCEL_FS_IPV4_TCP:
	case ACCEL_FS_IPV6_TCP:
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, tcp_dport);
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, tcp_sport);
		break;
	default:
		err = -EINVAL;
		goto out;
	}

	switch (type) {
	case ACCEL_FS_IPV4_TCP:
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c,
				 src_ipv4_src_ipv6.ipv4_layout.ipv4);
		MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c,
				 dst_ipv4_dst_ipv6.ipv4_layout.ipv4);
		break;
	case ACCEL_FS_IPV6_TCP:
		memset(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_headers_c,
				    src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       0xff, 16);
		memset(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_headers_c,
				    dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       0xff, 16);
		break;
	default:
		err = -EINVAL;
		goto out;
	}

	MLX5_SET_CFG(in, match_criteria_enable, MLX5_MATCH_OUTER_HEADERS);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_ACCEL_FS_GROUP1_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err;
	ft->num_groups++;

	/* Default Flow Group */
	memset(in, 0, inlen);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_ACCEL_FS_GROUP2_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);
	if (IS_ERR(ft->g[ft->num_groups]))
		goto err;
	ft->num_groups++;

	kvfree(in);
	return 0;

err:
	err = PTR_ERR(ft->g[ft->num_groups]);
	ft->g[ft->num_groups] = NULL;
out:
	kvfree(in);

	return err;
}

static int accel_fs_create_table(struct mlx5e_priv *priv,
				 enum accel_fs_type type)
{
	struct mlx5e_flow_table *ft = &priv->fs.accel.accel_tables[type];
	struct mlx5_flow_table_attr ft_attr = {};
	int err;

	ft->num_groups = 0;

	ft_attr.max_fte = MLX5E_ACCEL_FS_TABLE_SIZE;
	ft_attr.level = MLX5E_ACCEL_FS_FT_LEVEL;
	ft_attr.prio = MLX5E_NIC_PRIO;

	ft->t = mlx5_create_flow_table(priv->fs.ns, &ft_attr);
	if (IS_ERR(ft->t)) {
		err = PTR_ERR(ft->t);
		ft->t = NULL;
		return err;
	}

	netdev_dbg(priv->netdev, "Created fs accel table id %u level %u\n",
		   ft->t->id, ft->t->level);

	err = accel_fs_create_groups(ft, type);
	if (err)
		goto err;

	err = accel_fs_add_default_rule(priv, type);
	if (err)
		goto err;

	return 0;
err:
	mlx5e_destroy_flow_table(ft);
	return err;
}

static int mlx5e_accel_fs_disable(struct mlx5e_priv *priv)
{
	struct mlx5_flow_destination dest = {};
	int err = 0;
	int i;

	dest.type = MLX5_FLOW_DESTINATION_TYPE_TIR;

	for (i = 0; i < ACCEL_FS_NUM_TYPES; i++) {
		struct mlx5_flow_handle *handle = NULL;
		int tt = fs_accel2tt(i);

		if (tt < 0)
			return -EINVAL;

		handle = priv->fs.ttc.rules[tt];
		dest.tir_num = priv->indir_tir[tt].tirn;

		/* Modify ttc rules destination to point back to the indir TIRs */
		err = mlx5_modify_rule_destination(handle, &dest, NULL);
		if (err) {
			netdev_err(priv->netdev,
				   "%s: modify ttc destination failed err=%d\n",
				   __func__, err);
			return err;
		}
	}

	return 0;
}

void mlx5e_accel_fs_destroy_tables(struct mlx5e_priv *priv)
{
	int i;

	mlx5e_accel_fs_disable(priv);

	/* TODO not symmetric */
	destroy_workqueue(priv->fs.accel.wq);

	for (i = 0; i < ACCEL_FS_NUM_TYPES; i++) {
		if (!IS_ERR_OR_NULL(priv->fs.accel.accel_tables[i].t)) {
			mlx5_del_flow_rules(priv->fs.accel.default_rules[i]);
			mlx5e_destroy_flow_table(&priv->fs.accel.accel_tables[i]);
			priv->fs.accel.accel_tables[i].t = NULL;
		}
	}
}

static int mlx5e_accel_fs_enable(struct mlx5e_priv *priv)
{
	struct mlx5_flow_destination dest = {};
	int err = 0;
	int i;

	dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	for (i = 0; i < ACCEL_FS_NUM_TYPES; i++) {
		struct mlx5_flow_handle *handle = NULL;
		int tt = fs_accel2tt(i);

		if (tt < 0)
			return -EINVAL;

		handle = priv->fs.ttc.rules[tt];
		dest.ft = priv->fs.accel.accel_tables[i].t;

		/* Modify ttc rules destination to point on the accel_fs FTs */
		err = mlx5_modify_rule_destination(handle, &dest, NULL);
		if (err) {
			netdev_err(priv->netdev,
				   "%s: modify ttc destination failed err=%d\n",
				   __func__, err);
			return err;
		}
	}
	return 0;
}

int mlx5e_accel_fs_create_tables(struct mlx5e_priv *priv)
{
	int i, err;

	spin_lock_init(&priv->fs.accel.lock);
	priv->fs.accel.wq = create_singlethread_workqueue("mlx5e_accel");
	if (!priv->fs.accel.wq)
		return -ENOMEM;

	for (i = 0; i < ACCEL_FS_NUM_TYPES; i++) {
		err = accel_fs_create_table(priv, i);
		if (err)
			goto err;
	}

	err = mlx5e_accel_fs_enable(priv);
	if (err)
		goto err;

	return 0;
err:
	mlx5e_accel_fs_destroy_tables(priv);
	return err;
}
