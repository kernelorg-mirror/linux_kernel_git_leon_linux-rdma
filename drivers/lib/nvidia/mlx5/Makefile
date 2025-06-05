# SPDX-License-Identifier: GPL-2.0-only

mlx5_core-$(CONFIG_MLX5_CORE) := cmd.o debugfs.o

ifdef CONFIG_MLXFW
ccflags-y += -I$(srctree)/drivers/net/ethernet/mellanox/mlxfw
mlx5_core-$(CONFIG_MLX5_CORE) += fw.o
endif #CONFIG_MLXFW
