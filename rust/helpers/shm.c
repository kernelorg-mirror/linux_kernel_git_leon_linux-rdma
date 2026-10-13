// SPDX-License-Identifier: GPL-2.0

#include <linux/shm.h>

__rust_helper unsigned long rust_helper_shmlba(void)
{
	return SHMLBA;
}
