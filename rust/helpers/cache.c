// SPDX-License-Identifier: GPL-2.0

#include <linux/cache.h>

__rust_helper unsigned int rust_helper_cache_line_size_unsigned(void)
{
	return cache_line_size();
}
