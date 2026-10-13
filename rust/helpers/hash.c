// SPDX-License-Identifier: GPL-2.0

#include <linux/hash.h>

__rust_helper u32 rust_helper_hash_32(u32 value, unsigned int bits)
{
	return hash_32(value, bits);
}
