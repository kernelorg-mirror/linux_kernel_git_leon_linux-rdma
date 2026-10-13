// SPDX-License-Identifier: GPL-2.0

#include <linux/ratelimit.h>

__rust_helper void rust_helper_ratelimit_default_init(struct ratelimit_state *state)
{
	ratelimit_default_init(state);
}
