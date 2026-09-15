// SPDX-License-Identifier: GPL-2.0
/*
 * Generic device trust handling
 */

#include <linux/device.h>
#include <linux/errno.h>

#include "base.h"

static bool device_trust_policy_matches(enum device_trust_policy policy,
					enum device_trust_level level)
{
	switch (policy) {
	case DEVICE_TRUST_POLICY_DEFAULT:
		return true;
	case DEVICE_TRUST_POLICY_DISABLED:
		return level == DEVICE_TRUST_DISABLED;
	case DEVICE_TRUST_POLICY_ADVERSARY:
		return level == DEVICE_TRUST_ADVERSARY;
	case DEVICE_TRUST_POLICY_FULL:
		return level == DEVICE_TRUST_FULL;
	default:
		return false;
	}
}

static int device_trust_resolve_default(enum device_trust_policy policy,
					enum device_trust_level *level)
{
	switch (policy) {
	case DEVICE_TRUST_POLICY_DEFAULT:
	case DEVICE_TRUST_POLICY_FULL:
		*level = DEVICE_TRUST_FULL;
		return 0;
	case DEVICE_TRUST_POLICY_DISABLED:
		*level = DEVICE_TRUST_DISABLED;
		return 0;
	case DEVICE_TRUST_POLICY_ADVERSARY:
		*level = DEVICE_TRUST_ADVERSARY;
		return 0;
	default:
		return -EINVAL;
	}
}

int device_trust_prepare(struct device *dev, const struct device_driver *drv)
{
	enum device_trust_policy policy;
	enum device_trust_level level = DEVICE_TRUST_DISABLED;
	int ret;

	device_lock_assert(dev);
	policy = dev->trust_policy;

	if (WARN_ON_ONCE(READ_ONCE(dev->p->trust_level) !=
			 DEVICE_TRUST_DISABLED))
		return -EBUSY;
	if (dev->bus && dev->bus->trust_resolve)
		ret = dev->bus->trust_resolve(dev, drv, policy, &level);
	else
		ret = device_trust_resolve_default(policy, &level);
	if (ret)
		return ret;

	if (!device_trust_policy_matches(policy, level))
		return -EINVAL;
	if (level == DEVICE_TRUST_DISABLED)
		return -EPERM;

	WRITE_ONCE(dev->p->trust_level, level);
	return 0;
}

void device_trust_clear(struct device *dev)
{
	device_lock_assert(dev);
	WRITE_ONCE(dev->p->trust_level, DEVICE_TRUST_DISABLED);
}
