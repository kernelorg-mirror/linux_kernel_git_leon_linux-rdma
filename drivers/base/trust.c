// SPDX-License-Identifier: GPL-2.0

#include <linux/device.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <kunit/visibility.h>

#include "base.h"

void device_trust_init_state(struct device *dev)
{
	if (dev->p->trust_initialized)
		return;

	dev->p->trust_state = dev->trust_policy == DEVICE_TRUST_POLICY_DISABLED ?
		DEVICE_TRUST_WAITING : DEVICE_TRUST_SELECTABLE;
	dev->p->trust_initialized = true;
}

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

	if (WARN_ON_ONCE(READ_ONCE(dev->trust_level) != DEVICE_TRUST_DISABLED))
		return -EBUSY;
	if (policy == DEVICE_TRUST_POLICY_DISABLED)
		return -EPERM;
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
	if (level != DEVICE_TRUST_ADVERSARY && level != DEVICE_TRUST_FULL)
		return -EINVAL;
	if (dev->p->trust_state == DEVICE_TRUST_COMMITTED &&
	    dev->p->trust_committed_level != level)
		return -EINVAL;

	dev->p->trust_committed_level = level;
	dev->p->trust_state = DEVICE_TRUST_COMMITTED;
	WRITE_ONCE(dev->trust_level, level);
	return 0;
}

void device_trust_clear(struct device *dev)
{
	device_lock_assert(dev);
	WRITE_ONCE(dev->trust_level, DEVICE_TRUST_DISABLED);
}

/**
 * device_get_trust_level - Return a device's active trust level
 * @dev: device to inspect
 *
 * The value is stable from the start of DMA configuration through the end of
 * DMA cleanup. An unbound device has %DEVICE_TRUST_DISABLED as its active
 * trust level.
 *
 * Return: The active trust level for the current bind transaction.
 */
enum device_trust_level device_get_trust_level(const struct device *dev)
{
	return READ_ONCE(dev->trust_level);
}
EXPORT_SYMBOL_GPL(device_get_trust_level);

/**
 * device_is_adversarial - Test whether a device is operated as an adversary
 * @dev: device to inspect
 *
 * Return: True when the active trust level is %DEVICE_TRUST_ADVERSARY.
 */
bool device_is_adversarial(const struct device *dev)
{
	return device_get_trust_level(dev) == DEVICE_TRUST_ADVERSARY;
}
EXPORT_SYMBOL_GPL(device_is_adversarial);
