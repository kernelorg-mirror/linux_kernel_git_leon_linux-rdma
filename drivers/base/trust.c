// SPDX-License-Identifier: GPL-2.0
/*
 * Generic device trust handling
 */

#include <linux/device.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/sysfs.h>
#include <kunit/visibility.h>

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

static const char * const device_trust_policy_names[] = {
	[DEVICE_TRUST_POLICY_DEFAULT] = "default",
	[DEVICE_TRUST_POLICY_DISABLED] = "disabled",
	[DEVICE_TRUST_POLICY_ADVERSARY] = "adversary",
	[DEVICE_TRUST_POLICY_FULL] = "full",
};

static ssize_t trust_policy_show(struct device *dev,
				 const struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%s\n",
			  device_trust_policy_names[READ_ONCE(dev->trust_policy)]);
}

static int device_trust_policy_parse(const char *buf,
				     enum device_trust_policy *policy)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(device_trust_policy_names); i++) {
		if (!sysfs_streq(buf, device_trust_policy_names[i]))
			continue;

		*policy = i;
		return 0;
	}

	return -EINVAL;
}

static ssize_t trust_policy_store(struct device *dev,
				  const struct device_attribute *attr,
				  const char *buf, size_t count)
{
	enum device_trust_policy policy;
	int ret;

	ret = device_trust_policy_parse(buf, &policy);
	if (ret)
		return ret;

	device_lock(dev);
	if (dev_can_match(dev))
		ret = -EBUSY;
	else
		WRITE_ONCE(dev->trust_policy, policy);
	device_unlock(dev);

	return ret ? ret : count;
}
static DEVICE_ATTR_RW(trust_policy);

static struct attribute *device_trust_attrs[] = {
	&dev_attr_trust_policy.attr,
	NULL,
};

const struct attribute_group device_trust_attr_group = {
	.attrs = device_trust_attrs,
};

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
	if (!dev->p)
		return DEVICE_TRUST_DISABLED;

	return READ_ONCE(dev->p->trust_level);
}
EXPORT_SYMBOL_IF_KUNIT(device_get_trust_level);

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
EXPORT_SYMBOL_IF_KUNIT(device_is_adversarial);
