// SPDX-License-Identifier: GPL-2.0

#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/sysfs.h>
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

static const char * const device_trust_policy_names[] = {
	[DEVICE_TRUST_POLICY_DEFAULT] = "default",
	[DEVICE_TRUST_POLICY_DISABLED] = "disabled",
	[DEVICE_TRUST_POLICY_ADVERSARY] = "adversary",
	[DEVICE_TRUST_POLICY_FULL] = "full",
};

static const char * const device_trust_level_names[] = {
	[DEVICE_TRUST_DISABLED] = "disabled",
	[DEVICE_TRUST_ADVERSARY] = "adversary",
	[DEVICE_TRUST_FULL] = "full",
};

static ssize_t trust_show(struct device *dev,
			  const struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%s\n",
			  device_trust_level_names[device_get_trust_level(dev)]);
}
static DEVICE_ATTR_RO(trust);

static ssize_t trust_policy_show(struct device *dev,
				 const struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%s\n",
			  device_trust_policy_names[READ_ONCE(dev->trust_policy)]);
}

VISIBLE_IF_KUNIT int device_trust_set_policy(struct device *dev,
					   enum device_trust_policy policy)
{
	int ret = 0;

	if (policy < DEVICE_TRUST_POLICY_DEFAULT ||
	    policy > DEVICE_TRUST_POLICY_FULL)
		return -EINVAL;

	device_lock(dev);
	if (dev->p->dead) {
		ret = -ENODEV;
		goto unlock;
	}
	if (policy == dev->trust_policy)
		goto unlock;

	/* A driver that claimed the device before registration was not admitted. */
	if (READ_ONCE(dev->driver)) {
		ret = -EBUSY;
		goto unlock;
	}

	switch (dev->p->trust_state) {
	case DEVICE_TRUST_SELECTABLE:
		if (policy == DEVICE_TRUST_POLICY_DISABLED)
			dev->p->trust_state = DEVICE_TRUST_WAITING;
		break;
	case DEVICE_TRUST_WAITING:
		if (policy != DEVICE_TRUST_POLICY_ADVERSARY &&
		    policy != DEVICE_TRUST_POLICY_FULL) {
			ret = -EBUSY;
			goto unlock;
		}
		dev->p->trust_state = DEVICE_TRUST_AUTHORIZED;
		break;
	default:
		ret = -EBUSY;
		goto unlock;
	}
	WRITE_ONCE(dev->trust_policy, policy);
unlock:
	device_unlock(dev);
	return ret;
}
EXPORT_SYMBOL_IF_KUNIT(device_trust_set_policy);

static ssize_t trust_policy_store(struct device *dev,
				  const struct device_attribute *attr,
				  const char *buf, size_t count)
{
	int policy, ret;

	policy = sysfs_match_string(device_trust_policy_names, buf);
	if (policy < 0)
		return policy;

	ret = device_trust_set_policy(dev, policy);

	return ret ? ret : count;
}
static DEVICE_ATTR_RW(trust_policy);

static struct attribute *device_trust_attrs[] = {
	&dev_attr_trust.attr,
	&dev_attr_trust_policy.attr,
	NULL,
};

const struct attribute_group device_trust_attr_group = {
	.attrs = device_trust_attrs,
};

static const char *device_trust_cmdline __ro_after_init;

VISIBLE_IF_KUNIT int device_trust_parse_cmdline(const char *options,
						const struct device *dev,
						enum device_trust_policy *policy)
{
	enum device_trust_policy selected = DEVICE_TRUST_POLICY_DEFAULT;
	const char *entry = options;
	bool matched = false;

	if (!entry || !*entry)
		return -EINVAL;

	for (;;) {
		const char *end = entry + strcspn(entry, ",");
		const char *bus_end, *name, *level, *p;
		unsigned int i;

		bus_end = memchr(entry, ':', end - entry);
		if (!bus_end || bus_end == entry ||
		    memchr(entry, '=', bus_end - entry))
			return -EINVAL;
		name = bus_end + 1;
		level = memchr(name, '=', end - name);
		if (!level || level == name || level + 1 == end)
			return -EINVAL;

		for (p = entry; p < end; p++)
			if (isspace(*p) || iscntrl(*p) || *p == '"')
				return -EINVAL;

		for (i = 0; i < ARRAY_SIZE(device_trust_policy_names); i++)
			if (strlen(device_trust_policy_names[i]) == end - level - 1 &&
			    !strncmp(level + 1, device_trust_policy_names[i],
				     end - level - 1))
				break;
		if (i == ARRAY_SIZE(device_trust_policy_names))
			return -EINVAL;

		if (dev && dev->bus && dev_name(dev) &&
		    strlen(dev->bus->name) == bus_end - entry &&
		    !strncmp(dev->bus->name, entry, bus_end - entry) &&
		    strlen(dev_name(dev)) == level - name &&
		    !strncmp(dev_name(dev), name, level - name)) {
			selected = i;
			matched = true;
		}

		if (!*end)
			break;
		entry = end + 1;
	}

	if (matched)
		*policy = selected;
	return matched;
}
EXPORT_SYMBOL_IF_KUNIT(device_trust_parse_cmdline);

static int __init device_trust_setup(char *str)
{
	if (device_trust_parse_cmdline(str, NULL, NULL) < 0) {
		pr_warn("device_trust: ignoring invalid policy list '%s'\n", str);
		return 1;
	}

	/* The command-line buffer survives init. */
	device_trust_cmdline = str;
	return 1;
}
__setup("device_trust=", device_trust_setup);

/**
 * device_trust_init - Apply boot policy before registration or bus policy use
 * @dev: unregistered device with its bus, name, and default policy set
 */
void device_trust_init(struct device *dev)
{
	if (dev->p && dev->p->trust_initialized)
		return;

	if (device_trust_cmdline)
		device_trust_parse_cmdline(device_trust_cmdline, dev,
					   &dev->trust_policy);
}
EXPORT_SYMBOL_GPL(device_trust_init);
