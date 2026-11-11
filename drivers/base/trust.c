// SPDX-License-Identifier: GPL-2.0

#include <linux/device.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/sysfs.h>

#include "base.h"

static enum device_trust_policy device_trust_default_policy __ro_after_init =
	DEVICE_TRUST_POLICY_UNRESTRICTED;
static bool device_trust_configured __ro_after_init;

static void __init device_trust_configure(void)
{
	if (device_trust_configured)
		return;

	device_trust_default_policy = DEVICE_TRUST_POLICY_BLOCKED;
	device_trust_configured = true;
}

static int __init device_trust_detect_setup(char *str)
{
	if (!*str || *str == '=' || *str == '.')
		device_trust_configure();
	return !*str;
}
__setup("device_trust", device_trust_detect_setup);

void device_trust_init_state(struct device *dev)
{
	if (dev->trust_committed_level != DEVICE_TRUST_BLOCKED)
		dev->p->trust_state = DEVICE_TRUST_COMMITTED;
	else
		dev->p->trust_state = dev->trust_policy == DEVICE_TRUST_POLICY_BLOCKED ?
			DEVICE_TRUST_WAITING : DEVICE_TRUST_SELECTABLE;
}

static int __device_trust_prepare(struct device *dev,
				  const struct device_driver *drv, bool unrestricted_only)
{
	enum device_trust_policy policy;
	enum device_trust_level level;
	int ret;

	policy = dev->trust_policy;

	if (policy == DEVICE_TRUST_POLICY_BLOCKED)
		return -EPERM;
	if (dev->bus && dev->bus->trust_resolve) {
		ret = dev->bus->trust_resolve(dev, drv, policy, &level);
		if (ret)
			return ret;
	} else {
		level = policy == DEVICE_TRUST_POLICY_ADVERSARY ?
			DEVICE_TRUST_ADVERSARY : DEVICE_TRUST_UNRESTRICTED;
	}
	if (level == DEVICE_TRUST_BLOCKED)
		return -EPERM;
	if (unrestricted_only && level != DEVICE_TRUST_UNRESTRICTED)
		return -EPERM;
	if (dev->p->trust_state == DEVICE_TRUST_COMMITTED &&
	    dev->trust_committed_level != level)
		return -EINVAL;

	WRITE_ONCE(dev->trust_committed_level, level);
	dev->p->trust_state = DEVICE_TRUST_COMMITTED;
	WRITE_ONCE(dev->trust_level, level);
	return 0;
}

/**
 * device_trust_prepare - Admit a driver before operating a device
 * @dev: initialized device with its bus, name and initial policy set
 * @drv: driver claiming or probing the device
 *
 * The caller must hold the device lock. Buses may admit a claim before
 * device_add(); registration preserves the resulting policy and commitment.
 * Clear the active level after the driver has stopped operating the device.
 *
 * Return: 0 on admission, or a negative error before driver setup.
 */
int device_trust_prepare(struct device *dev, const struct device_driver *drv)
{
	int ret;

	device_lock_assert(dev);
	if (!dev->p) {
		ret = device_private_init(dev);
		if (ret)
			return ret;
		device_trust_init(dev);
		device_trust_init_state(dev);
	}
	return __device_trust_prepare(dev, drv, false);
}
EXPORT_SYMBOL_GPL(device_trust_prepare);

int device_trust_prepare_unrestricted(struct device *dev,
				      const struct device_driver *drv)
{
	if (device_trust_default_policy != DEVICE_TRUST_POLICY_UNRESTRICTED)
		return -EPERM;

	return __device_trust_prepare(dev, drv, true);
}

/**
 * device_trust_clear - End a device's active operating level
 * @dev: device whose driver setup and cleanup have finished
 *
 * The caller must hold the device lock. Lifetime commitment is retained.
 */
void device_trust_clear(struct device *dev)
{
	device_lock_assert(dev);
	WRITE_ONCE(dev->trust_level, DEVICE_TRUST_BLOCKED);
}
EXPORT_SYMBOL_GPL(device_trust_clear);

/**
 * device_get_trust_level - Return a device's active trust level
 * @dev: device to inspect
 *
 * The value is stable from the start of DMA configuration through the end of
 * DMA cleanup. An unbound device has %DEVICE_TRUST_BLOCKED as its active
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
	[DEVICE_TRUST_POLICY_BLOCKED] = "blocked",
	[DEVICE_TRUST_POLICY_ADVERSARY] = "adversary",
	[DEVICE_TRUST_POLICY_UNRESTRICTED] = "unrestricted",
};

static const char * const device_trust_level_names[] = {
	[DEVICE_TRUST_BLOCKED] = "blocked",
	[DEVICE_TRUST_ADVERSARY] = "adversary",
	[DEVICE_TRUST_UNRESTRICTED] = "unrestricted",
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

static bool device_trust_policy_frozen(void)
{
	return device_trust_configured &&
		device_trust_default_policy == DEVICE_TRUST_POLICY_UNRESTRICTED;
}

/**
 * device_trust_set_policy_locked - Request policy with the device locked
 * @dev: registered device
 * @policy: requested policy
 *
 * Apply the admission rules while the caller holds the device lock.
 *
 * Return: 0 on success, -EBUSY if the policy can no longer change, or
 * -ENODEV if the device is being removed outside explicit unrestricted mode.
 */
int device_trust_set_policy_locked(struct device *dev,
				   enum device_trust_policy policy)
{
	device_lock_assert(dev);
	if (device_trust_policy_frozen())
		return policy == dev->trust_policy ? 0 : -EBUSY;
	if (dev->p->dead)
		return -ENODEV;
	if (policy == dev->trust_policy)
		goto set_policy;

	if (dev->driver)
		return -EBUSY;

	switch (dev->p->trust_state) {
	case DEVICE_TRUST_SELECTABLE:
		if (policy == DEVICE_TRUST_POLICY_BLOCKED)
			dev->p->trust_state = DEVICE_TRUST_WAITING;
		break;
	case DEVICE_TRUST_WAITING:
		if (policy != DEVICE_TRUST_POLICY_ADVERSARY &&
		    policy != DEVICE_TRUST_POLICY_UNRESTRICTED)
			return -EBUSY;
		dev->p->trust_state = DEVICE_TRUST_AUTHORIZED;
		break;
	default:
		return -EBUSY;
	}
set_policy:
	WRITE_ONCE(dev->trust_policy, policy);
	return 0;
}
EXPORT_SYMBOL_GPL(device_trust_set_policy_locked);

/**
 * device_trust_set_policy - Request a trust policy for a device
 * @dev: registered device
 * @policy: requested policy
 *
 * Apply admission rules, including on legacy boots where trust_policy writes
 * are unavailable. Buses with their own authorization interfaces may use this
 * API. Callers of device_driver_attach_unrestricted() must preserve its invariants.
 *
 * Takes the device lock except in explicit unrestricted mode, where a same-policy
 * request is a no-op and does not override a pending driver boot rule.
 *
 * Return: 0 on success, -EBUSY if the policy can no longer change, or
 * -ENODEV if the device is being removed outside explicit unrestricted mode.
 */
int device_trust_set_policy(struct device *dev, enum device_trust_policy policy)
{
	int ret;

	if (device_trust_policy_frozen())
		return policy == READ_ONCE(dev->trust_policy) ? 0 : -EBUSY;

	device_lock(dev);
	ret = device_trust_set_policy_locked(dev, policy);
	device_unlock(dev);
	return ret;
}
EXPORT_SYMBOL_GPL(device_trust_set_policy);

static ssize_t trust_policy_store(struct device *dev,
				  const struct device_attribute *attr,
				  const char *buf, size_t count)
{
	int policy, ret;

	policy = sysfs_match_string(device_trust_policy_names, buf);
	if (policy < 0)
		return policy;

	if (!device_trust_configured)
		return policy == READ_ONCE(dev->trust_policy) ? count : -EBUSY;

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
static int __init device_trust_default_setup(char *str)
{
	int policy = match_string(device_trust_policy_names,
				  ARRAY_SIZE(device_trust_policy_names), str);

	device_trust_configure();
	if (policy < 0) {
		pr_warn("device_trust: ignoring invalid default policy '%s'\n", str);
		return 1;
	}

	device_trust_default_policy = policy;
	return 1;
}
__setup("device_trust.default=", device_trust_default_setup);

/**
 * device_trust_init - Apply global boot policy before registration
 * @dev: unregistered device with its initial policy set
 */
void device_trust_init(struct device *dev)
{
	if (dev->trust_committed_level != DEVICE_TRUST_BLOCKED)
		return;

	if (device_trust_configured &&
	    device_trust_default_policy != DEVICE_TRUST_POLICY_DEFAULT)
		dev->trust_policy = device_trust_default_policy;
}
EXPORT_SYMBOL_GPL(device_trust_init);
