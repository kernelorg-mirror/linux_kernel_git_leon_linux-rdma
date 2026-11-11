/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _DEVICE_TRUST_H_
#define _DEVICE_TRUST_H_

#include <linux/types.h>

struct device;
struct device_driver;

/**
 * enum device_trust_level - active trust level for a device
 * @DEVICE_TRUST_BLOCKED: The device cannot be operated by a driver
 * @DEVICE_TRUST_ADVERSARY: Classify the operating device as potentially malicious
 * @DEVICE_TRUST_UNRESTRICTED: Operate the device with the usual kernel privileges
 *
 * Active trust levels are discrete states, not an ordered privilege scale.
 * Adversary classification alone adds no protections; these depend on bus,
 * DMA and driver support.
 */
enum device_trust_level {
	DEVICE_TRUST_BLOCKED,
	DEVICE_TRUST_ADVERSARY,
	DEVICE_TRUST_UNRESTRICTED,
};

/**
 * enum device_trust_policy - requested device trust policy
 * @DEVICE_TRUST_POLICY_DEFAULT: Let the bus select the active trust level
 * @DEVICE_TRUST_POLICY_BLOCKED: Request that the device remain blocked
 * @DEVICE_TRUST_POLICY_ADVERSARY: Request adversary classification
 * @DEVICE_TRUST_POLICY_UNRESTRICTED: Request normal operation
 *
 * A requested policy is resolved to an active trust level before a driver is
 * probed.
 */
enum device_trust_policy {
	DEVICE_TRUST_POLICY_DEFAULT,
	DEVICE_TRUST_POLICY_BLOCKED,
	DEVICE_TRUST_POLICY_ADVERSARY,
	DEVICE_TRUST_POLICY_UNRESTRICTED,
};

void device_trust_init(struct device *dev);
int device_trust_prepare(struct device *dev, const struct device_driver *drv);
void device_trust_clear(struct device *dev);
int device_trust_set_policy_locked(struct device *dev,
				   enum device_trust_policy policy);
int device_trust_set_policy(struct device *dev, enum device_trust_policy policy);
enum device_trust_level device_get_trust_level(const struct device *dev);
bool device_is_adversarial(const struct device *dev);

#endif /* _DEVICE_TRUST_H_ */
