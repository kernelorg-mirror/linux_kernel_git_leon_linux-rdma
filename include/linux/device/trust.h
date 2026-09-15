/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _DEVICE_TRUST_H_
#define _DEVICE_TRUST_H_

/**
 * enum device_trust_level - active trust level for a device
 * @DEVICE_TRUST_DISABLED: The device cannot be operated by a driver
 * @DEVICE_TRUST_ADVERSARY: Operate the device with adversarial restrictions
 * @DEVICE_TRUST_FULL: Operate the device with the usual kernel privileges
 *
 * Active trust levels are discrete states, not an ordered privilege scale.
 */
enum device_trust_level {
	DEVICE_TRUST_DISABLED,
	DEVICE_TRUST_ADVERSARY,
	DEVICE_TRUST_FULL,
};

/**
 * enum device_trust_policy - requested device trust policy
 * @DEVICE_TRUST_POLICY_DEFAULT: Let the bus select the active trust level
 * @DEVICE_TRUST_POLICY_DISABLED: Request that the device remain disabled
 * @DEVICE_TRUST_POLICY_ADVERSARY: Request adversarial operation
 * @DEVICE_TRUST_POLICY_FULL: Request normal operation
 *
 * A requested policy is resolved to an active trust level before a driver is
 * probed.
 */
enum device_trust_policy {
	DEVICE_TRUST_POLICY_DEFAULT,
	DEVICE_TRUST_POLICY_DISABLED,
	DEVICE_TRUST_POLICY_ADVERSARY,
	DEVICE_TRUST_POLICY_FULL,
};

#endif /* _DEVICE_TRUST_H_ */
