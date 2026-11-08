.. SPDX-License-Identifier: GPL-2.0

============
Device trust
============

Device trust controls how the kernel uses a device. It does not verify the
device's identity or firmware. Driver core tracks the requested policy,
permission to bind, and active trust level separately.

Policy and active trust
=======================

The writable ``trust_policy`` attribute accepts ``default``, ``disabled``,
``adversary``, or ``full``. The bus may set the initial policy; otherwise it
starts as ``default``. Boot options can override it for all devices, a
named driver, or an individual device. See `Boot policy`_ for precedence.

The read-only ``trust`` attribute reports the active trust level:

``DEVICE_TRUST_DISABLED`` (``disabled``)
  There is no active driver setup or binding. The requested policy decides
  whether a later bind is allowed.

``DEVICE_TRUST_ADVERSARY`` (``adversary``)
  The kernel treats the device as potentially malicious. The bus and DMA
  layers must enforce the restrictions needed to operate it.

``DEVICE_TRUST_FULL`` (``full``)
  The device uses the normal privileges allowed by the bus and DMA policy.

Policy resolution
=================

A bus can implement ``bus_type::trust_resolve`` to choose the active level
from the device, candidate driver, and requested policy. For ``default``,
it may use topology or firmware information. Other policies must resolve
to the matching level or fail.

The callback must not enable the device or grant DMA access. Those steps
belong in setup callbacks, after resolution and before probe.

Without this callback, ``default`` and ``full`` resolve to
``DEVICE_TRUST_FULL``, and ``adversary`` to ``DEVICE_TRUST_ADVERSARY``.
Explicit ``disabled`` blocks binding. The bus remains responsible for
enforcing the chosen level's restrictions.

Admission and policy writes
===========================

Authorization is userspace's choice of adversary or full for a disabled
device. Commitment happens when the kernel accepts a policy and operating
level, before starting driver setup. Both limit later policy changes.

With ``device_trust.default=full``, runtime policy changes are unavailable
for every device, including devices with a boot policy exception. Writing
a different policy returns ``-EBUSY``. Writing the current policy succeeds
without changing state or suppressing a pending driver boot rule. Boot
device and driver rules retain their precedence.

In other global modes, runtime policy writes follow the internal states
below; these are not additional sysfs values.
``P`` is the requested policy and ``L`` is the committed operating level.

.. list-table:: Admission states
   :header-rows: 1
   :widths: 25 40 35

   * - State
     - Meaning
     - Policy writes
   * - SELECTABLE
     - The device has not been authorized or committed.
     - Any policy is allowed. Selecting disabled enters WAITING.
   * - WAITING
     - Policy is disabled - no operating level is committed.
     - Choose adversary or full to enter AUTHORIZED(P).
   * - AUTHORIZED(P)
     - Userspace has chosen adversary or full from WAITING.
     - The policy cannot change, even before setup begins.
   * - COMMITTED(P, L)
     - The kernel has accepted P and L for setup.
     - Neither the policy nor the operating level can change.

Bus defaults and boot options set the initial state: disabled starts in
WAITING; other policies start in SELECTABLE. Driver boot rules apply later,
when a matching driver attempts to bind. They may still replace this
initial state, including WAITING, unless a per-device boot entry or a
successful policy write takes precedence.

Userspace cannot move WAITING back to SELECTABLE by writing ``default``.
Choosing adversary or full from WAITING locks that policy immediately.

After boot initialization, the state transitions are::

  SELECTABLE ----select disabled----> WAITING
      |                                 |
      |                             authorize
      |                           adversary/full
      |                                 |
      |                                 v
      |                            AUTHORIZED(P)
      |                                 |
      +------ permitted resolution -----+
                       |
                       v
                 COMMITTED(P, L)

Binding and device lifetime
============================

A manual bind that reaches WAITING returns ``-EPERM`` before driver or DMA
setup. Automatic matching skips the rejected driver and tries the next
candidate. Except with ``device_trust.default=full``, repeated rejected
attempts leave the policy writable for later authorization.

Active trust stays at L through DMA setup, probe, operation, removal, and
``bus_type::dma_cleanup``. It returns to disabled only after cleanup ends.

The state lasts for the device object's lifetime, including the switch
from initrd to the root filesystem. Unbinding and rebinding a registered
device does not reset it. A removed device cannot be registered again; a
new object starts with bus and boot policy.

Manual attachment under global full policy
==========================================

This compatibility API **must not be used in any new code**. Its
full-only restriction prevents devices from using the device trust
authorization infrastructure. New code must use ``device_driver_attach()``.

``device_driver_attach_full()`` supports manual attachment with the
caller's existing subsystem serialization. It requires an explicit
``device_trust.default=full`` boot option and a policy that resolves to
full. It returns ``-EPERM`` in every other global mode, including when
the option is absent or set to ``default``, before calling the driver.

Per-device boot exceptions still apply: disabled and adversary reject
attachment. If a ``device_trust.driver=`` list is configured, the device
must also have an explicit ``device_trust=`` entry; otherwise this API
returns ``-EPERM``. That entry prevents a concurrent driver rule from
changing the policy.

The caller serializes attachment and removal. The API takes neither the
device nor parent lock, commits full before the probe callback, and
publishes the binding after probe succeeds. It does not perform normal
driver-core DMA, pinctrl, or power-domain setup. A failed probe or binding
clears active trust but retains the full commitment.

Boot policy
===========

Built-in drivers can probe before userspace starts. Use boot options to
set their initial policy. All three options accept default, disabled,
adversary, and full.

``device_trust.default=`` sets policy for all devices. If omitted or set
to default, it preserves bus policy. Other values replace bus policy,
including topology and removability defaults. The last valid value wins;
invalid values are reported and ignored.

``device_trust=`` sets policy for individual devices using a comma-separated
list of ``<bus>:<device>=<policy>`` entries. Names must match
``/sys/bus/<bus>/devices/<device>`` exactly. The first colon separates the
bus name; later colons are part of the device name. Names cannot contain
whitespace, control characters, commas, equals signs, or double quotes.
Wildcards are not supported.

A device entry overrides driver rules, the global setting, and bus policy,
regardless of option order. Explicit default asks the bus or generic
resolver to choose a level, even if the global setting is disabled. The
last entry for a device wins. If the option is repeated, the last valid
list replaces all earlier lists. A malformed list is ignored in full,
with a warning.

``device_trust.driver=`` sets policy by driver name using a comma-separated
list of ``<bus>:<driver>=<policy>`` entries. Use exact names from
``/sys/bus/<bus>/drivers/<driver>``, not module names or aliases. The name
restrictions and list handling are the same as for device entries. The
two lists are independent. Driver rules cover built-in drivers, modules,
and hotplug.

The first bind attempt with a matching driver rule applies it before
resolution and setup. It overrides bus and global defaults, including
global disabled. It cannot override a per-device entry or an existing
authorization or commitment. A successful sysfs policy write also takes
precedence, except for a no-op write with ``device_trust.default=full``.
The rule applies only once per device object, even if resolution or setup
fails.

After a disabled driver rule applies, rejected probes and driver changes
leave the device in WAITING. Userspace can authorize it unless the global
mode is full. Before any rule applies, a driver with no matching rule may
still bind through normal attachment. Use global or per-device disabled
to block every driver.

An initrd can hold devices with ``device_trust.default=disabled`` and use
boot exceptions for devices and suppliers needed to reach the initrd and
perform attestation. These exceptions allow operation before fresh initrd
attestation. Devices without an exception stay disabled even if their bus
would normally choose adversary or full.

Global and per-device rules apply before device registration. Buses that
need policy earlier call ``device_trust_init()`` after setting the bus,
name, and initial policy. Driver rules apply later, when a candidate driver
is known.

All boot rules remain available for newly discovered devices. Initialize
boot policy before device registration. These options are not runtime
controls or proof of hardware identity.
Disabled blocks early binding and, outside global full mode, allows later
authorization. Adversary and full permit early binding without fresh
initrd attestation.

DMA containment
===============

Disabled blocks driver binding, not DMA that hardware starts on its own.
The bus and IOMMU must provide containment while a device waits for
authorization.

Adversary does not require an IOMMU. Without an IOMMU group, or with IOMMU
support compiled out, binding uses the platform's normal DMA configuration.
Adversary policy alone does not provide DMA isolation.

Binding does not check the IOMMU domain. Neither a driver rule nor a sysfs
policy write reconfigures it. If a bus uses trust policy during DMA
configuration, select the policy before that configuration takes place.
A setup failure after commitment leaves the chosen mode fixed; it cannot
fall back to full.

Drivers that manage DMA themselves must provide their own containment.
Drivers that do not use DMA need no domain.

Initrd attestation sequence
===========================

For a device that uses normal driver attachment:

1. Boot with ``device_trust.default=disabled`` to hold all devices, or use
   a per-device rule to hold an individual device. Add exceptions needed
   to reach the initrd and provide DMA containment while waiting. Disabled
   attempts remain in WAITING, including attempts by built-in drivers.
2. In the initrd, control probing and attest the current device through a
   transport that works without its functional driver. Keep policy disabled
   during verification and preparation. Leave it disabled if verification
   fails or is unavailable. Removal or replacement invalidates the result;
   a reused bus address is not proof of identity. Repeat attestation if a
   reset or preparation step invalidates the evidence.
3. Once all checks and preparation are complete, write adversary or full
   to ``trust_policy``. This locks the choice and allows binding.
4. Request binding through ``drivers_probe`` or another attach path. The
   kernel commits the operating level before setup. Retries keep the same
   policy and level. An attachment deferred before the driver's probe
   callback returns ``-EAGAIN``; retry later. A successful write does not
   guarantee that a driver bound, so check the device's ``driver`` link.

Queued or concurrent probes may start as soon as step 3 completes, before
step 4. Evidence must still be valid when authorizing the device.
Boot exceptions that permit adversary or full allow early operation
without fresh initrd attestation.

The kernel interface provides neither an attestation transport nor a verifier.

Driver use and independent properties
=====================================

Drivers read active trust with ``device_get_trust_level()`` or
``device_is_adversarial()``. They may cache it while bound, but must not
change requested policy or treat trust as proof of other security
properties. Use the adversary check for paths that bypass the DMA API.
General DMA containment belongs in bus and IOMMU code.

Discovery code uses ``device_policy_is_adversarial()`` to check requested
policy before binding or after unbind. This helper does not resolve
default policy or report active trust.

Code that needs the level fixed for the device's lifetime can use
``device_get_committed_trust_level()``. It returns disabled before
commitment and the fixed level afterwards, including after failed setup
or unbind. It does not permit operation while unbound.

Trust does not describe transport protection, encryption, verified
identity, memory privacy, or DMA addressability. Keep these properties
independent of the requested policy and active trust level.

Policy writes cannot revoke authorization or switch an operating device
between adversary and full. Stopping it requires a separate procedure to
quiesce the driver, tear down DMA, and contain the device on its bus.
