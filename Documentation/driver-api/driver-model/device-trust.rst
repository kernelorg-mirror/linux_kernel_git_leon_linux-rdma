.. SPDX-License-Identifier: GPL-2.0

============
Device trust
============

Device trust describes how the kernel operates a device.  It is not a claim
about the device's identity and it does not attest device firmware.

The driver core keeps requested policy separate from the active trust level.
Requested policy may be ``default``, ``disabled``, ``adversary``, or ``full``.
``default`` is resolved by the bus immediately before probe, so a bound driver
sees only the active trust level.

Active trust levels
===================

``DEVICE_TRUST_DISABLED``
  A functional driver may not bind to the device.

``DEVICE_TRUST_ADVERSARY``
  The device may be operated only with the restrictions needed for a
  potentially malicious device.  The bus and DMA layers must enforce these
  restrictions.

``DEVICE_TRUST_FULL``
  The device receives the normal privileges selected by the bus and its DMA
  policy.  This preserves historical operation.

Active trust levels are discrete states, not an ordered privilege scale.  Code
must compare a level for equality rather than use ordinal comparisons.

Policy resolution
=================

A bus that needs bus-specific policy resolution implements
``bus_type::trust_resolve``.  The callback receives the device, candidate
driver, and requested policy, and returns the active trust level.  It may
combine a ``default`` request with bus topology or firmware information.
It must reject an explicit policy that the bus cannot support, rather than
silently substituting another level.

The callback only resolves policy.  It must not enable the device or grant DMA
access.  Bus enforcement belongs in the existing setup callbacks that run
after resolution and before probe.

A bus without the callback resolves ``default`` and ``full`` to
``DEVICE_TRUST_FULL`` and ``adversary`` to ``DEVICE_TRUST_ADVERSARY``.  It
honors ``disabled`` by suppressing binding.  Each bus remains responsible for
enforcing the restrictions associated with the resulting active level.

Binding lifetime
================

Requested policy is stored in ``struct device``.  The active trust level is
private to driver core and starts as ``DEVICE_TRUST_DISABLED``.  Driver core
resolves and records the active trust level while holding the device lock,
before assigning the driver and before ``bus_type::dma_configure``.

The active trust level remains stable through DMA configuration, probe, normal
operation, driver removal, and ``bus_type::dma_cleanup``.  A failed probe is
cleaned up before the level returns to ``DEVICE_TRUST_DISABLED``.  Normal
unbind similarly clears the active trust level only after the driver's remove
callback and DMA cleanup have finished.

The legacy ``device_bind_driver()`` shortcut does not run the normal probe and
DMA-configuration sequence.  Driver core therefore rejects it on any bus that
implements ``trust_resolve``.  Such a bus must use the normal driver attach
path or provide equivalent preparation before it opts into trust resolution.

Driver use
==========

Drivers read the active trust level with ``device_get_trust_level()`` or test
``device_is_adversarial()``.  A driver may cache the result for its bound
lifetime.  It must not change requested policy or infer other security
properties from the active trust level.

The adversary helper is intended for features whose safety changes for a
hostile device, such as peer-to-peer DMA, device memory, PASID/SVA, or paths
that bypass the DMA API.  General bus and IOMMU containment should remain in
their respective cores rather than be duplicated in each driver.

Userspace policy
================

The ``trust_policy`` device attribute exposes requested policy as ``default``,
``disabled``, ``adversary``, or ``full``.  Policy can change only before the
device is probed and remains fixed after probing starts.

Independent security properties
===============================

Trust is independent of transport protection, TDISP T=1/RUN, link encryption,
private MMIO, evidence validation, and whether a DMA mapping addresses private
or shared memory.  For example, both T=1 with ``DEVICE_TRUST_ADVERSARY`` and
T=1 with ``DEVICE_TRUST_FULL`` are valid.

Keeping these axes separate avoids a cross-product of trust states and lets
each subsystem enforce the property it owns.  In particular,
``force_dma_unencrypted()`` describes DMA addressability and must not be
derived from the device trust level.
