.. SPDX-License-Identifier: GPL-2.0

=====================
drivers/lib subsystem
=====================

:Author: Leon Romanovsky <leon@kernel.org>

The ``drivers/lib`` subsystem provides a framework within the Linux kernel
for managing complex hardware devices that implement **multiple distinct
functionalities**, each of which requires separate drivers. The goal of this
subsystem is to centralize and organize these drivers, improving **maintainability**
and making it easier to manage hardware with multiple interconnected components.

Overview
--------

Some hardware devices are inherently **complex** and consist of several functional
units, each requiring its own driver. For example, a network card might include
both a **network interface** and a **storage controller** that require separate
drivers for proper management and operation. Similarly, a multimedia device could
contain components for **video decoding**, **audio processing**, and **video capture**,
each requiring its own driver but all managed within a single hardware unit.

In such cases, these independent functionalities are typically controlled by an
**extra driver** that spans and integrates these various hardware units. This extra
driver acts as a **centralized manager** for the different components, ensuring seamless
operation across all parts of the hardware unit while maintaining the modularity of
each individual driver.

The ``drivers/lib`` subsystem addresses this challenge by providing a **centralized
location** where such **centralized manager** drivers can be placed together. This
allows for **better management of hardware with multiple functionalities** while
ensuring that each individual driver remains modular and focused on a specific
component of the hardware.

Key Features
------------

1. **Centralized Management for Complex Hardware:**
The ``drivers/lib`` subsystem acts as a **single point of maintenance** for
drivers that require interaction across multiple kernel subsystems.

2. **Shared Code and Common Infrastructure:**
The ``drivers/lib`` subsystem also encourages the use of shared code and common
infrastructure across drivers. For example, drivers that implement similar hardware
functionalities may share common helper functions or initialization code, reducing
duplication and improving maintainability.

Why It Is Not MFD?
------------------

The ``drivers/lib`` subsystem is often compared to the MFD (Multi-Function Device)
framework, but they are designed for different use cases and serve distinct
purposes. Here are the key reasons why the ``drivers/lib`` subsystem is not an MFD:

1. **Decentralized Driver Management:**
In an MFD, multiple tightly coupled drivers share resources and require a central
master driver to manage the device as a whole. In contrast, the ``drivers/lib``
subsystem is designed for hardware with independent components that each have their
own drivers. There is no central master driver in the ``drivers/lib`` subsystem, as the
components are not tightly coupled.

2. **Independent Functionalities:**
The components managed by the ``drivers/lib`` subsystem are typically independent,
whereas MFD devices contain tightly coupled components that rely on shared resources
(e.g., memory, interrupts). The need for shared resource management in MFD is not present
in the ``drivers/lib`` model.

3. **No Resource Sharing Between Components:**
MFD devices often involve resource sharing (e.g., a common interrupt or memory region),
which requires careful coordination by the master driver. The components in the ``drivers/lib``
subsystem can function independently, with each driver handling its component separately,
without the need for shared resources or a master driver.

4. **Modular and Independent Drivers:**
The ``drivers/lib`` subsystem maintains modular drivers for each functional component,
which are easier to maintain and update individually. In contrast, MFD requires the
drivers to be more tightly integrated, with the master driver orchestrating how the
child drivers interact with each other.

In conclusion, the ``drivers/lib`` subsystem is designed to centralize complex devices
with independent functionalities, making it more flexible and modular compared to MFD,
which is suited for tightly coupled hardware components that share resources.

Patch Acceptance, Merging, and Management
=========================================

Patches submitted to the ``drivers/lib`` subsystem must be reviewed and/or merged by developers
from multiple companies to ensure that that proper in-kernel interfaces are used and common
infrastructure is reused when it is applicable.

Patch series submitted to the ``drivers/lib`` subsystem should include all related changes,
including those targeted at sub-drivers in other subsystems, to ensure that the full set of
modifications is properly used and acknowledged by relevant subsystem maintainers.

The merged patches are going to be applied to per-vendor shared branch and semi-automatic PR
will be sent to relevant subsystema, so they will be able to merge core changes and apply
their relevant sub-driver changes.
