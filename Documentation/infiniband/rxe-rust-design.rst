.. SPDX-License-Identifier: GPL-2.0

==========================
Rust RXE ownership design
==========================

Configuration compatibility
===========================

RXE requires ``CONFIG_RUST`` and its architecture, toolchain and kernel
configuration dependencies. This replaces the previous C implementation;
there is no C fallback. Configurations that cannot enable Rust, including
``CONFIG_RANDSTRUCT``, cannot enable RXE. Installing the Rust toolchain does
not remove incompatible kernel configuration dependencies.

Implementation boundary
=======================

The RXE crate compiles with ``#![forbid(unsafe_code)]``. Its private state,
protocol engines, verbs policy and wire codecs are implemented in Rust.
The driver contains no C source, private C headers, unsafe blocks, unsafe
functions or unsafe implementations. Native handles retain core objects;
``Arc`` shares private window state and its revocation authority.

RXE retains generated ABI constants and uses bindgen types for value records
and compile-time layout checks. It does not call raw kernel functions or
implement FFI callback trampolines. Kernel abstractions own those boundaries
and provide checked operations, typed callbacks and native reference owners.
Protocol decisions remain in the driver rather than in RXE-specific wrappers
around its former implementation.

The layers have these responsibilities::

    RXE: device and object policy, transport engines, keys and wire codecs
      |
      v
    Kernel Rust: RDMA objects, memory, packets, networking and execution
      |
      v
    Existing kernel C interfaces and generated declarations

Unsafe implementations in the kernel crate must remain sound for every input
constructible through their safe APIs. Length checks, reference acquisition,
callback lifetimes, early drops and concurrent operations are part of that
contract. Generated module, initialization and callback glue also belongs to
this boundary review.

Device and object ownership
===========================

``kernel::rdma::software`` owns unpublished device allocation and
registration. A managed link registration retains the notifier and
per-network-namespace registration until device teardown finishes.
Construction failures release unpublished state through the same owners. RXE
keeps link validation, device capabilities and admission limits in its
provider implementation.

Typed RDMA callback adapters supply native object borrows and copied request
values. Core allocation lifetime and registered-device lifetime are distinct:
GID-cache access requires a registration reference or another capability that
excludes cache teardown. Owning the device allocation alone is insufficient.

Protection domains have immutable identities. Address handles live in a native
registry whose lock protects publication, identity checks and copied address
vectors. QPs, MRs and MWs use retained native object handles for asynchronous
access. Lookup takes its reference before releasing publication protection;
retirement removes lookup visibility before waiting for references to drain.

Object publication follows successful fallible initialization and userspace
response copying. Failed constructors do not leave initialized Rust state in
storage that the core will free without running its destructor. Object
identity is released only after resources that can still refer to it have
drained.

Module metadata is generated through ``module!``. Timer, UDP-bank and transmit
socket lock classes live in the kernel crate, so built-in users and loadable
providers share valid lock metadata without retaining module-owned names or
pinning a provider until its own exit routine can run.

Execution and teardown
======================

Requester and completer processing share one serialized send domain; responder
processing has a separate receive domain. Typed mutexes protect their mutable
progress. Immutable object relationships and independently synchronized state
are separate from those exclusive borrows. Control operations drain the
relevant worker before replacing task-owned protocol state.

QP configuration, timer notifications, queue admission and management-QP
lookup use named locks or native atomics. Queries read separately published
PSNs rather than borrowing a running engine's progress. Completion callbacks
run after queue and state guards are released, allowing an upper layer to
refill a one-entry queue from its completion handler. Native RDMA event
handlers must still obey the non-sleeping callback contract: QP query,
modification and destruction must be deferred to another execution context.
A CQ completion handler must likewise defer destruction of its own CQ.

RESET closes admission independently of asynchronous error state changes,
then synchronizes producers before draining and resetting queues. Packets and
timer callbacks retain the configuration generation they observed; publication
rejects an old generation after RESET, even if the QP has already become ready
again. A delayed timer callback also checks whether its timer has been rearmed.

Queued work and pending timer events retain QP references; idle execution
objects do not. QP teardown removes publication and management-QP visibility,
prevents timer rearming, shuts down timers and drains workers. Workers retain
valid error-flush state while draining. Admission is then closed under its
lock, remaining queues are flushed and type 2 window bindings to this QP are
released. Packet completions drain before resources and identities are
released.

Namespace storage uses revocable registration keys. An active namespace borrow
and registration read-side guard protect each operation independently. Idle
state does not retain active namespace references that would prevent namespace
exit from reaching the callback responsible for releasing it.

Packets, routes and UDP
=======================

``kernel::net::skbuff::packet`` distinguishes ownership of an skb header from
exclusive ownership of its data. Mutable byte access makes shared data private
and linearizes the requested range, including externally backed linear heads.
Receive owners retain their network device and discard unused destinations
before packets can enter deferred queues.

RXE wire views check opcode membership, header lengths, padding and payload
bounds before lending slices. Receive admission uses coherent QP configuration
snapshots for transport, peer and key validation. ICRC generation and checking
remain in RXE and operate on bounded bytes.

Transmit allocation uses ``kernel::net::udp::Payload``. Preparation consumes
the payload, checks the originating device and complete UDP selectors against
the route, and returns a ``Prepared`` packet. Only transport payload remains
mutable; the IP/UDP prefix, header offsets, family and destination cannot be
modified through the safe API. The owner reserves aligned link headroom,
retains the original network device and holds the route's namespace active
through native IP output.

RXE constructs RoCEv2 headers through the generic UDP configuration, selecting
port 4791 and zero UDP checksum mode. Native lookup sees the emitted ports,
traffic class, socket owner and security selectors. Lookup validates the
originating device's namespace index membership under RCU. Preparation checks the
retained device and routing selectors; headers use the source and destination
addresses the route resolves.

Each transmission looks up a fresh route. Route and ``Prepared`` owners
retain active namespace services while they own a destination. Idle QPs hold
no route or active namespace reference. Output protects destination device
sampling and revalidates the originating interface under RCU. Locally generated
packets carry no input-interface provenance into IP output. Local delivery
follows native IP, XFRM and UDP policy processing; the receiving tunnel resolves
the destination interface before dropping the input route and deferring work.

Transmit completions own the QP in revocable event state, independently of
``skb->cb``. Resident packet metadata retains the original network device even
after event cancellation. QP retirement cancels pending events and waits only
for callbacks already executing, so a packet held in networking cannot prevent
QP destruction. Later packet release invokes only resident code and frees its
independent metadata. Completions need no protocol socket
and do not pass a foreign namespace's socket to IP output. RXE installs the
completion before incrementing the outstanding count, and increments before
handoff or any possible packet destruction. Completion consumes the
low-watermark wakeup request atomically, preventing a stale wait publication
from stranding the requester. Network output consumes packet ownership on
success and failure.

Per-namespace UDP banks own receive sockets. Device leases share those
sockets; the final lease keeps the bank lock until its bound port is closed,
excluding replacement binding during closure. The namespace and registration
remain protected. Namespace exit revokes access and closes remaining sockets,
waits for network callbacks, and clears cached destinations while namespace
services remain live. Closure also purges ordinary UDP receive queues and their
memory accounting before releasing namespace services. Independent socket
references retain only inert protocol storage; delayed prefetched delivery
rejects closed sockets before repopulating caches or queues. Multicast filter
shutdown runs on netdevice unregister before network core filter flushing or
namespace migration; retained
memberships can drain later. Multicast changes take RTNL before the group
control mutex so validation, filter programming and device-type changes are
serialized without reversing notifier lock order.

Queues and userspace mappings
=============================

Mapped queues use checked shared-memory operations rather than ordinary Rust
references to bytes userspace can change. Native queue capacities govern
bounds, independently of userspace-writable headers. Producer and consumer
publication uses the required acquire/release operations.

Each send request is copied into private storage and decoded once. Engines
retain its metadata, descriptors and inline data through retries and
completion. Receive work similarly retains native progress. A racing userspace
producer can supply inconsistent bytes, but every resulting snapshot must
still parse safely.

CQ resize copies at most 32 entries per queue-lock acquisition. The original
ring remains available to polling and posting while new arrivals are mirrored
into the unpublished replacement. Migration skips consumed entries and commits
only after every remaining entry is ready. Arrivals that exceed a shrinking
replacement's capacity fail the resize while preserving the original queue.

SRQ resize keeps its original ring available to atomic kernel posters while
copying at most 32 entries per queue-lock acquisition. Receivers wait until
migration commits or fails, keeping the consumer position stable. Posts that
arrive between batches are copied before commit; arrivals exceeding a shrinking
replacement fail the resize while preserving the original ring.
Migration preserves entry order and uses private replacement positions;
mapped producer headers never select the destination. New mappings become
available only after migration succeeds.

Existing VMAs retain old mapped storage independently of the CQ, QP, SRQ or
userspace context. Completion codecs initialize the userspace record and check
its layout against the ABI; kernel-only metadata does not enter that record.

Shared allocations release their kernel mappings through preallocated work
owned outside the shared pages. Deferred-free linkage remains inaccessible to
userspace, and existing VMAs retain their independent page references.

Registered memory
=================

MR state serializes key, PD, access and translation publication. Acquired
handles retain an object incarnation and publication generation. Access
rejects stale versions even when a key or allocation address is reused.
Generation exhaustion rejects publication instead of wrapping.

Memory windows retain their bound region and, for type 2 windows, QP identity.
Lookups check both the window extent and MR range and retain binding
authorization. Each bounded memory access holds the window's access mutex;
replacement, invalidation and release revoke authorization and wait for
started accesses before returning. Old snapshots cannot access memory after
revocation completes. Waiting never holds the window registry IRQ lock.
Read replay records retain publication and binding versions without keeping
object references that would prevent teardown indefinitely. Atomic and flush
replay uses captured results.

Virtual DMA tracking retains mapping identities and checks ranges and
directions while holding the registry lock through each access. Identical live
address, size and direction tuples share one identity; their final unmap
revokes access before returning to the kernel caller. Fast-registration
translations capture those identities, so a replacement mapping after the
final unmap cannot revive an old translation. Reads materialize initialized
bytes at the native boundary; persistence covers only the validated request
range. Unrestricted DMA MRs intentionally admit a new live mapping.

Preparing a fast-registration mapping does not replace the active translation.
Callers can map the next buffer before posting local invalidation and
registration. Pending tables are detached under a short state lock for
allocation, DMA capture and old-capture disposal outside that IRQ lock.
Registration rejects a detached table and publishes a ready translation with
its key, bounds and generation after the previous registration is invalidated.
Table publication swaps ownership without walking old captures.

Pinned user memory uses bounded copies, atomics and persistence operations
through ``kernel::rdma::umem``. Externally mutable backing is never exposed as
an ordinary Rust slice. Local mappings remain scoped to the operation, and
writes perform the required page-cache maintenance. Access rejects poisoned
pages before mapping them. Persistent access requires backing validation at
registration and reregistration; RXE fences cache writeback before
acknowledging persistence. The user-memory APIs reject generic atomic64
emulation because its kernel-private locks cannot synchronize userspace
aliases.

ODP uses a non-sendable access guard that holds the umem mutex through bounded
operations. HMM faults use private PFN storage; publication and invalidation
use the same mutex for both virtual and hardware DMA mappings. An invalid
hardware snapshot preserves an older entry only when it owns a DMA mapping;
invalidation also clears cached PFNs after failed initial DMA setup.
RXE translates
IOVAs to registration offsets; it neither indexes PFN arrays nor maps pages
itself. The invalidation callback resides in the RDMA core and uses only
core memory-management operations, independently of provider module lifetime.
Asynchronous prefetch retains ODP backing and device allocation references
without retaining provider objects. Its dedicated core workqueue is drained
at core unload, independently of MR deregistration and device removal.
Synchronous fault handling may block; the HMM timeout limits invalidation
retries, not fault I/O. ODP registration and reregistration reject
persistent-flush access because faulted backing has no persistence guarantee;
global-visibility flushes remain supported. A global-only flush performs a
visibility barrier after admission without accessing registration backing;
replay acknowledges its recorded result without reacquiring that backing.

Validation and patch boundaries
===============================

Kernel abstractions precede their driver users in separate patches. The series
retains the existing RoCEv2 wire and userspace interfaces, RC/UC/UD
transports, kernel verbs, memory windows, ODP and IPv4/IPv6 support.

Native kernel posting supports SEND, RDMA READ/WRITE, compare-and-swap,
fetch-and-add, fast registration and local invalidation. READ_WITH_INV is
not supported by RXE; the generic RDMA client capability for that operation
is limited to iWARP. BIND_MW, FLUSH and ATOMIC_WRITE carry operation metadata
through the userspace shared-ring interface. Native posting rejects those
three operations because the kernel verbs request types provide no matching
typed extension for their metadata.

Validation should cover the crate-wide unsafe prohibition, configurations with
built-in or modular RDMA and RXE, and disabled userspace access, IPv6 or ODP.
Common kernel interfaces are also compiled without RXE. Unit coverage checks
wire boundaries, queue transitions, ownership operations and publication
decisions.

Runtime validation should include pyverbs, kernel verbs, queue mutation and
resize, registration and binding invalidation, retries, QP reset, namespace
deletion, netdevice migration and repeated module unload. Run RC/UC/UD and CM
traffic across namespaces for both IP families, including VLANs and cloned
packets. Use lockdep configurations to exercise registration and teardown
lifetimes. Report feature and hardware skips explicitly; passing runtime tests
alone does not prove an unsafe kernel abstraction sound.
