#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Check shared UDP bindings after successful and failed RXE registration.

source "$(dirname "$0")/../kselftest/ktap_helpers.sh"

PORT=4791
TUN0="rxt$$a"
TUN1="rxt$$b"
RXE0="rxe_socket_$$_a"
RXE1="rxe_socket_$$_b"
created_tun0=false
created_tun1=false
created_rxe0=false
created_rxe1=false
loaded_modules=()

cleanup()
{
	$created_rxe1 && rdma link del "$RXE1" 2>/dev/null
	$created_rxe0 && rdma link del "$RXE0" 2>/dev/null
	$created_tun1 && ip link del "$TUN1" 2>/dev/null
	$created_tun0 && ip link del "$TUN0" 2>/dev/null
	for ((i=${#loaded_modules[@]}-1; i>=0; i--)); do
		rmmod "${loaded_modules[i]}" 2>/dev/null
	done
}
trap cleanup EXIT

port_open()
{
	local sockets

	sockets=$(ss -Huln sport = :$PORT) || fail "query UDP bindings"
	[[ "$sockets" == *":$PORT"* ]]
}

fail()
{
	ktap_test_fail "$*"
	ktap_finished
}

module_is_builtin()
{
	local dependency

	while read -r dependency; do
		[[ "$dependency" == "builtin $1" ]] && return 0
	done < <(modprobe --show-depends "$1" 2>/dev/null)
	return 1
}

if [[ $EUID -ne 0 ]]; then
	ktap_print_header
	ktap_skip_all "root privileges are required"
	exit "$KSFT_SKIP"
fi
for command in ip rdma ss modprobe rmmod unshare; do
	command -v "$command" >/dev/null || {
		ktap_print_header
		ktap_skip_all "missing command: $command"
		exit "$KSFT_SKIP"
	}
done
if [[ ${1:-} != --isolated ]]; then
	# Keep unrelated host sockets and concurrent tests out of the assertions.
	exec unshare --net -- "$0" --isolated
fi
ktap_print_header
for mod in tun rdma_rxe; do
	if [[ ! -d /sys/module/$mod ]] && ! module_is_builtin "$mod"; then
		if modprobe --first-time "$mod"; then
			loaded_modules+=("$mod")
		elif [[ ! -d /sys/module/$mod ]]; then
			ktap_skip_all "cannot load $mod"
			exit "$KSFT_SKIP"
		fi
	fi
done
if port_open; then
	ktap_skip_all "UDP port $PORT is already in use"
	exit "$KSFT_SKIP"
fi
ktap_set_plan 1

ip tuntap add mode tun "$TUN0" || fail "create first interface"
created_tun0=true
ip addr add 192.0.2.1/24 dev "$TUN0" || fail "address first interface"
ip link set "$TUN0" up || fail "enable first interface"
rdma link add "$RXE0" type rxe netdev "$TUN0" || fail "register first RXE"
created_rxe0=true
port_open || fail "UDP binding missing after first registration"

ip tuntap add mode tun "$TUN1" || fail "create second interface"
created_tun1=true
ip addr add 198.51.100.1/24 dev "$TUN1" || fail "address second interface"
ip link set "$TUN1" up || fail "enable second interface"
rdma link add "$RXE1" type rxe netdev "$TUN1" || fail "register second RXE"
created_rxe1=true
rdma link del "$RXE1" || fail "delete second RXE"
created_rxe1=false

# assign_name() rejects an occupied fixed RDMA name with ENFILE. A successful
# registration above proves this interface can reach the duplicate-name check.
for ((i=0; i<16; i++)); do
	if error=$(LC_ALL=C rdma link add "$RXE0" type rxe netdev "$TUN1" 2>&1); then
		fail "duplicate RDMA name accepted"
	fi
	[[ "$error" == *"Too many open files in system"* ]] ||
		fail "unexpected duplicate-name failure: $error"
done
rdma link add "$RXE1" type rxe netdev "$TUN1" || fail "register after failures"
created_rxe1=true
port_open || fail "UDP binding missing after second registration"
rdma link del "$RXE1" || fail "delete second RXE after failures"
created_rxe1=false
port_open || fail "UDP binding closed while first RXE remains"
rdma link del "$RXE0" || fail "delete first RXE"
created_rxe0=false
port_open && fail "UDP binding remains after both RXE devices were deleted"

# Binding disappearance does not prove every independently retained SocketRef
# has been freed; it verifies that all registration leases were released.
ktap_test_pass "failed registrations release their shared UDP binding leases"
ktap_finished
