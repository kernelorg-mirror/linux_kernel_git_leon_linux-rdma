// SPDX-License-Identifier: GPL-2.0

#include <linux/netdevice.h>
#include <linux/if_vlan.h>

#ifdef CONFIG_NET
__rust_helper bool rust_helper_netif_running(const struct net_device *dev)
{
	return netif_running(dev);
}

__rust_helper bool rust_helper_netif_carrier_ok(const struct net_device *dev)
{
	return netif_carrier_ok(dev);
}

__rust_helper unsigned int
rust_helper_ll_reserved_space(const struct net_device *dev)
{
	return LL_RESERVED_SPACE_EX(dev, READ_ONCE(dev->hard_header_len));
}

__rust_helper void rust_helper_dev_hold(struct net_device *dev)
{
	dev_hold(dev);
}

__rust_helper struct net *rust_helper_dev_net(const struct net_device *dev)
{
	return dev_net(dev);
}

__rust_helper bool rust_helper_is_vlan_dev(const struct net_device *dev)
{
#if IS_ENABLED(CONFIG_VLAN_8021Q)
	return is_vlan_dev(dev);
#else
	return false;
#endif
}

__rust_helper u16 rust_helper_vlan_dev_vlan_id(const struct net_device *dev)
{
	return vlan_dev_vlan_id(dev);
}

__rust_helper void rust_helper_dev_put(struct net_device *dev)
{
	dev_put(dev);
}
#endif
