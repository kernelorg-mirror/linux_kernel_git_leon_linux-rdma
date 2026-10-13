// SPDX-License-Identifier: GPL-2.0

#include <net/netns/generic.h>
#include <net/sock.h>
#include <linux/atomic.h>
#include <linux/irqflags.h>
#include <linux/nstree.h>
#include <linux/module.h>

#ifdef CONFIG_NET
__rust_helper bool rust_helper_net_namespace_is_published(const struct net *net)
{
	return ns_tree_lookup_rcu(net->net_cookie, CLONE_NEWNET) == &net->ns;
}

__rust_helper void rust_helper_net_namespace_init_directory(atomic_t *state,
							  void (*init)(void))
{
	unsigned long flags;

	if (atomic_read_acquire(state) == 2)
		return;

	/* Exclude same-CPU reentry while the non-sleeping initializer runs. */
	local_irq_save(flags);
	if (atomic_cmpxchg(state, 0, 1) == 0) {
		init();
		atomic_set_release(state, 2);
	} else {
		atomic_cond_read_acquire(state, VAL == 2);
	}
	local_irq_restore(flags);
}

__rust_helper struct module *
rust_helper_net_namespace_callback_owner(const struct pernet_operations *ops)
{
	struct module *owner;

	rcu_read_lock();
	owner = __module_address((unsigned long)ops->init);
	if (owner != __module_address((unsigned long)ops->exit))
		owner = ERR_PTR(-EINVAL);
	else if (!try_module_get(owner))
		owner = ERR_PTR(-ENODEV);
	rcu_read_unlock();
	return owner;
}

__rust_helper void rust_helper_net_namespace_put_callback_owner(struct module *owner)
{
	module_put(owner);
}

__rust_helper void rust_helper_net_namespace_get_passive(struct net *net)
{
	net_passive_inc(net);
}

__rust_helper void rust_helper_net_namespace_put_passive(struct net *net)
{
	net_passive_dec(net);
}

__rust_helper struct net *rust_helper_get_net(struct net *net)
{
	return get_net(net);
}

__rust_helper struct net *rust_helper_maybe_get_net(struct net *net)
{
	return maybe_get_net(net);
}

__rust_helper void rust_helper_put_net(struct net *net)
{
	put_net(net);
}

__rust_helper void *rust_helper_net_generic(const struct net *net, unsigned int id)
{
	return net_generic(net, id);
}
#endif
