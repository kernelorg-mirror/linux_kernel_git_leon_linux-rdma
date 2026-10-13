/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
#ifndef RXE_NS_H
#define RXE_NS_H

struct rxe_ns_sock;

struct rxe_ns_sock *rxe_ns_get(struct net *net);
void rxe_ns_release(struct rxe_ns_sock *ns);
#if IS_ENABLED(CONFIG_IPV6)
struct sock *rxe_ns_pernet_sk6(struct net *net);
#endif
int rxe_namespace_init(void);
void rxe_namespace_exit(void);

#endif /* RXE_NS_H */
