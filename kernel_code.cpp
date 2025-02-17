#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/pfil.h>

static pfil_hook_t *pfh = NULL;
static unsigned long dropped_icmp_count = 0;
static unsigned long dropped_icmp_bytes = 0;

/* Packet filtering function */
// pkt->packet, dir->dr, ctx->context, inp->inpb
static int icmp_block_hook(pfil_packet_t packet, struct ifnet *ift, int dr, void *context, struct inpcb *inpb)
{
    struct mbuf *m;
    struct ip *ip_header;
    struct icmp *icmp_header;
    m = *pkt.m;

    int hlen;


    /* Ensure the packet has an IP header */
    if (m == NULL || m->m_len < sizeof(struct ip)) {
        return 0;
    }

    ip_header = mtod(m, struct ip *);

    hlen = ip_header->ip_hl << 2;
    if (m->m_pkthdr.len < hlen+sizeof(struct icmp_header))
        return 0;

    /* Check if it's an ICMP packet */
    if (ip_header->ip_p == IPPROTO_ICMP) {
        /* Ensure the full ICMP header is present */
        if (m->m_len < (ip_header->ip_hl << 2) + sizeof(struct icmp)) {
            return 0;
        }

        icmp_header = (struct icmp *)((char *)ip_header + (ip_header->ip_hl << 2));

        /* Drop ICMP Echo requests (ping requests) */
        if (icmp_header->icmp_type == ICMP_ECHO) {
            dropped_icmp_count++;
            dropped_icmp_bytes += m->m_pkthdr.len;
            printf("[icmp_block] Dropped ICMP Echo Request #%lu (Size: %lu bytes)\n", 
                   dropped_icmp_count, m->m_pkthdr.len);
            return PFIL_DROPPED; // Drop the packet
        }
    }

    return 0; // Allow other packets
}

static pfil_hook_t hook = NULL;

/* Module load function */
static int icmp_block_load(void)
{
    struct pfil_hook_args pha = {
        .pa_modname = "icmp_block",
        .pa_name = "icmp_block_hook",
        .pa_func = icmp_block_hook,
        .pa_flags = PFIL_IN,  // Filter incoming packets
        .pa_type = PFIL_TYPE_IP4,
        .pa_order = 0
    };

    struct pfil_link_args link_args;
    link_args.pa_version = PFIL_VERSION;
    link_args.pa_flags = PFIL_IN | PFIL_HOOKPTR;
    link_args.pa_headname = "inet";

    pfh = pfil_add_hook(&pha);
    if (pfh == NULL) {
        printf("[icmp_block] Failed to register packet filter hook\n");
        return EINVAL;
    }

    link_args.pa_hook = hook;
    pfil_link(&link_args);
    printf("[icmp_block] ICMP block module loaded\n");
    return 0;
}

/* Module unload function */
static int icmp_block_unload(void)
{
    if (pfh) {
        pfil_remove_hook(pfh);
        pfh = NULL;
    }
    printf("[icmp_block] Module unloaded. Dropped %lu ICMP packets (%lu bytes)\n",
           dropped_icmp_count, dropped_icmp_bytes);
    return 0;
}

/* Module event handler */
static int icmp_block_handler(module_t mod, int event, void *arg)
{
    switch (event) {
    case MOD_LOAD:
        return icmp_block_load();
    case MOD_UNLOAD:
        return icmp_block_unload();
    default:
        return EOPNOTSUPP;
    }
}

static moduledata_t icmp_block_mod = {
    "icmp_block",
    icmp_block_handler,
    NULL
};

DECLARE_MODULE(icmp_block, icmp_block_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
