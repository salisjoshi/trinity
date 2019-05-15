#ifndef NETWORK_H
#define NETWORK_H

#include "params.h"

//Create a feebdack packet. Note that bit is the congestion information and pkt is an incoming packet  
//Return 1 if successful. Else, return 0. 
//My implementation is based on send_reset function of Linux kernel
/*********************************/
/*******START: CUSTOM ************/
/*********************************/
//Two additional parameters, net & sk added
//these parameters will be passed from netfilter local_out hook
//protocol_no parameter added to indicate to generate congestion feedback or packet trapping alert 
static void generate_packet(unsigned int bit, struct net *net, struct sock *sk, struct sk_buff *pkt, int protocol_no)
{
	struct sk_buff *skb;
	struct ethhdr *eth_from;
	struct iphdr *iph_to, *iph_from;
	//unsigned int *ip_opt=NULL;		  	
	unsigned int addr_type = RTN_LOCAL;
			
	eth_from = eth_hdr(pkt);
	if(unlikely(eth_from->h_proto!= __constant_htons(ETH_P_IP)))
		return 0;
	
	iph_from=(struct iphdr *)skb_network_header(pkt);
	
	skb=alloc_skb(FEEDBACK_HEADER_SIZE+LL_MAX_HEADER, GFP_ATOMIC);
	if(unlikely(!skb))
		return 0;
	
	skb_reserve(skb, LL_MAX_HEADER);
	skb_reset_network_header(skb);
	iph_to=(struct iphdr *)skb_put(skb, FEEDBACK_HEADER_SIZE);
	iph_to->version=4;
	iph_to->ihl=FEEDBACK_HEADER_SIZE/4;
	iph_to->tos=FEEDBACK_PACKET_TOS; 
	iph_to->tot_len =htons(FEEDBACK_HEADER_SIZE);
	iph_to->id=htons((unsigned short int)bit);
	iph_to->frag_off=0;
	iph_to->protocol=(u8)protocol_no;			//use the passed protocol_no to generate congestion feedback or packet trapping pkt
	iph_to->check=0;
	iph_to->saddr=iph_from->daddr;
	iph_to->daddr=iph_from->saddr;
	
	/* ip_route_me_harder expects skb->dst to be set */
	skb_dst_set_noref(skb, skb_dst(pkt));
	
	skb->protocol=htons(ETH_P_IP);
					
	if (ip_route_me_harder(net, skb, addr_type)) //net variable added while calling as required for new linux kernel v4.4
		goto free_skb;
	
	iph_to->ttl=ip4_dst_hoplimit(skb_dst(skb));	
	
	/* "Never happens" */
	if (skb->len > dst_mtu(skb_dst(skb)))
		goto free_skb;
	
	ip_local_out(net, sk, skb);					 //net & sk variable added while calling as required for linux kernel v4.4
	
	printk(KERN_INFO "Generate feedback packet with bit=%u\n",bit);
	return 1;

 free_skb:
	kfree_skb(skb);
	
	return 0;	
}

static void enable_ecn_dscp(struct sk_buff *skb, u8 dscp)
{
	struct iphdr *iph =ip_hdr(skb);
	if(likely(iph!=NULL))
	{
		ipv4_change_dsfield(iph, 0xff, (dscp<<2)|INET_ECN_ECT_0);
	}
}

static void enable_ecn(struct sk_buff *skb)
{
	struct iphdr *iph =ip_hdr(skb);
	if(likely(iph!=NULL))
	{
		ipv4_change_dsfield(iph, 0xff, iph->tos | INET_ECN_ECT_0);
	}
}

static void clear_ecn(struct sk_buff *skb)
{
	struct iphdr *iph=ip_hdr(skb);
	if(likely(iph!=NULL))
	{
		ipv4_change_dsfield(iph, 0xff, iph->tos & ~0x3);
	}
}

#endif
