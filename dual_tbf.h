#ifndef DUAL_TBF_H
#define DUAL_TBF_H

#include "network.h" 
#include "params.h"

/* Structure of sk_buff and the function pointer to reinject packets */
/*********************************/
/*******START: CUSTOM ************/
/*********************************/
//Structure changed
//Two new elements, net & sk added. These elements will be set automatically when net filter hooks are called at Local_out
//Ok function pointer modified. Two new elements are passed as parameters to the ok function.
struct Packet
{
	int (*okfn)(struct sock *, struct net *, struct sk_buff *);
	struct net *net;
	struct sock *sk;
	struct sk_buff *skb;                  	
};
/*********************************/
/*******END: CUSTOM ************/
/*********************************/
/* Dual token bucket rate limiter */
/*********************************/
/*******START: CUSTOM ************/
/*********************************/
//Code (elements) related to small flows handling latency removed
//@congested element added to mark the channel as congested or not
struct dual_tbf_rl
{
	//Array(Queue) of packets for flows
	struct Packet* packet;
	//Head offset  of packets of flows
	unsigned int packet_head;		
	//Current queue length of flows
	unsigned int packet_len;		
	//Maximum queue length	of flows
	unsigned int packet_max_len;
	//Bandwidth guarantee rate in Mbps
	unsigned long long bg_rate;
	//Work conserving rate in Mbps
	unsigned long long wc_rate;
	//tokens in bytes for bandwidth guarantee traffic 
	unsigned long long bg_tokens;
	//tokens in bytes for work conserving traffic 
	unsigned long long wc_tokens;
	//bucket size in bytes for bandwidth guarantee traffic
	unsigned long long bg_bucket;
	//bucket size in bytes for work conserving traffic 
	unsigned long long wc_bucket;
	//Last update timer of timer
	ktime_t last_update_time;
	//Is link congested	
	bool congested;
	//Lock for the flow queue 
	spinlock_t packet_lock;
};
/*********************************/
/*******END: CUSTOM ************/
/*********************************/


/*********************************/
/*******START: CUSTOM ************/
/*********************************/
//Code (elements) related to small flows handling latency removed
static unsigned int Init_dual_tbf(
	struct dual_tbf_rl* dual_tbfPtr, 
	unsigned int bg_rate,
	unsigned int wc_rate,
	unsigned int bg_bucket,
	unsigned int wc_bucket,
	unsigned int packet_max_len ,
	int flags)
{
	if(unlikely(dual_tbfPtr==NULL))
		return 0;
	
	struct Packet* packet_tmp=kmalloc(packet_max_len*sizeof(struct Packet),flags);
	if(unlikely(packet_tmp==NULL))
		return 0;
	
	dual_tbfPtr->packet=packet_tmp;
	dual_tbfPtr->packet_head=0;
	dual_tbfPtr->packet_len=0;
	dual_tbfPtr->packet_max_len=packet_max_len;
	
	/*********************************/
	/*******START: CUSTOM ************/
	/*********************************/
	dual_tbfPtr->bg_rate=bg_rate*1024*1024/8;	//Changed to bytes per second from Mbps
	dual_tbfPtr->bg_bucket=bg_rate*1024*1024/8; //initialized to bg rate
	dual_tbfPtr->bg_tokens=bg_rate*1024*1024/8; //initialized to bg rate
	dual_tbfPtr->wc_rate=wc_rate; 
	dual_tbfPtr->wc_bucket=wc_rate; 
	dual_tbfPtr->wc_tokens=wc_rate; 
	dual_tbfPtr->congested = 0;
	/*********************************/
	/*******END: CUSTOM ************/
	/*********************************/
	
	dual_tbfPtr->last_update_time=ktime_get(); //current time in ns
	spin_lock_init(&(dual_tbfPtr->packet_lock));
	return 1;
}
/*********************************/
/*******END: CUSTOM ************/
/*********************************/
		

/* Release resources of token bucket rate limiter */
static void Free_dual_tbf(struct dual_tbf_rl* dual_tbfPtr)
{
	if(dual_tbfPtr!=NULL)
	{
		kfree(dual_tbfPtr->packet);
	}
}

/* Enqueue a packet to dual token bucket rate limiter. If it succeeds, return 1 */
/*********************************/
/*******START: CUSTOM ************/
/*********************************/
//Added 2 new parameters to the function
//net & sk variables added. These values will be passed from Local_out netfilter hook and will be stored in Packet structure
//parameters required for ok function included
static unsigned int Enqueue_dual_tbf(struct dual_tbf_rl* dual_tbfPtr, struct net *net, struct sock *sk, struct sk_buff *skb, int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
	//If there is still capacity to contain new packets
	if(dual_tbfPtr->packet_len<dual_tbfPtr->packet_max_len)
	{
		//Index for new insert packet
		unsigned int queueIndex=(dual_tbfPtr->packet_head+dual_tbfPtr->packet_len)%dual_tbfPtr->packet_max_len;
		dual_tbfPtr->packet[queueIndex].net=net;				
		dual_tbfPtr->packet[queueIndex].sk=sk;					
		dual_tbfPtr->packet[queueIndex].skb=skb;
		dual_tbfPtr->packet[queueIndex].okfn=okfn;
		dual_tbfPtr->packet_len++;
		return 1;
	}
	else
	{
		return 0;
	}
}
/*********************************/
/*******END: CUSTOM ************/
/*********************************/



/* Dequeue a packet from dual token bucket rate limiter. If it succeeds, return 1 */
static unsigned int Dequeue_dual_tbf(struct dual_tbf_rl* dual_tbfPtr, unsigned int is_bg)
{	
	if(dual_tbfPtr->packet_len>0)
	{
		dual_tbfPtr->packet_len--;
		//If we use tokens of bandwidth guarantee traffic 
		if(is_bg==1)
		{
			enable_ecn_dscp(dual_tbfPtr->packet[dual_tbfPtr->packet_head].skb,BANDWIDTH_GUARANTEE_DSCP);
		}
		//If we use tokens of work conserving traffic 
		else
		{
			enable_ecn_dscp(dual_tbfPtr->packet[dual_tbfPtr->packet_head].skb,WORK_CONSERVING_DSCP);			
		}			
		//Dequeue packet
		/*********************************/
		/*******START: CUSTOM ************/
		/*********************************/
		//ok function call
		//two parameters, net and sk required for ok function added.
		(dual_tbfPtr->packet[dual_tbfPtr->packet_head].okfn)(dual_tbfPtr->packet[dual_tbfPtr->packet_head].net, dual_tbfPtr->packet[dual_tbfPtr->packet_head].sk, dual_tbfPtr->packet[dual_tbfPtr->packet_head].skb);
		/*********************************/
		/*******END: CUSTOM ************/
		/*********************************/
		
		//Reinject head packet of current queue
		dual_tbfPtr->packet_head=(dual_tbfPtr->packet_head+1)%(dual_tbfPtr->packet_max_len);
		return 1;
	}
	else
	{
		return 0;
	}
	
}
#endif
