#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/inet.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/fs.h>
#include <linux/random.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/vmalloc.h>
#include <linux/list.h>
#include <linux/delay.h>

#include "tx.h"
#include "rx.h"
#include "rl.h"
#include "rc.h"
#include "network.h"
#include "params.h"
#include "control.h"

//Trinity needs to maintain per-flow state.
#include "flow.h"
#include "hash.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BAI Wei wbaiab@cse.ust.hk");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("Kernel module of Trinity");

//DEVICE_NAME = "trinity" defined in control.h
MODULE_SUPPORTED_DEVICE(DEVICE_NAME);

static char *param_dev=NULL;

//this function is used to describe the arguments to be passed to the module
MODULE_PARM_DESC(param_dev, "Network interface to operate");
module_param(param_dev, charp, 0);

//Open virtual characer device "/dev/trinity"
static int device_open(struct inode *, struct file *);
//Release virtual characer device "/dev/trinity"
static int device_release(struct inode *, struct file *);
//user space-kernel space communication (for Linux kernel 2.6.38.3)
static int device_ioctl(struct file *, unsigned int, unsigned long) ;
//Hook for outgoing packets
static struct nf_hook_ops nfho_outgoing;
//Hook for incoming packets
static struct nf_hook_ops nfho_incoming;

//RX context pointer
static struct rx_context* rxPtr;
//Lock for rx information
static spinlock_t rxLock;
//TX context pointer
static struct tx_context* txPtr;
//Lock for TX information
static spinlock_t txLock;

//FlowTable
static struct FlowTable ft;

/*
struct pair_tx_context* tx_pairPtr=NULL;
struct pair_tx_context* tx_pairPtr2=NULL;
struct pair_tx_context* tx_pairPtr3=NULL;
struct endpoint_tx_context* tx_endpointPtr=NULL;
struct pair_rx_context* rx_pairPtr=NULL;
struct pair_rx_context* rx_pairPtr2=NULL;
struct endpoint_rx_context* rx_endpointPtr=NULL;
*/

static int device_open(struct inode *inode, struct file *file)
{
	//printk(KERN_INFO "Device %s is opened\n",DEVICE_NAME);
	try_module_get(THIS_MODULE);
	return SUCCESS;
}

static int device_release(struct inode *inode, struct file *file)
{
	//printk(KERN_INFO "Device %s is closed\n",DEVICE_NAME);
	module_put(THIS_MODULE);
	return SUCCESS;
}

//This context of this function should be kernel thread rather than interrupt. Is this correct?
static int device_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
	//All possible pointers we will use in this function
	struct pair_context_user* user_pairPtr=NULL;
	struct endpoint_context_user* user_endpointPtr=NULL;
	struct pair_rx_context* rx_pairPtr=NULL;
	struct pair_tx_context* tx_pairPtr=NULL;
	struct endpoint_rx_context* rx_endpointPtr=NULL;
	//struct endpoint_tx_context* tx_endpointPtr=NULL;//commented by Salis Joshi

	switch (ioctl_num)
	{
		//Case 1: Insert a new pair RX context
		case IOCTL_INSERT_RX_PAIR:
			user_pairPtr=(struct pair_context_user*)ioctl_param;
			rx_pairPtr=kmalloc(sizeof(struct pair_rx_context), GFP_KERNEL);
			if(rx_pairPtr!=NULL)
			{
				Init_pair_rx_context(rx_pairPtr,user_pairPtr->local_ip,user_pairPtr->remote_ip,user_pairPtr->rate);
				Insert_rx_pair(rx_pairPtr,rxPtr);
			}
			else
			{
				printk(KERN_INFO "Kmalloc error when inserting a new pair RX context\n");
			}
			break;
		//Case 2: Insert a new pair TX context
		case IOCTL_INSERT_TX_PAIR:
			user_pairPtr=(struct pair_context_user*)ioctl_param;
			tx_pairPtr=kmalloc(sizeof(struct pair_tx_context), GFP_KERNEL);
			if(tx_pairPtr!=NULL)
			{
				Init_pair_tx_context(tx_pairPtr,user_pairPtr->local_ip,user_pairPtr->remote_ip,user_pairPtr->rate,
				BUCKET_SIZE_BYTES, MAX_QUEUE_LEN,&xmit_tasklet, &my_hrtimer_callback, TIMER_INTERVAL_US,GFP_KERNEL);
				Insert_tx_pair(tx_pairPtr,txPtr);
				/*********************************/
				/*******START: CUSTOM ************/
				/*********************************/
				//This function call will calculate initial WC rate according to the paper; initially WC rate was set to allocated BG rate in Init_pair_tx_context
				calculate_wc_rate(txPtr, 1);	
				/*********************************/
				/*******END: CUSTOM **************/
				/*********************************/
				
			}
			else
			{
				printk(KERN_INFO "Kmalloc error when inserting a new pair TX context\n");
			}
			break;
		//Case 3: Delete a pair RX context
		case IOCTL_DELETE_RX_PAIR:
			user_pairPtr=(struct pair_context_user*)ioctl_param;
			Delete_rx_pair(user_pairPtr->local_ip,user_pairPtr->remote_ip,rxPtr);
			break;
		//Case 4: Delete a pair TX context
		case IOCTL_DELETE_TX_PAIR:
			user_pairPtr=(struct pair_context_user*)ioctl_param;
			Delete_tx_pair(user_pairPtr->local_ip,user_pairPtr->remote_ip,txPtr);
			break;
		//Case 5: Insert a new endpoint RX context
		case IOCTL_INSERT_RX_ENDPOINT:
			user_endpointPtr=(struct endpoint_context_user*)ioctl_param;
			rx_endpointPtr=kmalloc(sizeof(struct endpoint_rx_context), GFP_KERNEL);
			if(rx_endpointPtr!=NULL)
			{
				Init_endpoint_rx_context(rx_endpointPtr,user_endpointPtr->local_ip,user_endpointPtr->rate);
				Insert_rx_endpoint(rx_endpointPtr,rxPtr);
			}
			else
			{
				printk(KERN_INFO "Kmalloc error when inserting a new endpoint RX context\n");
			}
			break;
		//Case 6: Insert a new endpoint TX context
		case IOCTL_INSERT_TX_ENDPOINT:
			user_endpointPtr=(struct endpoint_context_user*)ioctl_param;
			tx_endpointPtr=kmalloc(sizeof(struct endpoint_tx_context), GFP_KERNEL);
			if(tx_endpointPtr!=NULL)
			{
				Init_endpoint_tx_context(tx_endpointPtr,user_endpointPtr->local_ip,user_endpointPtr->rate,&tx_xmit_tasklet, &my_tx_hrtimer_callback, CONTROL_INTERVAL_DATA_SENT);
				Insert_tx_endpoint(tx_endpointPtr,txPtr);
			}
			else
			{
				printk(KERN_INFO "Kmalloc error when inserting a new endpoint TX context\n");
			}
			break;
		//Case 7: Delete an endpoint RX context
		case IOCTL_DELETE_RX_ENDPOINT:
			user_endpointPtr=(struct endpoint_context_user*)ioctl_param;
			Delete_rx_endpoint(user_endpointPtr->local_ip,rxPtr);
			break;
		//Case 8: Delete an endpoint TX context
		case IOCTL_DELETE_TX_ENDPOINT:
			user_endpointPtr=(struct endpoint_context_user*)ioctl_param;
			Delete_tx_endpoint(user_endpointPtr->local_ip,txPtr);
			break;
		//Case 9: Display RX
		case IOCTL_DISPLAY_RX:
			print_rx_context(rxPtr);
			break;
		//Case 10: Display TX
		case IOCTL_DISPLAY_TX:
			print_tx_context(txPtr);
			break;

	}
	return SUCCESS;
}

struct file_operations ops = {
    .read = NULL,
    .write = NULL,
   // .ioctl = device_ioctl, //For 2.6.32 kernel
    .unlocked_ioctl = device_ioctl, //For 2.6.38 kernel
    .open = device_open,
    .release = device_release,
};
/*********************************/
/*******START: CUSTOM ************/
/*********************************/
//Parameter of function definition changed according to linux kernel 4.4; Original code function defination was according to linux kernel 2.6
//Modified hook function defination by removing all the references related to handling latency
static unsigned int hook_func_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
/*********************************/
/*******END: CUSTOM **************/
/*********************************/
{
	
	struct pair_tx_context* pair_txPtr=NULL;
	struct iphdr *ip_header=NULL;
	unsigned int local_ip;
	unsigned int remote_ip;
	unsigned int result;
	struct Flow f;
	struct Information* info_pointer=NULL;
	//struct tcphdr *tcp_header=NULL;
	unsigned int delete_result;
	unsigned int payload_len;
	
	if(!state->out)
		return NF_ACCEPT;
	
	/*********************************/
	/*******START: CUSTOM ************/
	/*********************************/
	//Will get the ip header from the outgoing packets
	struct sk_buff *sock_buff;
	sock_buff = skb;
	
	if(!sock_buff)
	{
		printk(KERN_INFO "sk buff is null");
		return NF_ACCEPT;
	}

	ip_header = ip_hdr(sock_buff);
	/*********************************/
	/*******END: CUSTOM **************/
	/*********************************/
	
	//The packet is not ip packet (e.g. ARP or others)
	if (unlikely(ip_header==NULL))
		return NF_ACCEPT;

	local_ip=ip_header->saddr;
	remote_ip=ip_header->daddr;
	
	//unsigned short int remote_port, local_port;
	//tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
	//local_port=ntohs(tcp_header->source);
	//remote_port=ntohs(tcp_header->dest);
		
	pair_txPtr=Search_tx_pair(txPtr,local_ip,remote_ip);
			
	if(likely(pair_txPtr!=NULL))
	{
		spin_lock_bh(&(pair_txPtr->rateLimiter.packet_lock));
		/*********************************/
		/*******START: CUSTOM ************/
		/*********************************/
		/**Modified function call with additional/Changed parameters passed 
		 * Additional parameters are -
		 * state->net of type struct net
		 * state->sk of type struct sock
		 * Changed parameter is -
		 * state->okfn, ok function defined as function pointer inside struct nf_hook_state, in older kernel versions, directly oknf was passed
		 * These variables are set automatically when the packets are captured by netfilter hook
		 */		  
		result=Enqueue_dual_tbf(&(pair_txPtr->rateLimiter), state->net, state->sk, skb,state->okfn);
		/*********************************/
		/*******END: CUSTOM **************/
		/*********************************/
		
		spin_unlock_bh(&(pair_txPtr->rateLimiter.packet_lock));

		//If enqueue succeeds
		if(result==1)
			return NF_STOLEN;
		else
			return NF_DROP;
	}

	return NF_ACCEPT;
}

/*********************************/
/*******START: CUSTOM ************/
/*********************************/
//Parameter of function definition changed according to linux kernel 4.4; Original code function defination was according to linux kernel 2.6
//Also, modified hook function defination by removing all the references related to handling latency
static unsigned int hook_func_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
/*********************************/
/*******END: CUSTOM **************/
/*********************************/
{
	struct pair_rx_context* pair_rxPtr=NULL;
	struct pair_tx_context* pair_txPtr=NULL;
	ktime_t now;
	struct iphdr *ip_header=NULL;	//IP  header structure
	unsigned int local_ip;
	unsigned int remote_ip;
	//unsigned long flags;	//variable for save current states of irq
	unsigned int bit=0;	//feedback information
	unsigned short int feedback=0;
	unsigned short int ECN_fraction=0;
	unsigned short int isPktTrapped=0;

	
	if(!state->in)
		return NF_ACCEPT;

	/*if(strcmp(!state->in->name,param_dev)!=0)
		return NF_ACCEPT;
	*/
	
	ip_header=(struct iphdr *)skb_network_header(skb);

	//The packet is not ip packet (e.g. ARP or others)
	if (unlikely(ip_header==NULL))
		return NF_ACCEPT;

	local_ip=ip_header->daddr;
	remote_ip=ip_header->saddr;
	
	//If it's control packet, we need to do some special operations here
	if((u8)(ip_header->protocol)==FEEDBACK_PACKET_IPPROTO)
	{	
		printk(KERN_INFO "IN: control packet received");
		
		//Retrieve ECN fraction information
		ECN_fraction=ntohs(ip_header->id);
		printk(KERN_INFO "Receive control message packet, ECN fraction is %u%%\n",(unsigned int)ECN_fraction);
		pair_txPtr=Search_tx_pair(txPtr,local_ip,remote_ip);
		if(pair_txPtr!=NULL)
		{
			if(ECN_fraction!=0)
			{
				//DCTCP-like rate control for work conserving rate
				pair_txPtr->rateLimiter.wc_rate=pair_txPtr->rateLimiter.wc_rate*(200-ECN_fraction)/200;//max(pair_txPtr->rateLimiter.wc_rate*(200-ECN_fraction)/200,MINIMUM_RATE);
				//new_wc_rate = (1-B/2)* old_wc_rate --> a/c to paper
				/*********************************/
				/*******START: CUSTOM ************/
				/*********************************/
				//Mark the channel between two VM as congested
				//Added as per the paper
				pair_txPtr->rateLimiter.congested = 1;
				/*********************************/
				/*******END: CUSTOM **************/
				/*********************************/
			}
			else
			{
				/*********************************/
				/*******START: CUSTOM ************/
				/*********************************/
				//New function called to calculate WC rate as per the paper
				calculate_wc_rate(txPtr, 0);
				//Added as per the paper
				pair_txPtr->rateLimiter.congested = 0;
				/*********************************/
				/*******END: CUSTOM **************/
				/*********************************/
			}
		}
		//We should not let any VM receive this packet
		return NF_DROP;
	}
	
	/*********************************/
	/*******START: CUSTOM ************/
	/*********************************/
	//If it is an alert packet indicating packet trapping, set WC Rate = MIN_WC_RATE if packet trapping is confirmed
	if((u8)(ip_header->protocol)==TRAPPING_PACKET_IPPROTO)
	{	
		pair_txPtr=Search_tx_pair(txPtr,local_ip,remote_ip);
		if(pair_txPtr!=NULL)
		{
			if(pair_txPtr->stats.tx_wc_ecn_bytes_trap !=0)
			{
				pair_txPtr->rateLimiter.wc_rate=MIN_WC_RATE;
				pair_txPtr->rateLimiter.wc_bucket=MIN_WC_RATE;
				pair_txPtr->rateLimiter.congested=1;
			}
		}
		return NF_DROP;
	}
	/*********************************/
	/*******END: CUSTOM **************/
	/*********************************/

	pair_rxPtr=Search_rx_pair(rxPtr,local_ip,remote_ip);
		
	if(likely(pair_rxPtr!=NULL))
	{
		spin_lock_bh(&(pair_rxPtr->pair_lock));
		now=ktime_get();
		pair_rxPtr->last_update_time=now;
		
		/*********************************/
		/*******START: CUSTOM ************/
		/*********************************/
		//Set the flag to generate alert packet if it has not received WC traffic for CONTROL_INTERVAL_PKT_TRAPPING period
		if(ktime_us_delta(now,pair_rxPtr->stats.last_update_time) > CONTROL_INTERVAL_PKT_TRAPPING)
		{
			isPktTrapped = 1;
		}
		/*********************************/
		/*******END: CUSTOM **************/
		/*********************************/
			
		
		//If the interval is larger than control interval
		if(ktime_us_delta(now,pair_rxPtr->start_update_time)>=CONTROL_INTERVAL_US)
		{
			printk(KERN_INFO "IN: greater than control interval time");
			if(pair_rxPtr->stats.rx_wc_bytes+pair_rxPtr->stats.rx_bg_bytes>0)
			{
				printk(KERN_INFO "IN: bytes received");
				//print_pair_rx_context(pair_rxPtr);
				//We need to generate feedback packet now
				feedback=1;
				//Calculate the ECN fraction of work conserving traffic in this control interval
				if(pair_rxPtr->stats.rx_wc_bytes>0)
				{
					bit=pair_rxPtr->stats.rx_wc_ecn_bytes*100/pair_rxPtr->stats.rx_wc_bytes;
				}
			}
			pair_rxPtr->stats.rx_bg_bytes=0;
			pair_rxPtr->stats.rx_bg_ecn_bytes=0;
			pair_rxPtr->stats.rx_wc_bytes=0;
			pair_rxPtr->stats.rx_wc_ecn_bytes=0;
			pair_rxPtr->start_update_time=now;	
		}
			
		//Bandwidth guarantee traffic
		if((ip_header->tos>>2)==BANDWIDTH_GUARANTEE_DSCP)
		{
			printk(KERN_INFO "IN: bw guarantee pkt received");
			pair_rxPtr->stats.rx_bg_bytes+=skb->len;
			//ECN
			if((ip_header->tos<<6)==0xc0)
			{
				pair_rxPtr->stats.rx_bg_ecn_bytes+=skb->len;
				
			}
		}
		//Work conserving traffic
		else
		{
			printk(KERN_INFO "IN: WC pkt received");
			pair_rxPtr->stats.rx_wc_bytes+=skb->len;
			//ECN
			if((ip_header->tos<<6)==0xc0)
			{
				pair_rxPtr->stats.rx_wc_ecn_bytes+=skb->len;
				/*********************************/
				/*******START: CUSTOM ************/
				/*********************************/
				//Store the arrived time of WC traffic; will be used for checking packet trapping
				pair_rxPtr->stats.last_update_time=now;
				/*********************************/
				/*******END: CUSTOM **************/
				/*********************************/
			}
		}

		spin_unlock_bh(&(pair_rxPtr->pair_lock));
		//spin_unlock_irqrestore(&rxLock,flags);
		clear_ecn(skb);		
		
		if(feedback==1)
		{
			/*********************************/
			/*******START: CUSTOM ************/
			/*********************************/
			//New parameters state->net, state->sk sent as it requires these variable to dequeue packets in new linux kernel
			//FEEDBACK_PACKET_IPPROTO passed to generate feedback packet
			generate_packet(bit,state->net, state->sk, skb, FEEDBACK_PACKET_IPPROTO);
			/*********************************/
			/*******END: CUSTOM ************/
			/*********************************/
		}
			
		/*********************************/
		/*******START: CUSTOM ************/
		/*********************************/
		//Generate Packet Trapped Alert
		if(isPktTrapped==1)
			generate_packet(bit,state->net, state->sk, skb, TRAPPING_PACKET_IPPROTO);
		/*********************************/
		/*******END: CUSTOM **************/
		/*********************************/
		
	}
	return NF_ACCEPT;
}
static int __init trinity_init(void)
{
	
	int i,ret;

	//Get interface
    if(param_dev==NULL)
    {
        printk(KERN_INFO "Trinity: specify network interface (choose eth1 by default)\n");
	    param_dev = "eth1\0";
	}
	// trim
	for(i = 0; i < 32 && param_dev[i] != '\0'; i++)
	{
		if(param_dev[i] == '\n')
		{
			param_dev[i] = '\0';
			break;
		}
	}

	//Initialize RX context information
	
	rxPtr=kmalloc(sizeof(struct rx_context), GFP_KERNEL);
	if(rxPtr==NULL)
	{
		printk(KERN_INFO "Kmalloc error\n");
		return 0;
	}
	Init_rx_context(rxPtr);
	
	//Initialize tX context information
	txPtr=kmalloc(sizeof(struct tx_context), GFP_KERNEL); //bug corrected, eariler size of(rx_context) used
	if(txPtr==NULL)
	{
		printk(KERN_INFO "Kmalloc error\n");
		return 0;
	}
	dInit_tx_context(txPtr);
	//Initialize txLock
	//spin_lock_init(&txLock);

	//Initialize FlowTable
	Init_Table(&ft);


	nfho_incoming.hook = hook_func_in;
	//If we intercept incoming packets in PRE_ROUTING, generate_feedback will crash
	nfho_incoming.hooknum =  NF_INET_LOCAL_IN;
	nfho_incoming.pf = PF_INET;
	nfho_incoming.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_incoming);

	nfho_outgoing.hook = hook_func_out;
	nfho_outgoing.hooknum =  NF_INET_LOCAL_OUT;
	nfho_outgoing.pf = PF_INET;
	nfho_outgoing.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_outgoing);
	
	//Register device file
	ret = register_chrdev(MAJOR_NUM, DEVICE_NAME, &ops);
	if (ret < 0)
	{
		printk(KERN_ALERT "Register char device failed with %d\n", MAJOR_NUM);
		return ret;
	}
	printk(KERN_INFO "INIT: Register char device successfully with %d\n", MAJOR_NUM);
	printk(KERN_INFO "INIT: Start Trinity kernel module\n");
	
	/* initialize channel */
	/* code for converting IP from network byte order to text format 
	
	int ip;
	char *a;
	ip = in_aton("127.0.0.1");
	printk(KERN_INFO "network byte order: %d", ip);
		
	char local_ip[16]={0};           
	snprintf(local_ip, 16, "%pI4", &ip);
	printk(KERN_INFO "network ip: %s", local_ip); 
	
	*/
	/* Salis Joshi */			
	/*
	tx_endpointPtr=kmalloc(sizeof(struct endpoint_tx_context), GFP_KERNEL);
	
	//will be set only once
	//Init_endpoint_tx_context function will set the bandwidth capacity of the outgoing NIC
	//Insert_tx_endpoint function will maintain total no. of NIC's and its list. In our case it will be 1 as we have selected to have only 1 NIC for each VM
	if(tx_endpointPtr!=NULL)
	{
		Init_endpoint_tx_context(tx_endpointPtr,in_aton("192.168.0.22"),50, &tx_xmit_tasklet, &my_tx_hrtimer_callback, CONTROL_INTERVAL_DATA_SENT); //local ip = 16842879, total link capacity = 100 assumed
		Insert_tx_endpoint(tx_endpointPtr,txPtr);
		printk(KERN_INFO "INIT: count endpoints=%u", txPtr->endpoint_num);
		
	}
	else
	{
		printk(KERN_INFO "INIT: Kmalloc error when inserting a new endpoint TX context\n");
	}
	
	//will be set only once
	//Init_endpoint_rx_context function will set the bandwidth capacity of the incoming NIC
	//Insert_rx_endpoint function will maintain total no. of NIC's and its list. In our case it will be 1 as we have selected to have only 1 NIC for each VM
	rx_endpointPtr=kmalloc(sizeof(struct endpoint_rx_context), GFP_KERNEL);
	if(rx_endpointPtr!=NULL)
	{
		Init_endpoint_rx_context(rx_endpointPtr,in_aton("192.168.0.22"),50);
		Insert_rx_endpoint(rx_endpointPtr,rxPtr);
	}
	else
	{
		printk(KERN_INFO "INIT: Kmalloc error when inserting a new endpoint RX context\n");
	}
	
	
	tx_pairPtr=kmalloc(sizeof(struct pair_tx_context), GFP_KERNEL);	
	tx_pairPtr2=kmalloc(sizeof(struct pair_tx_context), GFP_KERNEL);	
	tx_pairPtr3=kmalloc(sizeof(struct pair_tx_context), GFP_KERNEL);	
	
	if(tx_pairPtr!=NULL)
	{
		
		//Init_pair_tx_context(tx_pairPtr,16842879,16777343,10, BUCKET_SIZE_BYTES, MAX_QUEUE_LEN,GFP_KERNEL);
		//Insert_tx_pair(tx_pairPtr,txPtr);
				
		//Init_pair_tx_context(tx_pairPtr2,16842879,16777345,5, BUCKET_SIZE_BYTES, MAX_QUEUE_LEN,GFP_KERNEL);
		/*
		Init_pair_tx_context(tx_pairPtr,in_aton("192.168.0.22"),in_aton("192.168.0.23"),10, BUCKET_SIZE_BYTES, MAX_QUEUE_LEN,&xmit_tasklet, &my_hrtimer_callback, TIMER_INTERVAL_US,GFP_KERNEL);
		Insert_tx_pair(tx_pairPtr,txPtr);
		calculate_wc_rate(txPtr, 1);
		printk(KERN_INFO "INIT: wc rate=%u", tx_pairPtr->rateLimiter.wc_rate);		
		//tx_pairPtr->txPtr = txPtr;
		
		Init_pair_tx_context(tx_pairPtr2,in_aton("192.168.0.22"),in_aton("192.168.0.24"),30, BUCKET_SIZE_BYTES, MAX_QUEUE_LEN,&xmit_tasklet, &my_hrtimer_callback, TIMER_INTERVAL_US,GFP_KERNEL);
		Insert_tx_pair(tx_pairPtr2,txPtr);	
		calculate_wc_rate(txPtr, 1);
		//tx_pairPtr2->txPtr = txPtr;
		/*
		Init_pair_tx_context(tx_pairPtr3,in_aton("127.0.0.1"),in_aton("127.0.0.1"),5, BUCKET_SIZE_BYTES, MAX_QUEUE_LEN,&xmit_tasklet, &my_hrtimer_callback, TIMER_INTERVAL_US,GFP_KERNEL);
		Insert_tx_pair(tx_pairPtr3,txPtr);	
		calculate_wc_rate(txPtr, 1);
		*/	
		//printk(KERN_INFO "INIT: pair num=%u", tx_endpointPtr->pair_num);
	/*
	}
	else
	{
		printk(KERN_INFO "INIT: Kmalloc error when inserting a new pair TX context\n");
	}
	/*
	rx_pairPtr=kmalloc(sizeof(struct pair_rx_context), GFP_KERNEL);
	if(rx_pairPtr!=NULL)
	{
		Init_pair_rx_context(rx_pairPtr,in_aton("192.168.0.22"),in_aton("192.168.0.23"),10);
		Insert_rx_pair(rx_pairPtr,rxPtr);
	}
	else
	{
		printk(KERN_INFO "INIT: Kmalloc error when inserting a new pair RX context\n");
	}
	
	rx_pairPtr2=kmalloc(sizeof(struct pair_rx_context), GFP_KERNEL);
	if(rx_pairPtr2!=NULL)
	{
		Init_pair_rx_context(rx_pairPtr2,in_aton("192.168.0.22"),in_aton("192.168.0.24"),30);
		Insert_rx_pair(rx_pairPtr2,rxPtr);
	}
	else
	{
		printk(KERN_INFO "INIT: Kmalloc error when inserting a new pair RX context\n");
	}
	*/	
	/* Salis Joshi */
	return SUCCESS;
		
}

static void __exit trinity_cleanup(void)
{
	//Unregister device
	unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
	
	//Unregister two hooks
	nf_unregister_hook(&nfho_outgoing);
	nf_unregister_hook(&nfho_incoming);

	//Clear table
	Empty_Table(&ft);

	if(rxPtr!=NULL)
	{
		Empty_rx_context(rxPtr);
		kfree(rxPtr);
	}
		

	if(txPtr!=NULL)
	{
		Empty_tx_context(txPtr);
		kfree(txPtr);		
	}

	printk(KERN_INFO "Stop Trinity kernel module\n");
}


module_init(trinity_init);
module_exit(trinity_cleanup);
