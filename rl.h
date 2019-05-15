#ifndef RL_H
#define RL_H

#include "params.h"
#include "tx.h"
#include "rc.h"
//void update_token_buckets(void);

/*********************************/
/*******START: CUSTOM ************/
/*********************************/	
//Removed references that handled latency
static void xmit_tasklet(unsigned long data)
{
	
	struct pair_tx_context *pair_txPtr=(struct pair_tx_context*)data;
	unsigned int skb_len;
		
	ktime_t now=ktime_get();	
	
	/*********************************/
	/*******START: CUSTOM ************/
	/*********************************/	
	//Modified code to generate BG and WC tokens		
	//Original code could generate token buckets and dequeue the packets at the higher rate than allocated BG and WC rates	
	if((pair_txPtr->rateLimiter.bg_tokens+(ktime_us_delta(now,pair_txPtr->rateLimiter.last_update_time)*(pair_txPtr->rateLimiter.bg_rate)/1000000))>pair_txPtr->rateLimiter.bg_bucket)
		pair_txPtr->rateLimiter.bg_tokens = pair_txPtr->rateLimiter.bg_bucket;
	else
		pair_txPtr->rateLimiter.bg_tokens+=ktime_us_delta(now,pair_txPtr->rateLimiter.last_update_time)*(pair_txPtr->rateLimiter.bg_rate)/1000000;	
	
	if((pair_txPtr->rateLimiter.wc_tokens+ktime_us_delta(now,pair_txPtr->rateLimiter.last_update_time)*(pair_txPtr->rateLimiter.wc_rate)/1000000) > pair_txPtr->rateLimiter.wc_bucket)
		pair_txPtr->rateLimiter.wc_tokens = pair_txPtr->rateLimiter.wc_bucket;
	else
		pair_txPtr->rateLimiter.wc_tokens+=ktime_us_delta(now,pair_txPtr->rateLimiter.last_update_time)*(pair_txPtr->rateLimiter.wc_rate)/1000000;
	
	/*********************************/
	/*******END: CUSTOM **************/
	/*********************************/		
	pair_txPtr->rateLimiter.last_update_time=now;
	
	//Dequeue packets of using both bandwidth and work conserving traffic
	while(1)
	{		
		if(pair_txPtr->rateLimiter.packet_len>0)//if packets are queued
		{			
			skb_len=pair_txPtr->rateLimiter.packet[pair_txPtr->rateLimiter.packet_head].skb->len;
			
			if(skb_len<=pair_txPtr->rateLimiter.bg_tokens)
			{
				pair_txPtr->rateLimiter.bg_tokens-=skb_len;
				spin_lock_bh(&(pair_txPtr->rateLimiter.packet_lock));
				Dequeue_dual_tbf(&(pair_txPtr->rateLimiter),1);
				pair_txPtr->stats.last_data_sent_time = now;
				spin_unlock_bh(&(pair_txPtr->rateLimiter.packet_lock));				
			}
			else if(skb_len<=pair_txPtr->rateLimiter.wc_tokens)
			{
				pair_txPtr->rateLimiter.wc_tokens-=skb_len;
				spin_lock_bh(&(pair_txPtr->rateLimiter.packet_lock));
				Dequeue_dual_tbf(&(pair_txPtr->rateLimiter),0);
				/*********************************/
				/*******START: CUSTOM ************/
				/*********************************/		
				//Code added to track packet trapping		
				if(ktime_us_delta(now,pair_txPtr->stats.last_update_time) <= CONTROL_INTERVAL_PKT_TRAPPING)
					pair_txPtr->stats.tx_wc_ecn_bytes_trap+=skb_len;
				else
				{
					pair_txPtr->stats.tx_wc_ecn_bytes_trap=0;
					pair_txPtr->stats.last_update_time=ktime_get();
				}			
				/*********************************/
				/*******END: CUSTOM **************/
				/*********************************/				
				spin_unlock_bh(&(pair_txPtr->rateLimiter.packet_lock));						
			}
			else
			{
				break;
			}
		}
		else
		{
			break;
		}
	}
		
	//Start time again, pair_txPtr-> timer_interval = 100
	hrtimer_start(&(pair_txPtr->timer), ktime_set(0, pair_txPtr-> timer_interval), HRTIMER_MODE_REL);
}
/*********************************/
/*******END: CUSTOM **************/
/*********************************/

/** Function will be executed periodically to check unutilized bandwidth
 * @data is the tx_endpointPtr type
 */ 		
static void tx_xmit_tasklet(unsigned long data)
{
	struct endpoint_tx_context *tx_endpointPtr=(struct endpoint_tx_context*)data;
	struct pair_tx_context* pair_txPtr=NULL;
	unsigned int total_link_bw = 0, allocated_bw = 0, spare_bw = 0,	change_wc_rates = 0;
	
	total_link_bw = tx_endpointPtr->guarantee_bw;
	
	ktime_t now = ktime_get();
	list_for_each_entry(pair_txPtr,&(tx_endpointPtr->pair_list),list)
	{
		if(ktime_us_delta(now,pair_txPtr->stats.last_data_sent_time)<=CONTROL_INTERVAL_DATA_SENT*1000000)
			allocated_bw += pair_txPtr->guarantee_bw;
		else
			change_wc_rates =  1;		
	}
	spare_bw = total_link_bw - allocated_bw;
		
	if(change_wc_rates == 1)
	{
		list_for_each_entry(pair_txPtr,&(tx_endpointPtr->pair_list),list)
		{
			if(ktime_us_delta(now,pair_txPtr->stats.last_data_sent_time)<=CONTROL_INTERVAL_DATA_SENT*1000000)
			{
				pair_txPtr->rateLimiter.wc_rate=MIN_WC_RATE;
				pair_txPtr->rateLimiter.wc_bucket=MIN_WC_RATE;
				pair_txPtr->rateLimiter.congested=1;
			}
			else
			{	
				pair_txPtr->rateLimiter.wc_rate = min(spare_bw*pair_txPtr->rateLimiter.bg_rate/allocated_bw,(1+TRINITY_ALPHA/1000)*pair_txPtr->rateLimiter.wc_rate);
				pair_txPtr->rateLimiter.wc_bucket = min(spare_bw*pair_txPtr->rateLimiter.bg_rate/allocated_bw,(1+TRINITY_ALPHA/1000)*pair_txPtr->rateLimiter.wc_rate);
			}
		}
	}	
	//Start time again, 
	hrtimer_start(&(tx_endpointPtr->timer), ktime_set(tx_endpointPtr-> timer_interval, 0), HRTIMER_MODE_REL);
}


/* HARDIRQ timeout */
static enum hrtimer_restart my_hrtimer_callback(struct hrtimer *timer )
{
	/* schedue xmit tasklet to go into softirq context */
	struct pair_tx_context  *pair_txPtr= container_of(timer, struct pair_tx_context, timer);
	tasklet_schedule(&(pair_txPtr->xmit_timeout));
	return HRTIMER_NORESTART;
}

/** Function to restart the timer that schedules tx_xmit_timeout to execute at a periodic interval**/
 
static enum hrtimer_restart my_tx_hrtimer_callback(struct hrtimer *timer )
{
	
	struct endpoint_tx_context *tx_endpointPtr= container_of(timer, struct endpoint_tx_context, timer);
	tasklet_schedule(&(tx_endpointPtr->tx_xmit_timeout));
	return HRTIMER_NORESTART;
}

#endif
