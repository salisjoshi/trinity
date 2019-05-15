#ifndef RC_H
#define RC_H

#include "params.h"

unsigned int cubic_rc(unsigned int current_rate, unsigned int target_rate, unsigned int alpha)
{
	unsigned int increase=0;
	if(unlikely(target_rate<=current_rate))
		return current_rate;
	
	increase=max((target_rate-current_rate)*alpha/1000,MINIMUM_RATE_INCREASE);
	return current_rate+increase;
}

/**
 * Function to calculate new WC rate
 * @txPtr contains link list of allocated containers
 * @is_initial is a flag to check whether the b/w enforcement is being intialized or periodically called
*/
void calculate_wc_rate(struct tx_context* txPtr, bool is_initial)
{
	if(likely(txPtr!=NULL))
	{
		unsigned int total_link_bw = 0, allocated_bw = 0, spare_bw = 0;	
		
		struct pair_tx_context* pair_txPtr=NULL;
		struct endpoint_tx_context* endpoint_ptr=NULL; 

		list_for_each_entry(endpoint_ptr,&(txPtr->endpoint_list),list)
		{
			total_link_bw = endpoint_ptr->guarantee_bw;
					
			list_for_each_entry(pair_txPtr,&(endpoint_ptr->pair_list),list)
			{
				allocated_bw += pair_txPtr->guarantee_bw;
			}
			
			spare_bw = total_link_bw - allocated_bw;
									
			list_for_each_entry(pair_txPtr,&(endpoint_ptr->pair_list),list)
			{
				if(is_initial == 1)
				{
					pair_txPtr->rateLimiter.wc_rate = spare_bw*pair_txPtr->rateLimiter.bg_rate/allocated_bw;		
					pair_txPtr->rateLimiter.wc_bucket = spare_bw*pair_txPtr->rateLimiter.bg_rate/allocated_bw;
				}
				else
				{	
					pair_txPtr->rateLimiter.wc_rate = min(spare_bw*pair_txPtr->rateLimiter.bg_rate/allocated_bw,(1+TRINITY_ALPHA/1000)*pair_txPtr->rateLimiter.wc_rate);
					pair_txPtr->rateLimiter.wc_bucket = min(spare_bw*pair_txPtr->rateLimiter.bg_rate/allocated_bw,(1+TRINITY_ALPHA/1000)*pair_txPtr->rateLimiter.wc_rate);
				}
			}
			
		}
		
	}
	
}

#endif
