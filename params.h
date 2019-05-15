#ifndef PARAMS_H
#define PARAMS_H

//Rate control interval 
unsigned int CONTROL_INTERVAL_US=5*1000;				//In micro seconds

/*********************************/
/*******START: CUSTOM ************/
/*********************************/
unsigned long CONTROL_INTERVAL_PKT_TRAPPING=20*1000000;	//Parameter for interval for checking Packet Trapping in network (in nano seconds)
unsigned long CONTROL_INTERVAL_DATA_SENT=20;			//Parameter for interval for checking idle containers (in seconds)
/*********************************/
/*******END: CUSTOM **************/
/*********************************/

/* The following four parameters are used to generate feedback packet */
const u16 FEEDBACK_HEADER_SIZE=20;
const u8 FEEDBACK_PACKET_TTL=64;
const u8 FEEDBACK_PACKET_TOS=0xa; 				//(DSCP=2 TOS=4*2+2=10=0Xa)
int FEEDBACK_PACKET_IPPROTO=143; 				//should be some unused protocol

/*********************************/
/*******START: CUSTOM ************/
/*********************************/
int TRAPPING_PACKET_IPPROTO=144; 				// Protocol number of a packet indicating possible packet trapping; Should be some unused protocol			
const int MIN_WC_RATE=2*1024;					//When packet trapping is confirmed, set WC Rate to this value (In Bytes)			
/*********************************/
/*******END: CUSTOM **************/
/*********************************/


/* The following parameters are used for rate limters */
const unsigned int MAX_QUEUE_LEN=256;
/*********************************/
/*******START: CUSTOM ************/
/*********************************/
const unsigned int TIMER_INTERVAL_US=100000; 		//Token generating and packet dequeuing interval; This is always calculated in "xmit_tasklet" function in "rl.h" header file, so just changing the final value here directly (no difference from original code)
/*********************************/
/*******END: CUSTOM **************/
/*********************************/
const unsigned int BUCKET_SIZE_BYTES=32*1024;
const u8 BANDWIDTH_GUARANTEE_DSCP=0x1;
const u8 WORK_CONSERVING_DSCP=0x0;

/* The following parameters are used for rate control */
const unsigned int LINK_CAPACITY=960; 				//Mbps
const unsigned int ELASTICSWITCH_ALPHA=100;			//ALPHA/1000 is the actual factor
const unsigned int TRINITY_ALPHA=500;
const unsigned int MINIMUM_RATE_INCREASE=10;
//const unsigned int MINIMUM_RATE=10;

/* The following parameters are used for maintaing flow states */
const unsigned int MAX_BYTES_SENT=4294900000;
const unsigned int FLOW_THRESH=100*1024;
 
#endif
