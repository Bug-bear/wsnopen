#ifndef __NOISEPROBE_H
#define __NOISEPROBE_H

/**
\addtogroup MAClow
\{
\addtogroup IEEE802154E
\{
*/

#include "openwsn.h"

//=========================== define ==========================================
enum {
  MASK_SIZE = 6,
  LOG2SAMPLES = 5, //this is the best a slot can cope
  ED_OFFSET = -91,
  SCALAR = 100
};

// Do this for once only to help future mask-related operations
static const uint16_t maskBits[] 
  = { (uint16_t)1<<0, (uint16_t)1<<1, (uint16_t)1<<2, (uint16_t)1<<3, 
      (uint16_t)1<<4, (uint16_t)1<<5, (uint16_t)1<<6, (uint16_t)1<<7, 
      (uint16_t)1<<8, (uint16_t)1<<9, (uint16_t)1<<10, (uint16_t)1<<11, 
      (uint16_t)1<<12, (uint16_t)1<<13, (uint16_t)1<<14, (uint16_t)1<<15 };

//=========================== typedef =========================================

//IEEE802.15.4E acknowledgement (ACK)
/*
typedef struct {
   uint8_t channel;
   uint8_t size;
} NF_CMD;
*/

//=========================== variables =======================================

//=========================== prototypes ======================================
// admin
void nf_init();
void startProbeSlot(uint8_t channel, uint8_t size);
void readEd();
void nf_endOfED(PORT_TIMER_WIDTH capturedTime);      //collect samples
void record();  
void sift(); //debug - show those whose rssi is above -91dBm

void sort();
//void sort(float[]); //float version
//void sort(uint8_t[]); //int version

void electFixed();  
void electThreshold();  

void notifyMe();
void notifyOther();
void reset_vars();
void reset_record();

uint8_t get_temp(); // debug only
#endif