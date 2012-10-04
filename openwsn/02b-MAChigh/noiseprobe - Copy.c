#include "openwsn.h"
#include "radio.h"
#include "spi.h"
#include "neighbors.h"
#include "noiseprobe.h"
#include "IEEE802154E.h"
#include "idmanager.h"
#include "res.h"
#include "at86rf231.h"
#include "openrandom.h"
#include "kalman.h"
#include "ses.h"

#include <stdlib.h> //for random
#include "openserial.h" //debug
//=========================== defines =========================================
const uint16_t BLPERIOD  =  64; //30 sec (512/8) integral number of sweep
const int BLTHRESHOLD = -88; 
const int NUL = -123; 
//=========================== variables =======================================
typedef struct {
   uint8_t         current;   //channel to sense
   uint8_t         bl_size;   //blacklist size (non-zero to indicate size update)
   uint16_t         reads;     //number of collected sample
   uint16_t        runs;      //how many times this module is called
   uint16_t        masked;    //blacklisting result to be reported
   uint8_t         rank[16];  //ranking based on noise floors
   /*for integer KF
   uint32_t        total;     //sum of samples
   uint8_t         rssi[16];  //record of noise floors of all channels*/
   /*for float KF version*/
   float total;              
   float rssi[16];
   uint16_t        updatePeriod;
} nf_vars_t;

nf_vars_t nf_vars;

float st1[16]={0};
//=========================== prototypes ======================================

//=========================== public ==========================================
void nf_init() { 
    radio_setEDCb(nf_endOfED);
    memset(&nf_vars,0,sizeof(nf_vars_t));
    nf_vars.updatePeriod = 64 * (6 + (rand()%3)*2); // 384 + (0/64/128)*2
}

inline void startProbeSlot(uint8_t channel, uint8_t size){
    nf_vars.runs++;
    nf_vars.reads = 0;
    nf_vars.total = 0;
    nf_vars.current = channel-11;
    nf_vars.bl_size = size;
    
    readEd(); //start 1st Reg reading of this NF slot
}

inline void readEd(){
    //piggy23:  initiate ED measurement
    radio_spiWriteReg(RG_PHY_ED_LEVEL,0xbb);
}

//called by radio.c
inline void nf_endOfED(PORT_TIMER_WIDTH capturedTime){
    nf_vars.total += radio_spiReadReg(RG_PHY_ED_LEVEL);
    nf_vars.reads++;
    if(nf_vars.reads==(uint8_t)(1<<LOG2SAMPLES))
    {
      radio_rfOff(); //shut the RF as soon as we probed NF
      record();
      /* MAXACTIVESLOTS*16/2 slots per full sweep  (64 runs currently) */
      if(nf_vars.runs%256==0) //mask updated per 128 superframes, for debugging
      //if(nf_vars.runs==512) //per 256 superframes, approx. 30 secs
      //if(nf_vars.runs == nf_vars.updatePeriod)
      {
        nf_vars.updatePeriod = 64 * (6 + (rand()%3)*2);
        reset_vars();
        sort(nf_vars.rssi); //piggy28 (enabled for fix-sized blacklist)
        //electFixed();
        electThreshold();
        //notifyOther();
        //sift(); //debug
      }
      notifyMe(); // this end every NF slot
      //notifyOther(); //debug only - fixed now; however question remains: why it has to be 6 instead of 9?
    }
    else
    {
      readEd();
    }
}

//build the record of historical RSSI
inline void record(){ 
  //piggy31: now an updated version utilising Kalman filter, as opposed to the older one commented below
  //rssi[current] = (uint8_t)(kalman(total,(rssi[current]<<LOG2SAMPLES))>>LOG2SAMPLES);
  /*int version
  nf_vars.rssi[nf_vars.current] = (uint8_t)(kalman(nf_vars.total,(nf_vars.rssi[nf_vars.current]<<LOG2SAMPLES),nf_vars.current)>>LOG2SAMPLES); */
  
  if(nf_vars.rssi[nf_vars.current]==NUL){ //set initial value
      nf_vars.rssi[nf_vars.current] = (nf_vars.total/(1<<LOG2SAMPLES))+ED_OFFSET;
      st1[nf_vars.current] = nf_vars.rssi[nf_vars.current];
  }
  else{  
    /* kalman filter */ /*float version*/
    //nf_vars.rssi[nf_vars.current] = kalman((nf_vars.total/(1<<LOG2SAMPLES))+ED_OFFSET,nf_vars.rssi[nf_vars.current],nf_vars.current); 
    
    /* Simple Exponential Smoothin */
    nf_vars.rssi[nf_vars.current] = brown_ses(0.5,(nf_vars.total/(1<<LOG2SAMPLES))+ED_OFFSET, nf_vars.rssi[nf_vars.current], nf_vars.current);
  }
}

//basic bubble sort
inline void sort(){ 
//inline void sort(float sortee[]){ 
//inline void sort(uint8_t sortee[]){ 
    float sortee[16];
    memcpy(sortee,nf_vars.rssi,sizeof(sortee));
    for(int8_t i=1; i< 16; i++)
    {
      for(int8_t j=0; j<16-i; j++)
      {
          if(sortee[j]<sortee[j+1])
          {
            float temp1 = sortee[j+1];
            //int8_t temp1 = sortee[j+1];
            
            sortee[j+1] = sortee[j];
            sortee[j] = temp1;
            int8_t temp2 = nf_vars.rank[j+1];
            nf_vars.rank[j+1]=nf_vars.rank[j]; 
            nf_vars.rank[j] = temp2;
          }
      }
    }
}   

void electFixed(){ 
  nf_vars.masked=0;
  /* fix-sized */
  for(int8_t i=0; i<nf_vars.bl_size; i++){
      nf_vars.masked+=1<<nf_vars.rank[i];
  }
}

void electThreshold(){ 
  nf_vars.masked=0;
  /* threshold-based */
  for(int8_t i=0; i<16; i++){
      if(nf_vars.rssi[i]>BLTHRESHOLD){
        nf_vars.masked+=1<<i;
      }
  }
}


/*piggy15: tell myself */
inline void notifyMe(){ //need to be called every NF slot for timing
  // root: simply report mask to be inserted in Adv
  // motes: generate RES packets to be pushed into queue
  
  //if(idmanager_getIsDAGroot()) //(comment to enable blacklisting in senders)
  { 
      activity_np3(nf_vars.masked);
      //activity_np3(~((uint16_t)(nf_vars.rssi[nf_vars.current]))); //debug
  }
}

/*piggy16: tell others*/
inline void notifyOther(){
  //piggy29 (push ADV carrying new t_mask) - temp: if DAGroot, will be solved once BL-election period becomes random
  //if(idmanager_getIsDAGroot()) sendAdv(); 
  //piggy16b (comment to use uni-directional parent-only blacklisting)
  //if(!idmanager_getIsDAGroot()) sendRpt(~(nf_vars.masked)); 
  return; //temp
}

void reset_vars(){
  nf_vars.runs=0;
  for(int8_t i=0; i<16; i++)
    nf_vars.rank[i]=i;
}
void reset_record(){
  for(int8_t i=0; i<16; i++){
    st1[i]=NUL;
    nf_vars.rssi[i]=NUL;
  }
}

//debug only - show those whose rssi is above -91dBm
inline void sift(){
  nf_vars.masked=0;
  for(int8_t i=0; i<16; i++){
    if(nf_vars.rssi[i]>0) nf_vars.masked+=(1<<i);
  }
  //it will become the negated value!
  
  //nf_vars.masked=nf_vars.rssi[4]; //debug
  //if(!idmanager_getIsDAGroot()) sendRpt(nf_vars.masked);
}