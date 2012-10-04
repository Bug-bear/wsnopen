#include "openwsn.h"
#include "hdl.h"
#include "opencoap.h"
#include "opentimers.h"
#include "openqueue.h"
#include "packetfunctions.h"
#include "openserial.h"
#include "openrandom.h"
#include "scheduler.h"
#include "ADC_Channel.h"

#include "IEEE802154E.h"
#include "idmanager.h"
#include "openudp.h"
//=========================== defines =========================================

/// inter-packet period (in ms)
#define BBKPERIOD    1000
#define SAMPLE  300

//=========================== variables =======================================

typedef struct {
   coap_resource_desc_t desc;
   opentimer_id_t  timerId;
   uint32_t  sequence;
   uint32_t  rate;
} bbk_vars_t;


//=========================== prototypes ======================================



//=========================== public ==========================================

void hdl_init(){
}

//=========================== private =========================================

error_t hdl_receive(OpenQueueEntry_t* msg) {
   return E_FAIL;
}

error_t hdl_respond(){
    response_t* pkt;
    construct_response(pkt);
    
    return E_FAIL;
}

void hdl_sendDone(OpenQueueEntry_t* msg, error_t error) {
   openqueue_freePacketBuffer(msg);
}

void construct_response(response_t* data) {
}