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
#include "hdl.h"
//=========================== defines =========================================

/// inter-packet period (in ms)
#define BBKPERIOD    1000
#define SAMPLE  300

//=========================== variables =======================================

//=========================== prototypes ======================================

//=========================== public ==========================================

//=========================== private =========================================

int8_t HDLCreate(HDLContext* ctx, const char *handle, unsigned int handleLen,
              HDLValue *values[], int numValues)
{
  HDLMessage* msg = NULL;
  HDLMessage* resp = NULL;
  int datasize, valsize, offset;
  int ret = HDL_ERROR;

  if (!ctx) return HDL_EMPTY_RESOLVER_CONTEXT;
  if (!handle) return HDL_EMPTY_HANDLE_INPUT;

  msg = HDLInitMessage(HDL_OC_CREATE_HANDLE, HDL_RC_RESERVED, ctx->msgFlags);
  if(msg==NULL) return HDL_OUT_OF_MEMORY;
  
  datasize = handleLen + HDL_INT4_SIZE; // adjust size for handle
  // adjust size for values
  valsize = calcValueListStorageBytes(values, numValues);
  datasize += valsize;

  msg->messageBody = MALLOC(datasize);
  msg->authoritative = HDL_TRUE;

  /* write the handle */
  HDLEncodeByteArray((char*)msg->messageBody, handle, handleLen, 0, datasize);
  offset = (HDL_INT4_SIZE + handleLen);

  /* write the values */
  HDLEncodeValueList((char*)msg->messageBody, offset, datasize, numValues, values);
  offset += valsize;

  msg->messageBodyLen = datasize;
  msg->messageLength = HDL_MESSAGE_HEADER_SIZE + datasize + HDL_INT4_SIZE;

  ret = HDLProcessRequest(ctx, handle, handleLen, msg, &resp);
  
  HDLDestroyMessage(&msg);
  if (resp){ 
    ret = resp->responseCode;
    HDLDestroyMessage(&resp);
  }
  return ret;
}

int HDLDelete(HDLContext* ctx, const char *handle, unsigned int handleLen){
  HDLMessage* msg = NULL;
  HDLMessage* resp = NULL;
  int datasize;
  int ret = HDL_ERROR;

  if (!ctx) return HDL_EMPTY_RESOLVER_CONTEXT;
  if (!handle) return HDL_EMPTY_HANDLE_INPUT;

  msg = HDLInitMessage(HDL_OC_DELETE_HANDLE, HDL_RC_RESERVED, ctx->msgFlags);
  if(msg==NULL) return HDL_OUT_OF_MEMORY;
  
  datasize = handleLen + HDL_INT4_SIZE; // adjust size for handle

  msg->messageBody = MALLOC(datasize);
  msg->authoritative = HDL_TRUE;

  /* write the handle */
  HDLEncodeByteArray((char*)msg->messageBody, handle, handleLen, 0, datasize);

  msg->messageBodyLen = datasize;
  msg->messageLength = HDL_MESSAGE_HEADER_SIZE + datasize + HDL_INT4_SIZE;
  ret = HDLProcessRequest(ctx, handle, handleLen, msg, &resp);  
  
  HDLDestroyMessage(&msg);
  if (resp != NULL) HDLDestroyMessage(&resp);
  return ret;
}

int HDLAddValues(HDLContext* ctx, const char *handle, unsigned int handleLen,
                 HDLValue *values[], int numValues){

  HDLMessage* msg = NULL;
  HDLMessage* resp = NULL;
  int datasize, valsize, offset;
  int ret = HDL_ERROR;

  if (!ctx) return HDL_EMPTY_RESOLVER_CONTEXT;
  if (!handle) return HDL_EMPTY_HANDLE_INPUT;

  msg = HDLInitMessage(HDL_OC_ADD_VALUE, HDL_RC_RESERVED, ctx->msgFlags);
  if(msg==NULL) return HDL_OUT_OF_MEMORY;
  
  datasize = handleLen + HDL_INT4_SIZE; // adjust size for handle

  /* adjust size for values */
  valsize = calcValueListStorageBytes(values, numValues);
  datasize += valsize;

  msg->messageBody = MALLOC(datasize);
  msg->authoritative = HDL_TRUE;

  /* write the handle */
  HDLEncodeByteArray((char*)msg->messageBody, handle, handleLen, 0, datasize);
  offset = (HDL_INT4_SIZE + handleLen);

  /* write the values */
  HDLEncodeValueList((char*)msg->messageBody, offset, datasize, numValues, values);

  msg->messageBodyLen = datasize;
  msg->messageLength = HDL_MESSAGE_HEADER_SIZE + datasize + HDL_INT4_SIZE; 
  /* the last 4 bytes is for signature */

  ret = HDLProcessRequest(ctx, handle, handleLen, msg, &resp);  
  
  HDLDestroyMessage(&msg);
  if (resp){ 
    ret = resp->responseCode;
    HDLDestroyMessage(&resp);
  }
  return ret;
}
                
int HDLRemoveValues(HDLContext* ctx, const char *handle, 
                    unsigned int handleLen, int indices[], int numValues){
  HDLMessage* msg = NULL;
  HDLMessage* resp = NULL;
  int datasize, offset, i;
  int ret = HDL_ERROR;

  if (!ctx) return HDL_EMPTY_RESOLVER_CONTEXT;
  if (!handle) return HDL_EMPTY_HANDLE_INPUT;

  msg = HDLInitMessage(HDL_OC_REMOVE_VALUE, HDL_RC_RESERVED, ctx->msgFlags);
  if(msg==NULL) return HDL_OUT_OF_MEMORY;
  
  datasize = handleLen + HDL_INT4_SIZE; // adjust size for handle
  datasize += HDL_INT4_SIZE+HDL_INT4_SIZE*numValues;  // adjust size for values

  msg->messageBody = MALLOC(datasize);
  msg->authoritative = HDL_TRUE;

  /* write the handle */
  HDLEncodeByteArray((char*)msg->messageBody, handle, handleLen, 0, datasize);
  offset = (HDL_INT4_SIZE + handleLen);

  /* write the indices */
  HDLEncodeInt4((char*)msg->messageBody, numValues, offset, datasize);
  offset += HDL_INT4_SIZE;
  for (i=0; i<numValues; i++){
    HDLEncodeInt4((char*)msg->messageBody, indices[i], offset, datasize);
    offset += HDL_INT4_SIZE;
  }
 
  msg->messageBodyLen = datasize;
  msg->messageLength = HDL_MESSAGE_HEADER_SIZE + datasize + HDL_INT4_SIZE; 
  /* the last 4 bytes is for signature */

  ret = HDLProcessRequest(ctx, handle, handleLen, msg, &resp);  
  
  HDLDestroyMessage(&msg);
  if (resp){ 
    ret = resp->responseCode;
    HDLDestroyMessage(&resp);
  }
  return ret;

}

int HDLModifyValues(HDLContext *ctx, const char *handle, unsigned int handleLen, 
		    HDLValue *values[], int numValues
                   )
{
  HDLMessage* msg = NULL;
  HDLMessage* resp = NULL;
  int datasize, offset, valsize;
  int ret = HDL_OK;

  if (!ctx)
     return HDL_EMPTY_RESOLVER_CONTEXT;

  if (!handle)
     return HDL_EMPTY_HANDLE_INPUT;

  if (!((msg = HDLInitMessage(HDL_OC_MODIFY_VALUE, HDL_RC_RESERVED, ctx->msgFlags))))
     return HDL_OUT_OF_MEMORY;
  
  datasize = handleLen + HDL_INT4_SIZE; // adjust size for handle 

  // adjust size for values 
  valsize = calcValueListStorageBytes(values, numValues);
  datasize += valsize;

  msg->messageBody = MALLOC(datasize);
  msg->authoritative = HDL_TRUE;
  msg->certify = HDL_TRUE;

  /* write the handle */
  HDLEncodeByteArray((char*)msg->messageBody, handle, handleLen, 0, datasize);
  offset = (HDL_INT4_SIZE + handleLen);

  /* write the values */
  HDLEncodeValueList((char*)msg->messageBody, offset, datasize, numValues, values);

  msg->messageBodyLen = datasize;
  msg->messageLength = HDL_MESSAGE_HEADER_SIZE + datasize + HDL_INT4_SIZE; 
  /*the last is for signature */

  ret = HDLProcessRequest(ctx, handle, handleLen, msg, &resp);  

  
  HDLDestroyMessage(&msg);
  if (resp){ 
    ret = resp->responseCode;
    HDLDestroyMessage(&resp);
  }
  return ret;
}

/** Retrieve the site info by giving the primary server address, port number, and
 protocol string.
 Input: ctx, a valid handle context, containing the root info;
        primServerIp, the ip address string of the primary server;
		ipLen, the length of the ip address;
		port, the integer to specify the port number of handle server service;
		protocol, the null -terminated string to specify the protocol used to get site info;
 Output: siteInfo, the site information for which your primary server belong to.
 Returns: HDL_OK, success;
          other: errors.
*/


int HDLGetSiteInfo(HDLContext *ctx, const char *primServerIp, int port, 
		   const char* protocolStr, HDLSite** siteInfo
                  )
{
  HDLMessage *msg = NULL,
             *resp = NULL;

  int datasize,
      ret = HDL_OK,
      savedCheckSignatures,
      addrLen;

  char *addr,
        protocol[10] = "tcp";

  HDLSite *site = NULL;



  if (!ctx) return HDL_EMPTY_RESOLVER_CONTEXT;
  if (!primServerIp) return HDL_NULL_INPUT;

  savedCheckSignatures = ctx->checkSignatures;
  ctx->checkSignatures = HDL_FALSE;

  /* init the output */
  *siteInfo = NULL;

  msg = HDLInitMessage(HDL_OC_GET_SITE_INFO, HDL_RC_RESERVED, ctx->msgFlags);
  if(msg==NULL) return HDL_OUT_OF_MEMORY;

  datasize = strlen(HDL_BLANK_HANDLE) + HDL_INT4_SIZE; // adjust size for handle

  msg->messageBody = MALLOC(datasize);

  /* write the handle */
  HDLEncodeByteArray((char*)msg->messageBody, HDL_BLANK_HANDLE, strlen(HDL_BLANK_HANDLE), 0, datasize);
  msg->messageBodyLen = datasize;
  msg->messageLength = HDL_MESSAGE_HEADER_SIZE + datasize + HDL_INT4_SIZE; 
  /*the signature slot */

  if (protocolStr) {
	strncpy(protocol, protocolStr, sizeof(protocol)-1);
  }

  if (port <= 0)
     port=2641;

  if(HDLGetIpByHost((char*)primServerIp, &addr, &addrLen)!=HDL_OK) {
    fprintf(stderr, "Error: unable to resolve host %s\n", primServerIp);
    return HDL_UNABLE_TO_RESOLVE_HOST;
  }

  /* there is no way to check signature, because we don't have server 
     pubkey now */
	
  if(strcasecmp(protocol, "tcp")==0) {
    HDL_DEBUG("Sending tcp get site info message...");
    if(HDLSendHdlTcpMessage(ctx, msg, addr, addrLen, port, &resp)!=HDL_OK) {
      HDL_DEBUG("Error: couldn't send message\n");
      ret = HDL_UNABLE_TO_SEND_TCP_MSG;
    }

  } else if(strncasecmp(protocolStr, "http", 4)==0) {
	HDL_DEBUG("Sending http get site info message...");
    if(HDLSendHdlHttpMessage(ctx, msg, addr, addrLen, port, &resp)!=HDL_OK) {
      HDL_DEBUG("Error: couldn't send http message\n");
      ret = HDL_UNABLE_TO_SEND_HTTP_MSG;
    }

  } else if(strncasecmp(protocolStr,"udp", 3)==0) {
	HDL_DEBUG("Sending udp get site info message...");
    if(HDLSendHdlUdpMessage(ctx, msg, addr, addrLen, port, &resp)!=HDL_OK) {
      HDL_DEBUG("Error: couldn't send message\n");
      ret = HDL_UNABLE_TO_SEND_UDP_MSG;
    }
 
  } else {
    HDL_DEBUG("Error: unknown protocol: %s\n", protocolStr);
	ret = HDL_UNKNOWN_PROTOCOL;
  }

  if (resp) {
    if ((site = HDLDecodeSite((char*)resp->messageBody, 0, resp->messageBodyLen)))
       *siteInfo = site;

    HDLDestroyMessage(&resp);
  } 

  ctx->checkSignatures = savedCheckSignatures;
  return ret;
}

/*----------------------------------------------------------------------------*/

static int HDLHomeOrUnhomeNA_Site(HDLContext *ctx,
                                  const char *naHandle,
                                  unsigned int handleLen,
                                  HDLSite* siteInfo,
		                  unsigned int OpCode /* HDL_OC_HOME_NA      */
						      /* or HDL_OC_UNHOME_NA */
                                 )
{
 HDLMessage *msg = NULL,
            *resp = NULL;

        int  datasize = handleLen + HDL_INT4_SIZE, /* adjust size for handle */
             ret = HDL_ERROR;

  HDLServer *server = NULL;

   unsigned  int i = 0;


  if (!ctx)
     return HDL_EMPTY_RESOLVER_CONTEXT;

  if (!naHandle)
     return HDL_EMPTY_HANDLE_INPUT;

  if (!siteInfo)
     return HDL_NULL_INPUT;

  if (!(   ((msg = HDLInitMessage(OpCode, HDL_RC_RESERVED, ctx->msgFlags)))
        && ((msg->messageBody = MALLOC(datasize)))
       )
     )
     return HDL_OUT_OF_MEMORY;
                                                          /* write the handle */

  HDLEncodeByteArray((char*)msg->messageBody, naHandle, handleLen, 0, datasize);
  msg->messageBodyLen = datasize;
  msg->messageLength = HDL_MESSAGE_HEADER_SIZE + datasize + HDL_INT4_SIZE;

  msg->certify = HDL_TRUE;

        /* The regular processRequest will send to one server by hash option. */
        /* For homing/unhoming, send requests to each server in site.         */

  for (i = 0; i < siteInfo->numServers; i++)
      {
       if ((server = (HDLServer*)siteInfo->servers[i]))
          {
           ret = HDLSendMessageToServer(ctx, msg, server, &resp);
           if (   (ret != HDL_OK)
	       || (!(resp))
	       || (resp->responseCode != HDL_RC_SUCCESS)
	      )
              {
               if (   (ret == HDL_OK)
		   && (resp)
		  )       /* These are OK, but responseCode indicates failure */ 
                  ret = resp->responseCode;
               break;
              }
           HDLDestroyMessage(&resp);
           resp = NULL;
          }
       else ret = HDL_ERROR;
      }

  HDLDestroyMessage(&msg);

  if (resp)
     HDLDestroyMessage(&resp);

  return ret;
}

/*----------------------------------------------------------------------------*/

               /* Home NA to the site by given site info and na handle string */

int HDLHomeNA_Site(HDLContext *ctx, const char *naHandle,
		   unsigned int handleLen, HDLSite* siteInfo
		  )
{
  return HDLHomeOrUnhomeNA_Site(ctx,naHandle,handleLen,siteInfo,HDL_OC_HOME_NA);
}

/*----------------------------------------------------------------------------*/

          /* Un-Home NA from the site by given site info and na handle string */

int HDLUnhomeNA_Site(HDLContext *ctx, const char *naHandle,
		     unsigned int handleLen, HDLSite* siteInfo
		    )
{
 return HDLHomeOrUnhomeNA_Site(ctx,naHandle,handleLen,siteInfo,HDL_OC_UNHOME_NA);
}

/*----------------------------------------------------------------------------*/

static int HDLHomeOrUnhomeNA(HDLContext *ctx, const char *naHandle,
		             unsigned int handleLen, const char *primServerIp,
		             int port, const char* protocol,
		             unsigned int OpCode       /* HDL_OC_HOME_NA      */
						       /* or HDL_OC_UNHOME_NA */
		            )
{
  int err = HDL_ERROR;
  HDLSite *siteInfo = NULL;

  err = HDLGetSiteInfo(ctx,primServerIp, port, protocol, &siteInfo);

  if ((err == HDL_OK) && (siteInfo))
     err = ((OpCode == HDL_OC_HOME_NA)
	                  ? HDLHomeNA_Site(ctx, naHandle, handleLen, siteInfo)
                          : HDLUnhomeNA_Site(ctx, naHandle, handleLen, siteInfo)
	   );

  return err;
}

/*----------------------------------------------------------------------------*/

                     /* Home NA to the site by given primary server address,  */
                     /* port number, and protocol string and na handle string */

int HDLHomeNA(HDLContext *ctx, const char *naHandle, unsigned int handleLen,
	      const char *primServerIp, int port, const char* protocol
	     )
{
	return HDLHomeOrUnhomeNA(ctx, naHandle, handleLen, primServerIp, port,
			         protocol, HDL_OC_HOME_NA
		                );
}

/*----------------------------------------------------------------------------*/

                 /* Un-Home NA from the site by given primary server address, */
                 /* port number, and protocol string and na handle string     */

int HDLUnhomeNA(HDLContext *ctx, const char *naHandle, unsigned int handleLen,
		const char *primServerIp, int port, const char* protocol
	       )
{
	return HDLHomeOrUnhomeNA(ctx, naHandle, handleLen, primServerIp, port,
			         protocol, HDL_OC_UNHOME_NA
		                );
}


#endif /* HDL_RESOLUTION_ONLY */
