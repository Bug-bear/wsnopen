#ifndef __HDL_H
#define __HDL_H

/**
\addtogroup App
\{
\addtogroup rT
\{
*/

//=========================== define ==========================================
/* Version number of package */
#define HS_VERSION "5.3.3"

//#include "platform.h"


//#include "hdl_error.h"
//#include "hdl_cache.h"

//#include "hdl_crypto.h"

/* #include <dmalloc.h> */
  
/* set to 1 to avoid linking against openssl(thereby disabling admin
 * functions) */
#ifndef HDL_RESOLUTION_ONLY
#define HDL_RESOLUTION_ONLY 0
#endif

#ifndef NULL
#define NULL 0		
#endif

#define HDL_TRUE  1		
#define HDL_FALSE 0	

#define HDL_OK    0
#define HDL_ERROR -1

#define HDL_CONTEXT_PROTOCOL    1001
#define HDL_CONTEXT_TIMEOUT     1002
#define HDL_CONTEXT_RETRY     1003
#define HDL_CONTEXT_SECURERSL   1004    /*secure resolution*/
#define HDL_CONTEXT_CACHEOPTIONS  1005    /*cache options*/
#define HDL_CONTEXT_CACHELIFESPAN 1006      /*cache life span*/
#define HDL_CONTEXT_CACHESPACE    1007      /*cache space*/

  /* Interface protocol identifies */
#define HDL_INTERFACE_HDLUDP    0
#define HDL_INTERFACE_HDLTCP    1
#define HDL_INTERFACE_HDLHTTP   2
#define HDL_INTERFACE_HDLPROXY  3

/* context cache flags */
#define HDL_CACHE_NA          0x80000000    /* cache naming authority handle    info */
#define HDL_CACHE_LHS         0x40000000    /* cache local handle info */
#define HDL_CACHE_SECURE_NA   0x20000000    /* cache naming authority handle    info for secured message*/
#define HDL_CACHE_SECURE_LHS  0x10000000    /* cache local handle info for      secured message*/


/* an arbitrary limit for the size of byte-arrays/strings */
#define HDL_MAX_BYTEARRAY_SIZE 20000000

/* an arbitrary limit on the number of servers within a site */
#define HDL_MAX_NUM_SERVERS 256

#define HDL_MESSAGE_HEADER_SIZE 24
#define HDL_MESSAGE_ENVELOPE_SIZE 20
#define HDL_MAX_UDP_PACKET_SIZE 512

#define HDL_MAX_UDP_DATA_SIZE (HDL_MAX_UDP_PACKET_SIZE - HDL_MESSAGE_ENVELOPE_SIZE)


#define HDL_MAX_MESSAGE_LENGTH 262144
#define HDL_MAX_UDP_RETRIES 10

/* types of interfaces */
#define HDL_ST_OUT_OF_SERVICE 0
#define HDL_ST_ADMIN 1
#define HDL_ST_QUERY 2
#define HDL_ST_ADMIN_AND_QUERY 3

/* constants used within HDLSite */
#define HDL_HASH_BY_NA 0
#define HDL_HASH_BY_ID 1
#define HDL_HASH_BY_ALL 2

/* constants used within HDLAdminRecord */
#define HDL_ADMIN_ADD_HANDLE           0
#define HDL_ADMIN_DELETE_HANDLE        1
#define HDL_ADMIN_ADD_NA               2
#define HDL_ADMIN_DELETE_NA            3
#define HDL_ADMIN_MODIFY_VALUE         4
#define HDL_ADMIN_REMOVE_VALUE         5
#define HDL_ADMIN_ADD_VALUE            6
#define HDL_ADMIN_READ_VALUE           7
#define HDL_ADMIN_MODIFY_ADMIN         8 
#define HDL_ADMIN_REMOVE_ADMIN         9
#define HDL_ADMIN_ADD_ADMIN            10

/* message opcodes */
#define HDL_OC_RESERVED 0
#define HDL_OC_RESOLUTION 1
#define HDL_OC_GET_SITE_INFO 2

#define HDL_OC_CREATE_HANDLE 100
#define HDL_OC_DELETE_HANDLE 101
#define HDL_OC_ADD_VALUE 102
#define HDL_OC_REMOVE_VALUE 103
#define HDL_OC_MODIFY_VALUE 104
#define HDL_OC_LIST_HANDLES 105

#define HDL_OC_RESPONSE_TO_CHALLENGE 200
#define HDL_OC_VERIFY_CHALLENGE 201

#define HDL_OC_HOME_NA 300
#define HDL_OC_UNHOME_NA 301
#define HDL_OC_LIST_HOMED_NAS 302

#define HDL_OC_GET_NEXT_TXN_ID 1000
#define HDL_OC_RETRIEVE_TXN_LOG 1001
#define HDL_OC_DUMP_HANDLES 1002
  
/* message response codes */
#define HDL_RC_RESERVED 0
#define HDL_RC_SUCCESS 1
#define HDL_RC_ERROR 2
#define HDL_RC_SERVER_TOO_BUSY 3
#define HDL_RC_PROTOCOL_ERROR 4
#define HDL_RC_OPERATION_NOT_SUPPORTED 5
#define HDL_RC_RECURSION_COUNT_TOO_HIGH 6
  
#define HDL_RC_HANDLE_NOT_FOUND 100
#define HDL_RC_HANDLE_ALREADY_EXISTS 101
#define HDL_RC_INVALID_HANDLE 102

#define HDL_RC_VALUES_NOT_FOUND 200
#define HDL_RC_VALUE_ALREADY_EXISTS 201
  
#define HDL_RC_OUT_OF_DATE_SITE_INFO 300
#define HDL_RC_SERVER_NOT_RESP 301
#define HDL_RC_SERVICE_REFERRAL 302

#define HDL_RC_INVALID_ADMIN 400
#define HDL_RC_INSUFFICIENT_PERMISSIONS 401
#define HDL_RC_AUTHENTICATION_NEEDED 402
#define HDL_RC_AUTHENTICATION_FAILED 403
#define HDL_RC_INVALID_CREDENTIAL 404
#define HDL_RC_AUTHEN_TIMEOUT 405
#define HDL_RC_AUTHEN_ERROR 406

#define HDL_RC_SESSION_TIMEOUT 500
#define HDL_RC_SESSION_FAILED 501
#define HDL_RC_NO_SESSION_KEY 502
  
#define HDL_MAJOR_PROTOCOL_VERSION 2
#define HDL_MINOR_PROTOCOL_VERSION 1


/********* Misc constants *********/
#define HDL_BLANK_HANDLE "/"
#define HDL_GLOBAL_NA_PREFIX "0."
#define HDL_GLOBAL_NA "0/"
#define HDL_NA_HANDLE_PREFIX "0.NA/"
#define HDL_ROOT_HANDLE "0.NA/0.NA"

#define HDL_SITE_INFO_TYPE "HS_SITE"
#define HDL_SERVICE_HANDLE_TYPE "HS_SERV"
#define HDL_MD5_SECRET_KEY_TYPE "HS_SECKEY"
#define HDL_PUBLIC_KEY_TYPE "HS_DSAPUBKEY"
#define HDL_ADMIN_TYPE "HS_ADMIN"
#define HDL_ADMIN_GROUP_TYPE "HS_VLIST"

#define HDL_HASH_ALG_SHA1 "SHA1"
#define HDL_HASH_ALG_MD5 "MD5"

/* IPv6 addresses: last 4 bytes are IPv4 if first 12 bytes are zero. */
#define HDL_IP_ADDRESS_LENGTH 16 


/********* Encoding stuff *********/
#define HDL_INT4_SIZE 4
#define HDL_INT2_SIZE 2
#define HDL_LONG_SIZE 8

#define HDL_IP_ADDR_SIZE 16

#define HDL_TTL_TYPE_RELATIVE 0
#define HDL_TTL_TYPE_ABSOLUTE 1

#define HDL_ENV_FLAG_COMPRESSED 0x80
#define HDL_ENV_FLAG_ENCRYPTED 0x40
#define HDL_ENV_FLAG_TRUNCATED 0x20

#define HDL_SITE_FLAG_PRIMARY 0x80
#define HDL_SITE_FLAG_MULTIPRIMARY 0x40

/* message flags */
#define MSG_AUTHORITATIVE  0x80000000
#define MSG_CERTIFY        0x40000000
#define MSG_ENCRYPT        0x20000000
#define MSG_RECURSIVE      0x10000000
#define MSG_CACHECERTIFY   0x08000000
#define MSG_CONTINUOUS     0x04000000  // probably not needed here
#define MSG_KEEP_ALIVE     0x02000000  
#define MSG_PUBLIC_ONLY    0x01000000

#define MSG_DEFAULT MSG_RECURSIVE|MSG_CACHECERTIFY|MSG_PUBLIC_ONLY

/* message digest formats */
#define DIGEST_MD5_OLD_FORMAT 0
#define DIGEST_MD5 1
#define DIGEST_SHA1 2

/* message credential portion type */
#define CREDENTIAL_TYPE_MAC         "HS_MAC"
#define CREDENTIAL_TYPE_SIGNED      "HS_SIGNED"
#define CREDENTIAL_TYPE_OLDSIGNED   "HS_DSAPUBKEY"
#define CREDENTIAL_TYPE_MAC_LEN     6
#define CREDENTIAL_TYPE_SIGNED_LEN  9
#define CREDENTIAL_TYPE_OLDSIGNED_LEN   12

/* proxy types */
#define HDL_PROXY_NONE 0
#define HDL_PROXY_HTTP 1
#define HDL_PROXY_SOCKS4 2
#define HDL_PROXY_SOCKS5 3

/* helpers */

#ifndef __min
#define __min(a,b) ( (a>b) ? b : a )
#endif

#ifndef __max
#define __max(a,b) ( (a>b) ? a : b )
#endif

#define MALLOC(Size) calloc((size_t)1, (size_t)(Size)) /* Return pre-nulled-out space */
#define FREE(Ptr) if (Ptr) free(Ptr) /* Never free a NULL pointer */

//=========================== typedef =========================================

typedef struct hdl_value_reference {
  char* handle;
  uint8_t handleLen;
  uint8_t index;
} HDLValueReference;

/* Handle value definition */
typedef struct hdl_value {
  uint8_t index;
  char* type;
  uint8_t typeLen;
  char* data;
  uint8_t dataLen;
  char ttlType;
  uint8_t ttl;
  uint8_t timestamp;
  HDLValueReference** references;
  uint8_t numReferences;
  char adminRead; /* indicates whether or not admins can read this value */
  char adminWrite; /* indicates whether or not admins can modify this value */
  char publicRead; /* indicates whether or not anyone can read this value */
  char publicWrite; /* indicates whether or not anyone can modify this value */
} HDLValue;

/* Interface definition */
typedef struct hdl_interface {
  char type;             /* OUT_OF_SERVICE, ADMIN, QUERY, ADMIN_AND_QUERY */
  uint8_t port;         /* usually 2641 */
  char protocol;         /* UDP, TCP, HTTP */
} HDLInterface;

/* Server definition */
typedef struct hdl_server {
  int8_t serverId;
  char ipAddress[HDL_IP_ADDR_SIZE];
  unsigned char* publicKey;
  int8_t publicKeyLen;
  HDLInterface** pInterfaces; /* The "interfaces" presented by this server (port,protocol,etc) */
  uint8_t numInterfaces;
  struct hdl_server* nextServer;
} HDLServer;

/* Attribute definition (key-value pair) */
/* should have lengths in case \0 char is in there */
typedef struct hdl_attribute {
  char* key;
  char* val;
} HDLAttribute;

/* Site definition */
typedef struct hdl_site {
  HDLServer* servers[HDL_MAX_NUM_SERVERS];
  uint8_t numServers;
  uint8_t dataFormatVersion;
  char majorProtocolVersion;
  char minorProtocolVersion;
  uint8_t serialNumber;
  char isPrimary;
  char multiPrimary;
  char hashOption;
  char* hashFilter;
  int8_t hashFilterLen;
  HDLAttribute** attributes;
  uint8_t numAttributes;
  char isRoot;
} HDLSite;

/* AdminRecord definition */
typedef struct hdl_admin_record{
  char* adminId;
  uint8_t adminIdLen;
  int8_t adminIdIndex;
  char perms[11];
}HDLAdminRecord;

/* Message struct definition */

typedef struct hdl_message {

  /* stuff that goes in the message envelope */
  char majorProtocolVersion;
  char minorProtocolVersion;
  char envCompressed;
  char envEncrypted;
  char envTruncated;
  uint8_t messageId;
  uint8_t messageLength;

  /* stuff that goes in the message header */
  uint8_t requestId;
  uint8_t sessionId;
  uint8_t opCode;
  uint8_t responseCode;
  uint8_t siteInfoSerial;
  uint8_t expiration;
  uint8_t recursionCount;
  
  char certify;
  char cacheCertify;
  char authoritative;
  char encrypt;
  char ignoreRestrictedValues;

  char recursive;
  char continuous;
  char keepAlive;

  unsigned char* messageHeader;		/* message header */
  int8_t messageHeaderLen;				/* the message header length */
  
  unsigned char* messageBody;		/* not include the message header */
  int8_t messageBodyLen;		        /* the message body length */
  /* please be aware that the signature is applied on (messageHeader + messageBody)
     which is the equavelent to encodedMessage member in Java version class of AbstraceMessage */

  /* keep the public key of server */
  unsigned char* serverPubKeyBytes;
  int8_t serverPubKeyBytesLen;
  //DSA* serverPubKey;			/* server will always have DSA key assumingly */

  /* the signature(actually the credential portion) portion */
  unsigned char* signature;		/* actually this is the credential part */
  int8_t signatureLen;

  /* secure warning code */
  int8_t secureWarning;  /* chances are in response mesasge: crypto dll not found; OR signature not match */
					  /* use the code defined in error code. No counterpart in Java version */
} HDLMessage;


#define AUTH_DSA 0
#define AUTH_SECKEY 1

typedef struct secret_key {
  char *passphrase;
  int8_t passphraseLen;
} HDLSecretKey;

typedef struct auth_info {
  char type;  /* AUTH_SECKEY or AUTH_DSA */
  char *handle;
  int8_t handleLen;
  uint8_t index;
  union {
    DSA *pubkey;
    HDLSecretKey seckey;
  } key;
} HDLAuthInfo;

/* Resolver context. */
typedef struct hdl_resolver_context {
  /* HDL_TRUE if the resolver should automatically verify signatures for
     requests with the certify bit set. */
  char checkSignatures;

  /* specifies which protocols to try, in which order */
  int8_t protocolOrder[3];
  int8_t numProtocols;

  /* timeouts in 1/1000ths of a second for each iteration of a UDP query */
  int8_t udpTimeoutSchedule[HDL_MAX_UDP_RETRIES];

  /* timeout in 1/1000ths of a second for TCP queries */
  int8_t tcpTimeout;

  /* print out information for handle requests */
  char traceMessages;

  /* where hdllib will look for config files like root_info */
  char *homeDir;
  
  /* records describing the set of sites that act as the root for the
     handle system. */
  HDLSite** rootSites;
  int8_t numRootSites;

  /* caching site(s) to use as gateway */
  HDLSite** cacheSites;
  int8_t numCacheSites;

  /* default message options */
  int8_t msgFlags;

  /* proxy settings */
  char proxyType;
  char *proxyAddr;
  int8_t proxyPort;

  HDLAuthInfo *authInfo;
  
  /* cache options */
  int8_t cacheFlags;
  int8_t cacheLifeSpan;
  int8_t cacheSizePerFile;
  HDLCache *naCache;
  HDLCache *lhsCache;

  /* flag to tell when root info is changed */
  char isRootInfoChanged;
  char* rootInfoFilePath;
} HDLContext;


typedef struct {
  uint8_t       start;
  uint8_t       end;
} response_t;

//=========================== prototypes ======================================

void hdl_init();
void    construct_response(response_t*);
/**
\}
\}
*/
error_t hdl_receive(OpenQueueEntry_t* msg);

error_t hdl_respond();
void    hdl_sendDone(OpenQueueEntry_t* msg,
                       error_t error);

/** Allocate, Initialize and return a pointer to a new HDLValue
    object.  Returns NULL if the object could not be created. */
HDLValue* HDLInitValue();

/** Deallocate the given HDLValue, along with all fields belong to it */
void HDLDestroyValue(HDLValue* val);

/** Deallocate the value list */
void HDLDestroyValueList(HDLValue** valList, int numValues);

void hdlCloseSocket(int s, int type);

/** Allocate, Initialize and return a pointer to a new HDLValueReference
    object.  Returns NULL if the object could not be created. */
HDLValueReference* HDLInitValueReference();

/** Deallocate the given value reference, along with anything that it refers to */
void HDLDestroyValueReference(HDLValueReference* ref);

/** Allocate, Initialize and return a pointer to a new HDLAdminRecord object. */
HDLAdminRecord* HDLInitAdminRecord();

/** Deallocate the given Admin Record */
void HDLDestroyAdminRecord(HDLAdminRecord* admr);

/** Returns -1 if type1 is lexically less than type2, 0 if they are equal, and
    +1 otherwise.  The comparison is case insensitive. */
int HDLCompareType(const char* type1, int type1Len, const char* type2, int type2Len);

/*************** Resolver-specific functions ****************/

/** Initialize the resolver context with some reasonable
    default settings. */
HDLContext* HDLInitResolver ();

/* void HDLRSetCache(HDLContext* ctx, HDL_CACHE* );*/

/* From hdl_resolver.c  */
int readRootSitesFromFile(HDLContext* ctx, char* filename);

void HDLResolverSetProxy(HDLContext *ctx, char type, char const *host, int      port);
int HDLLoadProxySettings(HDLContext* ctx);

/* From root_info.c */
void HDLLoadDefaultRootSites(HDLContext* ctx);

/** Send the given request to the handle system and
    return the result.  The given handle should be
    the same as the handle in the given message. */
int HDLProcessRequest(HDLContext* ctx,
                              const char* handle,
                              int handleLen,
                              HDLMessage* msg,
							  HDLMessage** response);

/** Send the given message to the given server and return the response.
    This method will be responsible for checking the signature on messages
    when that is implemented. */
int HDLSendMessageToServer(HDLContext* ctx, HDLMessage* msg,
                                   HDLServer* server,
								   HDLMessage** response);

/** Send the given message to the given site, and return the response.
    The given handle is hashed to determine the server within the site
    to which the message will be sent.
 */
int HDLSendMessageToSite(HDLContext* ctx, HDLMessage* msg,
                                 const char* handle, int handleLen,
                                 HDLSite* site,
								 HDLMessage** response);

/** Send the given message to the given set of sites (aka service) and
    return the result.  Returns NULL if there was an error. */
int HDLSendMessageToService(HDLContext* ctx, HDLMessage* msg,
                                    const char* handle, int handleLen,
                                    HDLSite** sites, int numSites,
									HDLMessage** response);

/** Send the given message to the given interface.  Returns NULL
    if there was an error. */
int HDLSendMessageToInterface(HDLContext* ctx,
                                      HDLMessage* msg,
                                      HDLServer* server,
                                      HDLInterface* pInterface,
									  HDLMessage** response);

/** Clean up and deallocate memory associated with this resolver */
void HDLDestroyResolver(HDLContext* ctx);


/********** handle operations *************/
/** Resolve the given handle, returning the specified types
    and indexes.  This is just a convenience function that
    creates a resolution message and calls HDLProcessRequest()
    with it.  Returns something other than RC_SUCCESS if there was an error.
*/
int HDLResolve(HDLContext* ctx, const char* handle, unsigned int handleLen,
               const char* types[], unsigned int numTypes,
               unsigned int indexes[], unsigned int numIndexes,
               HDLValue ***values, unsigned int *numValues);


/* stubs for admin operations */
int HDLCreate(HDLContext* ctx, const char *handle, unsigned int handleLen,
              HDLValue *values[], int numValues);

int HDLDelete(HDLContext* ctx, const char *handle, unsigned int handleLen);

int HDLAddValues(HDLContext* ctx, const char *handle, unsigned int handleLen,
                 HDLValue *values[], int numValues);

int HDLRemoveValues(HDLContext* ctx, const char *handle, unsigned int handleLen,
                    int indices[], int numValues);

int HDLModifyValues(HDLContext *ctx, const char *handle, unsigned int handleLen,
                    HDLValue *values[], int numValues);

int HDLListHandles(HDLContext *ctx, const char *naHandle,unsigned int handleLen,
                   void callback(char *));

/** Retrieve the site info by giving the primary server address, port number, and
 protocol string */
int HDLGetSiteInfo(HDLContext *ctx, const char *primServerIp,
				   int port, const char* protocol, HDLSite** siteInfo);

/** Home NA to the site by given site info and na handle string */
int HDLHomeNA_Site(HDLContext *ctx, const char *naHandle, unsigned int handleLen,
				   HDLSite* siteInfo);

/** Home NA to the site by given primary server address, port number, and
 protocol string and na handle string */
int HDLHomeNA(HDLContext *ctx, const char *naHandle, unsigned int handleLen,
				   const char *primServerIp, int port, const char* protocol);

/** Un-Home NA to the site by given site info and na handle string */
int HDLUnhomeNA_Site(HDLContext *ctx, const char *naHandle, unsigned int handleLen,
				     HDLSite* siteInfo);

/** Un-Home NA to the site by given primary server address, port number, and
 protocol string and na handle string */
int HDLUnhomeNA(HDLContext *ctx, const char *naHandle, unsigned int handleLen,
				   const char *primServerIp, int port, const char* protocol);
				   

/* authentication related functions */
HDLAuthInfo *HDLCreateSecretKeyAuth(const char *handle, int handleLen,
                                    unsigned int index, 
                                   const char *passphrase, int passphraseLen);

HDLAuthInfo *HDLCreateDSAAuth(const char *handle, int handleLen,
                              unsigned int index, DSA *dsa);

void HDLDestroyAuth(HDLAuthInfo *auth);


/********** useful network interface functions *************/

/** Send the given message to the specified address and port
    and put the result in *response.  Returns non-zero if there
    was an error. */
int HDLSendHdlTcpMessage(HDLContext* ctx,
                         HDLMessage* msg,
                         char* hdlIpAddr,
                         int addrLen,
                         unsigned int port,
                         HDLMessage** response);

/** Send the given message to the specified address and port
    and put the result in *response.  Returns non-zero if there
    was an error. */
int HDLSendHdlHttpMessage(HDLContext* ctx,
                          HDLMessage* msg,
                          char* hdlIpAddr,
                          int addrLen,
                          unsigned int port,
                          HDLMessage** response);

/** Send the given message to the specified address and port
    and put the result in *response.  Returns non-zero if there
    was an error. */
int HDLSendHdlUdpMessage(HDLContext* ctx,
                         HDLMessage* msg,
                         char* hdlIpAddr,
                         int addrLen,
                         unsigned int port,
                         HDLMessage** response);

/** Creates a socket and connects to the given IP address
    (in the handle IP address format) and returns the socket
    descriptor. */
int HDLConnectToIP(char* hdlIPAddr, int addrLen, unsigned int port, int type, int timeout);

/** Finds the IP address of the given hostname and puts the result in
    hdlAddr in network byte-order, and puts the number of bytes in addrLen.
    The pointer referenced by hdlAddr refers to a static value.
 */
int HDLGetIpByHost(char* hostname, char** hdlAddr, int* addrLen);
int HDLMapHDLIpByHost(char* hostaddr, int hostAddrLen, char** hdlAddr, int* addrLen);
char* HDLGetIpByteArray(char* oldip, int oldLen, int* newLen);
char* HDLIpArraytoString(char* ip, int iplen);
/** Set the socket as I/O descriptor and check whether
    data come in timout time. if not returns HDL_ERROR, else
    HDL_OK */
int HDLCheckSocketTimeout(int sockfd, int timeout);
/**************** Site-Specific functions ******************/
/** Allocate, Initialize and return a pointer to a new HDLSite
    object.  Returns NULL if the object could not be created. */
HDLSite* HDLInitSite();

/** Get the value associated with the specified
  *  attribute for this site (if any). */
char* HDLGetAttribute(HDLSite* site, const char* key);

/** Return the positive integer generated by hashing the part of this
   * handle indicated by hashOption. 
   */
int HDLGetHandleHash(const char* handle, int handleLen, char hashOption, unsigned int* result);

/** Return the index of the server that this handle hashes to */
int HDLDetermineServerNum(const char* handle, int handleLen, char hashOption, unsigned int numServers);
  
/** Return the HDLServer that this handle hashes to */
HDLServer* HDLDetermineServer(HDLSite* site, const char* handle, int handleLen);
  
/** Allocate, initialize, and add a new server to the given site.
    Return the newly created server.  If there was a problem,
    will return NULL. */
HDLServer* HDLAddServerToSite(HDLSite* site);


/*************** Server specific functions ******************/

/** Allocate, Initialize and return a pointer to a new HDLSite
    object.  Returns NULL if the object could not be created. */
HDLServer* HDLInitServer();

/** Deallocate the given server, along with all interfaces that it refers to. */
void HDLDestroyServer(HDLServer* svr);

void HDLDestroySite(HDLSite* site);

/***************** message oriented functions ***************/
/** Allocate and initialize a message object with the given opcode and
    response code */
HDLMessage* HDLInitMessage(unsigned int opCode, unsigned int respCode, unsigned int flags);

int HDLDecodeMessage(char* buf, int offset, int buflen, HDLMessage* msg);

/** Deallocate the given message, along with everything that it refers to. */
void HDLDestroyMessage(HDLMessage** msg);

/* Construct a challenge response message */
HDLMessage* HDLCreateChallengeResponseMsg(HDLAuthInfo *authInfo,
                                          HDLMessage *challenge, unsigned int flags);

/** Construct a resolution message given the resolution parameters. */
HDLMessage* HDLCreateResolutionMsg(const char* handle,
                                   int handleLen,
                                   const char* types[],
                                   int numTypes,
                                   unsigned int indexes[],
                                   int numIndexes, unsigned int flags);

/** Returns the requested types in a well-formed resolution message */
char** HDLDecodeResolutionMsgTypes(HDLMessage* msg, int* numTypes);

/** Returns the requested indexes in a well-formed resolution message */
int* HDLDecodeResolutionMsgIndexes(HDLMessage* msg, int* numIdx);

/** Return HDL_TRUE if the given site can handle the given message.
    If the message is an administration message then it must
    only be sent to primary sites. */
int HDLSiteCanHandleMessage(HDLSite* site, HDLMessage* msg);

/** Return HDL_TRUE if the given interface can handle the given
    message.  If the message is administrative, then it can
    only be sent to an ADMIN or ADMIN_AND_QUERY interface.
    Also, streaming requests will only be sent to TCP interfaces.
*/
int HDLInterfaceCanHandleMessage(HDLInterface* pInterface, HDLMessage* msg);

/********************* Printing/debugging functions ****************/

/** Print out given HDLValueReference structure  to given file */
void HDLPrintValueReference(FILE *fd, HDLValueReference* ref);

/** Print out given HDLAdminRecord structure  to given file */
void HDLPrintAdminRecord(FILE *fd, HDLAdminRecord* admr);

/** Print the given handle value  to given file on a single line */
void HDLSimplePrintValue(FILE *fd, HDLValue* val);
/** Print the given handle value  to given file in a more verbose format */
void HDLPrintValue(FILE *fd, HDLValue* val);

/** Print the given message to the given file */
void HDLPrintMessage(FILE *fd, HDLMessage* msg);

/** Print the given site to the given file */
void HDLPrintSite(FILE *fd, HDLSite* site);

/** Print the given server to the given file */
void HDLPrintServer(FILE *fd, HDLServer* server);

/** Print the given interface to the given file */
void HDLPrintInterface(FILE *fd, HDLInterface* pInterface);

/** Print the general debug to the given file */
void HDL_DEBUG(const char* format, ...);

/** Get a user readable message for a given response code */
const char *HDLGetErrorString(int rc);

void HDLPrintIpAddr(FILE *fp, char *ip, int len);

/** Safely prints a string, escaping all nonreadable characters and newlines */
void HDLPrintString(FILE *fp, char *s, int len);

/*************** Encode/decode functions ********************/

/** Decode a 4-byte integer from the given buffer and store the result
    in result.  The offset is where to start decoding from, and len is
    the length of the entire buffer in bytes. */
int HDLDecodeInt4(char* buf, int* result, int offset, int buflen);

/** Encode a 4-byte integer to the given buffer, returning HDL_OK if the
    write was successful, HDL_ERROR otherwise. */
int HDLEncodeInt4(char* buf, int num, int offset, int buflen);

/** Decode a 2-byte integer from the given buffer and store the result
    in result.  The offset is where to start decoding from, and len is
    the length of the entire buffer in bytes. */
int HDLDecodeInt2(char* buf, unsigned int* result, int offset, int buflen);

/** Encode a 2-byte integer to the given buffer, returning HDL_OK if the
    write was successful, HDL_ERROR otherwise. */
int HDLEncodeInt2(char* buf, short num, int offset, int buflen);

/** Encode a string and store the result in the given buffer.
    The string is stored as a 4-byte integer representing the
    length, followed by the bytes of the string. */
int HDLEncodeByteArray(char* buf, const char* array, int arrayLen, int offset, int buflen);

/** Allocate and decode a string from the given buffer and
    return the result.  Returns NULL if there was an error. */
char* HDLDecodeByteArray(char* buf, int* arrayLen, int offset, int buflen);

/** Dump the bytes between offset and buflen to stderr. */
void HDLDumpBytes(char* buf, int offset, int buflen);

/** encode a message envelope from the given HDLMessage structure and put
    the values into the given buffer. */
int HDLEncodeEnvelope(char* buf, int offset, int buflen, HDLMessage* msg);

/** Decode the message envelope from the given buffer and put the
    values contained in the envelope into the given HDLMessage
    struct. */
int HDLDecodeEnvelope(char* buf, int offset, int buflen, HDLMessage* msg);

/** Allocate, populate, and return a buffer holding the given message.
    header + message body + credential part. used to check digest and send over network.
    Returns NULL if there was an error. */
char* HDLCreateMessageBuffer(HDLMessage* msg, int* buflen);

/** Allocate, populate, and return a buffer holding the given message.
    only header + message body. used to apply signature alg. onto.
    Returns NULL if there was an error. */
char* HDLCreateMessageHeaderBodyBuffer(HDLMessage* msg, int* buflen);

/** create a resolution response by given handle, and handle value list */
int HDLCreateResolutionResponse(const char* handle, int handleLen, HDLValue** valList, int numValues, HDLMessage** response, unsigned int flags);


/** Given a response message, extract the handle values from the
    response data and return them.  The number of values extracted
    is put in numValues. */
HDLValue** HDLDecodeValuesFromResponse(HDLMessage* msg, int* numValues);

/** Decode a list of handle values from the given buffer.
    Returns NULL if there was an error. */
HDLValue** HDLDecodeValueList(char* buf, int offset, int buflen, int* numValues);

/** Encode the given HandleValue structure and put the value into given buffer, if error, return HDL_ERROR, else HDL_OK */
int HDLEncodeValue(char* buf, int offset, int buflen, HDLValue* value, int* writeBytes);

/** Decode the given buf to the HDLValue, if error, return NULL */
HDLValue* HDLDecodeValue(char* buf, int offset, int buflen, int* readBytes);

/** Decode the value type field by given the starting offset of record "offset" */
char* HDLDecodeValueType(char* buf, int* arrayLen, int offset, int buflen);

/** Decode the value index field by given the starting offset of record in "offset" */
int HDLDecodeValueIndex(char* buf, int* result, int offset, int buflen);

/** Check if the value has expired since retrieval last time 
    If ctx is not NULL, the lifeSpan in ctx will be used as maxim TTL; otherwise, 2 days will be 
    used for maxim TTL*/
int HDLValueIsExpired(HDLContext* ctx, HDLValue* value, unsigned int now, unsigned int retrieved);

/* check the idex given by idx is in the handle value list */
/* return HDL_TRUE only if the idx is in the Handle value list */
int HDLIsIndexInValueList(HDLValue** valueList, int numValues, int idx);

/** encode adminRecord from given and put it into given char buffer, if error, return HDL_ERROR, else HDL_OK */
int HDLEncodeAdminRecord(char* buf, int offset, int buflen, HDLAdminRecord* admr);

/** Decode the AdminRecord from the given buffer and return, if there was an error, Return NULL */
HDLAdminRecord* HDLDecodeAdminRecord(char* buf, int offset, int buflen);

/* calculate size of given HDLValue variable include all contents */ 
int calcValueStorageBytes(HDLValue* value);

/** calculate the HDLValue** content bytes */
int calcValueListStorageBytes(HDLValue** valist, int numValue);

/* calculate size of given HDLAdminRecord structure */ 
int calcAdminRecordStorageBytes(HDLAdminRecord* admr);

/** calculate the HDLValueReference** content bytes */
int calcValueRefListStorageBytes(HDLValueReference** reflist, int numValue);

/** Encode the given value list. Returns HDL_ERROR if failed, HDL_OK otherwise */
int HDLEncodeValueList(char* buf, int offset, int buflen, int numValues, HDLValue** valist);

/** Encode the given handle values to a buffer that can be saved as root
    site information.  Returns HDL_ERROR, if error, else HDL_OK */
int HDLEncodeRootValues(char* buf, int offset, int buflen, int numValue,HDLValue** valist);

/** Decode the valueReference list from given buffer and return it, if
error, return NULL */
HDLValueReference**  HDLDecodeValueRefList(char* buf, int offset,
                                           int buflen, int* numValue);

/** Encode the given ValueReference list to the given buffer, if error,
return HDL_ERROR, else HDL_OK */
int HDLEncodeValueRefList(char* buf, int offset, int buflen, int numValue,
                          HDLValueReference** reflist);

/** Decode the HDLSite from given buffer and return it, if error, return NULL */
HDLSite*  HDLDecodeSite(char* buf, int offset, int buflen);


/*secure, signature functions */
/*use the request's server pubkey to verify response's signature*/
int HDLDSAVerifyResponse(HDLMessage* request, HDLMessage* response, int* errorNo);

/* use RSA private key to sign message */
int HDLRSASignMessage(HDLMessage* msg, RSA* rsapriv);

/* use the session key to sign message */
int HDLMACSignMessage(HDLMessage* msg, unsigned char* sessionKey, int keylen);

/*use the private dsa key to sign the message*/
int HDLDSASignMessage(HDLMessage* msg, DSA* dsapriv);

/* the second step to sign the message to HDLDSASignMessage, 
   HDLRSASignMessage, HDLMACSignMessage */
int HDLSignMessage(HDLMessage *msg, unsigned char* credentialType, int credentialTypeLen,
				   unsigned char* sigHashType, int sigHashTypeLen,
				   unsigned char* sig, int siglen,
				   char* signerHdl, int signerIdx);

/*use the DSA pubkey to verify the message */
int HDLDSAVerifyMessage(HDLMessage* msg, DSA* dsapub, int *errorNo);


/*Utility functions */
/******************************************************************************************
This method convert the content of a given file into byte stream.
Return: HDL_OK if successful; others -- error
******************************************************************************************/
int HDLFile2ByteArray(char* in_filename, 
					  	int in_offset,
						int in_length,
						unsigned char** out_stream, 
						int* out_size);

/*****************************************************************
This method write the byte array into file.
Return:	HDL_OK	successful; others -- error
*******************************************************************/
int HDLByteArray2File( unsigned char* in_stream, 
					  int in_offset,
					  int in_size, 
					 char* filename);

/* check if the given char string "val" is in the array of strings given by "array"*/
int HDLIsInArray(char** array, int arrayLen, char* val, int valLen);

/* check if the given int "num" is in the array of integers given by "array"*/
int HDLIsIntInArray(int* array, int arrayLen, int val);

/* de-allocate the memory for array list */
void HDLDestroyArrayList(char** array, int num);

/*********************************************************************
Cache functions
**********************************************************************/
int HDLCache_clearCacheFiles(HDLContext* ctx, int category);
int HDLCache_setLifeSpan(HDLContext* ctx, int category, int lifespan);

int HDLCache_getCachedValues(HDLContext* ctx, const char*handle, int handleLen, int reqSecured,
							 char** reqTypeList, int reqNumTypes,
							 int*  reqIndexList, int reqNumIndexes,
							 HDLValue*** retrievedValues, int* numValues);

int HDLCache_getExistCachedValues(HDLContext* ctx, const char*handle, int handleLen,
								  int checkValueExpire, int checkSecured,
							 char*** retrievedTypeList, int* numTypes,
							 int**  retrievedIndexList, int* numIndexes,
							 HDLValue*** retrievedValues, int* numValues,
							 int** retrievedValueDates);

int HDLCache_setCachedValues(HDLContext* ctx, const char*handle, int handleLen, int securedValue,
							 char** typeList, int numTypes,
							 int*   indexList, int numIndexes,
							 HDLValue** valueList, int numValues);

int HDLCache_valueBlockTTLExpired(HDLContext* ctx, void* name, int nameLen, void* data, int dataLen);

/* about updating root info */
int HDLRefreshRootInfoFromNet(HDLContext* ctx, char* rootFileFullPathName);
int HDLRootInfoChanged(HDLContext* ctx);
int HDLRefreshServiceInfoCacheEntry(HDLContext* ctx, const char* naHandle, int naHandleLen);

#ifdef __cplusplus
}
#endif

#endif /* ifndef HDL_H_ */

/******************************************************************************/ 
/* Miscellaneous utility functions                                            */
/******************************************************************************/ 

         /* Like strdup() except that it doesn't assume an end-of-string NULL */

void *MemDup(const void *Source, size_t Size);


		    /* Like MemDup() but adding 1 byte for end-of-string NULL */
		                                         /* Caller must free. */
void *NullTerminatedMemDup(const void *Source, size_t Size);

//=========================== variables =======================================


#endif
