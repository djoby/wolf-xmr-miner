// {{{ Includes
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <stdbool.h>
#include <jansson.h>
#include <stdatomic.h>
#ifdef __x86_64__
#include <cpuid.h>
#endif
#ifdef __linux__
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sched.h>
#else
#include <winsock2.h>
#undef __cpuid
#endif
#include "cryptonight.h"
#include "minerutils.h"
#include "minerlog.h"
#include "minernet.h"
#include "miner.h"
// }}} Includes

// {{{ Defines
#define STRATUM_TIMEOUT_SECONDS			120
#define STRATUM_MAX_MESSAGE_LEN_BYTES	4096
#define JSON_BUF_LEN	345
// }}} Defines

// {{{ Typedefs
typedef struct _JobInfo
{
	uint64_t XMRTarget;
	uint8_t ID[32];
	uint8_t XMRBlob[128];
	uint32_t XMRBlobLen;
	char *blockblob;
} JobInfo;

typedef struct _StatusInfo
{
	uint64_t SolvedWork;
	uint64_t RejectedWork;
	double *ThreadHashCounts;
	double *ThreadTimes;
} StatusInfo;

typedef struct _WorkerInfo
{
	char *User;
	char *Pass;
	struct _WorkerInfo *NextWorker;
} WorkerInfo;

typedef struct _PoolInfo
{
	SOCKET sockfd;
	char *PoolName;
	char *StrippedURL;
	char *Port;
	WorkerInfo WorkerData;
	uint32_t MinerThreadCount;
	uint32_t *MinerThreads;
	atomic_uint StratumID;
	char XMRAuthID[64];
} PoolInfo;


typedef struct _Share
{
	struct _Share *next;
	JobInfo *Job;
	uint32_t Nonce;
	int Gothash;
	uint8_t Blob[32];
} Share;

typedef struct _ShareQueue
{
	Share *first;
	Share *last;
} ShareQueue;

typedef struct _PoolBroadcastInfo
{
	int poolsocket;
	WorkerInfo WorkerData;
} PoolBroadcastInfo;

// RequestedWorksize and RequestedxIntensity should be zero if none was requested
typedef struct _MinerThreadInfo
{
	uint32_t ThreadID;
	uint32_t TotalMinerThreads;
} MinerThreadInfo;

// Settings structure for a group of threads mining one algo.
typedef struct _Settings
{
	uint32_t TotalThreads;
	uint32_t PoolCount;
	char **PoolURLs;
	WorkerInfo *Workers;
} Settings;
// }}} Typedefs

// {{{ Globals
pthread_mutex_t StatusMutex = PTHREAD_MUTEX_INITIALIZER;

static StatusInfo GlobalStatus;

static cryptonight_func *cryptonight_hash_ctx;

atomic_bool *RestartMining;

bool ExitFlag = false;
int ExitPipe[2];

JobInfo Jobs[2];
volatile JobInfo *CurrentJob;
volatile int JobIdx;

Share *ShareList;
ShareQueue CurrentQueue;
pthread_mutex_t QueueMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t QueueCond = PTHREAD_COND_INITIALIZER;
// }}} Globals

// {{{ Functions
Share *GetShare()
{
	Share *ret;
	if (ShareList) {
		ret = ShareList;
		ShareList = ret->next;
	} else {
		ret = malloc(sizeof(Share));
	}
	return ret;
}

void SubmitShare(ShareQueue *queue, Share *NewShare)
{
	NewShare->next = NULL;
	
	if(!queue->first) queue->first = queue->last = NewShare;
	else queue->last = queue->last->next = NewShare;
}

Share *RemoveShare(ShareQueue *queue)
{
	Share *tmp = queue->first;
	if(queue->first) queue->first = queue->first->next;	
	return(tmp);
}

void FreeShare(Share *share)
{
	share->next = ShareList;
	ShareList = share;
}

int sendit(int fd, char *buf, int len)
{
	int rc;
	do
	{
		rc = send(fd, buf, len, 0);
		if (rc == -1)
			return rc;
		buf += rc;
		len -= rc;
	} while (len > 0);
	return rc < 1 ? -1 : 0;
}

void *PoolBroadcastThreadProc(void *Info)
{
	PoolInfo *pbinfo = (PoolInfo *)Info;
	char s[JSON_BUF_LEN];
	void *c_ctx = cryptonight_ctx();

	pthread_mutex_lock(&QueueMutex);
	for(;;)
	{
		pthread_cond_wait(&QueueCond, &QueueMutex);
		for(Share *CurShare = RemoveShare(&CurrentQueue); CurShare; CurShare = RemoveShare(&CurrentQueue))
		{
			char ASCIINonce[9], ASCIIResult[65];
			uint8_t HashResult[32];
			int ret, len;
			
			BinaryToASCIIHex(ASCIINonce, &CurShare->Nonce, 4U);
			
			if (!CurShare->Gothash) {
				((uint32_t *)(CurShare->Job->XMRBlob + 39))[0] = CurShare->Nonce;
				cryptonight_hash_ctx(HashResult, CurShare->Job->XMRBlob, CurShare->Job->XMRBlobLen, c_ctx);
				BinaryToASCIIHex(ASCIIResult, HashResult, 32);
			} else {
				BinaryToASCIIHex(ASCIIResult, CurShare->Blob, 32);
			}
			len = snprintf(s, JSON_BUF_LEN,
				"{\"method\": \"submit\", \"params\": {\"id\": \"%s\", "
				"\"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, "
				"\"id\":1}\r\n\n",
				pbinfo->XMRAuthID, CurShare->Job->ID, ASCIINonce, ASCIIResult);

			FreeShare(CurShare);
			pthread_mutex_lock(&StatusMutex);
			GlobalStatus.SolvedWork++;
			pthread_mutex_unlock(&StatusMutex);
			
			Log(LOG_NETDEBUG, "Request: %s", s);
			
			ret = sendit(pbinfo->sockfd, s, len);
			if (ret == -1)
				break;
			
		}
	}
	pthread_mutex_unlock(&QueueMutex);
	// free(c_ctx);
	return(NULL);
}

static void RestartMiners(PoolInfo *Pool)
{
	for(int i = 0; i < Pool->MinerThreadCount; ++i)
		atomic_store(RestartMining + i, true);
}

void *StratumThreadProc(void *InfoPtr)
{
	JobInfo *NextJob;
	int poolsocket, ret;
	size_t PartialMessageOffset;
	char rawresponse[STRATUM_MAX_MESSAGE_LEN_BYTES];
	PoolInfo *Pool = (PoolInfo *)InfoPtr;
	char s[JSON_BUF_LEN];
	int len;
	
	poolsocket = Pool->sockfd;
	
	len = snprintf(s, JSON_BUF_LEN, "{\"method\": \"login\", \"params\": "
		"{\"login\": \"%s\", \"pass\": \"%s\", "
		"\"agent\": \"xmr-wolf-miner/1.0\"}, \"id\": 1}\r\n\n",
		Pool->WorkerData.User, Pool->WorkerData.Pass);

	Log(LOG_NETDEBUG, "Request: %s", s);

	ret = sendit(Pool->sockfd, s, len);
	if (ret == -1)
		return(NULL);
	
	PartialMessageOffset = 0;
	
	SetNonBlockingSocket(Pool->sockfd);
	
	NextJob = &Jobs[0];

	// Listen for work until termination.
	for(;;)
	{
		fd_set readfds;
		uint32_t bufidx, MsgLen;
		struct timeval timeout;
		char StratumMsg[STRATUM_MAX_MESSAGE_LEN_BYTES];
		
		timeout.tv_sec = 480;
		timeout.tv_usec = 0;
		FD_ZERO(&readfds);
		FD_SET(poolsocket, &readfds);
		
		ret = select(poolsocket + 1, &readfds, NULL, NULL, &timeout);
		
		if(ret != 1 || !FD_ISSET(poolsocket, &readfds))
		{
retry2:
			Log(LOG_NOTIFY, "Stratum connection to pool timed out.");
			closesocket(poolsocket);
			RestartMiners(Pool);
retry:
			poolsocket = Pool->sockfd = ConnectToPool(Pool->StrippedURL, Pool->Port);
			
			// TODO/FIXME: This exit is bad and should be replaced with better flow control
			if(poolsocket == INVALID_SOCKET)
			{
				Log(LOG_ERROR, "Unable to reconnect to pool. Sleeping 10 seconds...\n");
				sleep(10);
				goto retry;
			}
			
			Log(LOG_NOTIFY, "Reconnected to pool... authenticating...");
reauth:
			
			Log(LOG_NETDEBUG, "Request: %s", s);

			ret = sendit(Pool->sockfd, s, len);
			if (ret == -1)
				return(NULL);
			
			PartialMessageOffset = 0;
			
			Log(LOG_NOTIFY, "Reconnected to pool.");
			
		}
		
		// receive
		ret = recv(poolsocket, rawresponse + PartialMessageOffset, STRATUM_MAX_MESSAGE_LEN_BYTES - PartialMessageOffset, 0);
		if (ret <= 0)
			goto retry2;
		
		rawresponse[ret] = 0x00;
		
		bufidx = 0;
		
		while(strchr(rawresponse + bufidx, '\n'))
		{
			json_t *msg, *msgid, *method;
			
			MsgLen = strchr(rawresponse + bufidx, '\n') - (rawresponse + bufidx) + 1;
			memcpy(StratumMsg, rawresponse + bufidx, MsgLen);
			StratumMsg[MsgLen] = 0x00;
			
			bufidx += MsgLen;
			
			Log(LOG_NETDEBUG, "Got something: %s", StratumMsg);
			msg = json_loads(StratumMsg, 0, NULL);
			
			if(!msg)
			{
				Log(LOG_CRITICAL, "Error parsing JSON from pool server.");
				closesocket(poolsocket);
				return(NULL);
			}
			
			msgid = json_object_get(msg, "id");
			
			// If the "id" field exists, it's either the reply to the
			// login, and contains the first job, or is a share
			// submission response, at least in this butchered XMR Stratum
			// The ID is also stupidly hardcoded to 1 in EVERY case.
			// No ID field means new job
			// Also, error responses to shares have no result
			if(msgid && json_integer_value(msgid))
			{
				json_t *result = json_object_get(msg, "result");
				json_t *authid = NULL;
				
				//if(!result)
				//{
				//	Log(LOG_CRITICAL, "Server sent a message with an ID and no result field.");
				//	json_decref(msg);
				//	close(poolsocket);
				//	return(NULL);
				//}
				
				// Only way to tell the two apart is that the result
				// object on a share submission response has ONLY
				// the status string.
				
				if(result) authid = json_object_get(result, "id");
				
				// Must be a share submission response if NULL
				// Otherwise, it's the first job.
				if(!authid)
				{
					json_t *result = json_object_get(msg, "result");
					json_t *err = json_object_get(msg, "error");
					
					pthread_mutex_lock(&StatusMutex);
					
					if(json_is_null(err) && !strcmp(json_string_value(json_object_get(result, "status")), "OK"))
					{
						Log(LOG_INFO, "Share accepted: %d/%d (%.02f%%)", GlobalStatus.SolvedWork - GlobalStatus.RejectedWork, GlobalStatus.SolvedWork, (double)(GlobalStatus.SolvedWork - GlobalStatus.RejectedWork) / GlobalStatus.SolvedWork * 100.0);
					}
					else
					{
						const char *errmsg;
						GlobalStatus.RejectedWork++;
						errmsg = json_string_value(json_object_get(err, "message"));
						Log(LOG_INFO, "Share rejected (%s): %d/%d (%.02f%%)", errmsg, GlobalStatus.SolvedWork - GlobalStatus.RejectedWork, GlobalStatus.SolvedWork, (double)(GlobalStatus.SolvedWork - GlobalStatus.RejectedWork) / GlobalStatus.SolvedWork * 100.0);
						if (!strcasecmp("Unauthenticated", errmsg)) {
							pthread_mutex_unlock(&StatusMutex);
							RestartMiners(Pool);
							goto reauth;
						}
					}
					
          double TotalHashrate = 0;
					for(int i = 0; i < Pool->MinerThreadCount; ++i)
					{
						TotalHashrate += GlobalStatus.ThreadHashCounts[i] / GlobalStatus.ThreadTimes[i];
					}
					
					Log(LOG_INFO, "Total Hashrate: %.02fH/s\n", TotalHashrate);
					
					pthread_mutex_unlock(&StatusMutex);
				}
				else
				{
					json_t *job, *blob, *jid, *target;
					
					// cpuminer has it hardcoded to 64, so hell, no point
					// in handling arbitrary sizes here
					strcpy(Pool->XMRAuthID, json_string_value(authid));
					
					job = json_object_get(result, "job");
					
					if(!job)
					{
						Log(LOG_CRITICAL, "Server did not respond to login request with a job.");
						json_decref(msg);
						return(NULL);
					}
					
					blob = json_object_get(job, "blob");
					jid = json_object_get(job, "job_id");
					target = json_object_get(job, "target");
					
					if(!blob || !jid || !target)
					{
						Log(LOG_CRITICAL, "Server sent invalid first job.");
						json_decref(msg);
						return(NULL);
					}
					
					const char *val = json_string_value(blob);
					NextJob->XMRBlobLen = strlen(val) / 2;
					ASCIIHexToBinary(NextJob->XMRBlob, val, NextJob->XMRBlobLen * 2);
					strcpy((char *) NextJob->ID, json_string_value(jid));
					NextJob->XMRTarget = __builtin_bswap32(strtoul(json_string_value(target), NULL, 16));
					CurrentJob = NextJob;
					JobIdx++;
					NextJob = &Jobs[JobIdx&1];
					Log(LOG_NOTIFY, "First job at diff %g", (double)0xffffffff / CurrentJob->XMRTarget);
					CurrentJob->XMRTarget <<= 32;
					CurrentJob->XMRTarget |= 0xffffffff;
				}
				json_decref(result);
			}
			else
			{
				method = json_object_get(msg, "method");
				if(!method)
				{
					Log(LOG_CRITICAL, "Server message has no id field and doesn't seem to have a method field...");
					json_decref(msg);
					closesocket(poolsocket);
					return(NULL);
				}
				
				if(!strcmp("job", json_string_value(method)))
				{
					json_t *job, *blob, *jid, *target;
					
					job = json_object_get(msg, "params");
					
					if(!job)
					{
						Log(LOG_CRITICAL, "Job notification sent no params.");
						json_decref(msg);
						return(NULL);
					}
					
					blob = json_object_get(job, "blob");
					jid = json_object_get(job, "job_id");
					target = json_object_get(job, "target");
					
					if(!blob || !jid || !target)
					{
						Log(LOG_CRITICAL, "Server sent invalid job.");
						json_decref(msg);
						return(NULL);
					}
					
					const char *val = json_string_value(blob);
					NextJob->XMRBlobLen = strlen(val) / 2;
					ASCIIHexToBinary(NextJob->XMRBlob, val, NextJob->XMRBlobLen * 2);
					strcpy((char *) NextJob->ID, json_string_value(jid));
					NextJob->XMRTarget = __builtin_bswap32(strtoul(json_string_value(target), NULL, 16));
					CurrentJob = NextJob;
					JobIdx++;
					NextJob = &Jobs[JobIdx&1];
					
    
					pthread_mutex_lock(&StatusMutex);
          double TotalHasrate = 0;
          for(int i = 0; i < Pool->MinerThreadCount; ++i)
          {
            TotalHasrate += GlobalStatus.ThreadHashCounts[i] / GlobalStatus.ThreadTimes[i];
          }
          
          Log(LOG_INFO, "Total Hashrate: %.02fH/s\n", TotalHasrate);
					pthread_mutex_unlock(&StatusMutex);

					// No cleanjobs param, so we flush every time
					RestartMiners(Pool);
						
					Log(LOG_NOTIFY, "New job at diff %g", (double)0xffffffff / CurrentJob->XMRTarget);
					CurrentJob->XMRTarget <<= 32;
					CurrentJob->XMRTarget |= 0xffffffff;
				}	
				else
				{
					Log(LOG_NETDEBUG, "I have no idea what the fuck that message was.");
				}
				
				json_decref(msg);
			}
		}
		memmove(rawresponse, rawresponse + bufidx, ret - bufidx);
		PartialMessageOffset = ret - bufidx;
	}
}

// Block header is 2 uint512s, 1024 bits - 128 bytes
void *MinerThreadProc(void *Info)
{
	int MyJobIdx;
  TIME_TYPE begin, end;
	JobInfo *MyJob;
	char ThrID[128];
	uint32_t TmpWork[32];
	uint64_t Target;
	uint32_t BlobLen;
	MinerThreadInfo *MTInfo = (MinerThreadInfo *)Info;
	uint32_t StartNonce = (0xFFFFFFFFU / MTInfo->TotalMinerThreads) * MTInfo->ThreadID;
	uint32_t MaxNonce = StartNonce + (0xFFFFFFFFU / MTInfo->TotalMinerThreads);
	struct cryptonight_ctx *ctx;
	uint32_t *nonceptr = (uint32_t *)((char *)TmpWork + 39);
	unsigned long hashes_done;
  uint32_t n;
  uint64_t hash[32/8] __attribute__((aligned(64)));
  int found;
  double Seconds;
	
	// Generate work for first run.
	MyJobIdx = JobIdx;
	MyJob = (JobInfo *)CurrentJob;
	BlobLen = MyJob->XMRBlobLen;
	memcpy(TmpWork, MyJob->XMRBlob, BlobLen);
	Target = MyJob->XMRTarget;
	ctx = cryptonight_ctx();
	*nonceptr = StartNonce;
	sprintf(ThrID, "Thread %d, (CPU)", MTInfo->ThreadID);
	
	while(!ExitFlag)
	{
		atomic_store(RestartMining + MTInfo->ThreadID, false);
		
		// If JobID is not equal to the current job ID, generate new work
		// off the new job information.
		// If JobID is the same as the current job ID, go hash.
		if(MyJobIdx != JobIdx)
		{
			Log(LOG_DEBUG, "%s: Detected new job, regenerating work.", ThrID);
			MyJobIdx = JobIdx;
			MyJob = (JobInfo *)CurrentJob;
			BlobLen = MyJob->XMRBlobLen;
			memcpy(TmpWork, MyJob->XMRBlob, BlobLen);
			Target = MyJob->XMRTarget;
			*nonceptr = StartNonce;
		}
		else
				++(*nonceptr);
		begin = MinerGetCurTime();
		const uint32_t first_nonce = *nonceptr;
		n = first_nonce - 1;
		found = 0;
		do {
			if (ExitFlag) break;
			*nonceptr = ++n;
			cryptonight_hash_ctx(hash, TmpWork, BlobLen, ctx);
			if (hash[3] < Target) {
				found = 1;
			} else if (atomic_load(RestartMining + MTInfo->ThreadID)) {
				found = 2;
			}
		} while (!found && n < MaxNonce);
		end = MinerGetCurTime();
		if (found == 1) {
			Log(LOG_DEBUG, "%s: SHARE found (nonce 0x%.8X)!", ThrID, *nonceptr);
			pthread_mutex_lock(&QueueMutex);
			Share *NewShare = GetShare();
			
			NewShare->Nonce = *nonceptr;
			NewShare->Gothash = 1;
			memcpy(NewShare->Blob, hash, 32);
			NewShare->Job = MyJob;
			
			SubmitShare(&CurrentQueue, NewShare);
			pthread_cond_signal(&QueueCond);
			pthread_mutex_unlock(&QueueMutex);
		}
		pthread_mutex_lock(&StatusMutex);
		hashes_done = n - first_nonce;
		Seconds = SecondsElapsed(begin, end);
		GlobalStatus.ThreadHashCounts[MTInfo->ThreadID] = hashes_done;
		GlobalStatus.ThreadTimes[MTInfo->ThreadID] = Seconds;
		pthread_mutex_unlock(&StatusMutex);
		
		Log(LOG_INFO, "%s: %.02fH/s", ThrID, hashes_done / (Seconds));
	}
	return(NULL);
}

#ifdef __linux__
void SigHandler(int signal)
{
	char c;
	ExitFlag = true;
	write(ExitPipe[1], &c, 1);
}
#else
BOOL SigHandler(DWORD signal)
{
	ExitFlag = true;

	return(TRUE);
}
#endif

int ParseConfigurationFile(char *ConfigFileName, Settings *Settings)
{
	json_t *Config;
	json_error_t Error;
	
	Config = json_load_file(ConfigFileName, JSON_REJECT_DUPLICATES, &Error);
	
	if(!Config)
	{
		Log(LOG_CRITICAL, "Error loading configuration file: %s on line %d.", Error.text, Error.line);
		return(-1);
	}
  
  json_t *num = json_object_get(Config, "threads");
  if(num && !json_is_integer(num))
  {
    Log(LOG_CRITICAL, "Argument to threads for algo CryptoNight is not an integer.");
    return(-1);
  }
  
  if(num) Settings->TotalThreads = json_integer_value(num);
  else Settings->TotalThreads = 1;

//  if (Settings->TotalThreads > sysconf(_SC_NPROCESSORS_ONLN)) {
//    Log(LOG_CRITICAL, "Argument threads s too high for algo CryptoNight (max: cores - 1).");
//    return(-1);
//  }

	json_t *PoolsArr = json_object_get(Config, "pools");
	if(!PoolsArr || !json_array_size(PoolsArr))
	{
		Log(LOG_CRITICAL, "No pools specified for algorithm CryptoNight.");
		return(-1);
	}
	
	Settings->PoolURLs = (char **)malloc(sizeof(char *) * (json_array_size(PoolsArr) + 1));
	Settings->Workers = (WorkerInfo *)malloc(sizeof(WorkerInfo) * ((json_array_size(PoolsArr) + 1)));
	Settings->PoolCount = json_array_size(PoolsArr);
	
	for(int i = 0; i < Settings->PoolCount; ++i)
	{
		json_t *PoolObj = json_array_get(PoolsArr, i);
		json_t *PoolURL = json_object_get(PoolObj, "url");
		json_t *PoolUser = json_object_get(PoolObj, "user");
		json_t *PoolPass = json_object_get(PoolObj, "pass");
		
		if(!PoolURL || !PoolUser || !PoolPass)
		{
			Log(LOG_CRITICAL, "Pool structure %d for algo CryptoNight is missing an URL, username, or password.", i);
			return(-1);
		}
		
		Settings->PoolURLs[i] = (char *)malloc(sizeof(char) * (strlen(json_string_value(PoolURL)) + 1));
		Settings->Workers[i].User = (char *)malloc(sizeof(char) * (strlen(json_string_value(PoolUser)) + 1));
		Settings->Workers[i].Pass = (char *)malloc(sizeof(char) * (strlen(json_string_value(PoolPass)) + 1));
		
		strcpy(Settings->PoolURLs[i], json_string_value(PoolURL));
		strcpy(Settings->Workers[i].User, json_string_value(PoolUser));
		strcpy(Settings->Workers[i].Pass, json_string_value(PoolPass));
		
		Settings->Workers[i].NextWorker = NULL;
	}
	
	return(0);
}

void FreeSettings(Settings *Settings)
{
	for(int i = 0; i < Settings->PoolCount; ++i)
	{
		free(Settings->PoolURLs[i]);
		free(Settings->Workers[i].User);
		free(Settings->Workers[i].Pass);
	}
	
	free(Settings->PoolURLs);
	free(Settings->Workers);
}

// Only doing IPv4 for now.

// We should connect to the pool in the main thread,
// then give the socket to threads that need it, so
// that the connection may be cleanly closed.

// TODO: Get Platform index from somewhere else
// TODO/FIXME: Check functions called for error.
int main(int argc, char **argv)
{
  cpu_set_t cpuset;
	PoolInfo Pool = {0};
	Settings Settings;
	MinerThreadInfo *MThrInfo;
	int ret, poolsocket;
	pthread_t Stratum, BroadcastThread, *MinerWorker;

	InitLogging(LOG_INFO);
	
	if(argc != 2)
	{
		Log(LOG_CRITICAL, "Usage: %s <config file>", argv[0]);
		return(0);
	}
	
	if(ParseConfigurationFile(argv[1], &Settings)) return(0);
	
#ifdef __aarch64__
	cryptonight_hash_ctx = cryptonight_hash_aesni;
#else
	int use_aesni = 0;
	unsigned int tmp1, tmp2, tmp3, tmp4;

	if (__get_cpuid_max(0, &tmp1) >= 1) {
		__get_cpuid(1, &tmp1, &tmp2, &tmp3, &tmp4);
		if (tmp3 & 0x2000000)
			use_aesni = 1;
	}
	if (use_aesni)
		cryptonight_hash_ctx = cryptonight_hash_aesni;
	else
		cryptonight_hash_ctx = cryptonight_hash_dumb;
#endif

	MThrInfo = (MinerThreadInfo *)malloc(sizeof(MinerThreadInfo) * Settings.TotalThreads);
	MinerWorker = (pthread_t *)malloc(sizeof(pthread_t) * Settings.TotalThreads);
	
	#ifdef __linux__
	
	pipe(ExitPipe);
	struct sigaction ExitHandler;
	memset(&ExitHandler, 0, sizeof(struct sigaction));
	ExitHandler.sa_handler = SigHandler;
	
	sigaction(SIGINT, &ExitHandler, NULL);
	signal(SIGPIPE, SIG_IGN);
	
	#else
	
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)SigHandler, TRUE);
	
	#endif
	
	RestartMining = (atomic_bool *)malloc(sizeof(atomic_bool) * Settings.TotalThreads);
	
	char *TmpPort;
	uint32_t URLOffset;
	
	if(strstr(Settings.PoolURLs[0], "stratum+tcp://"))
		URLOffset = strlen("stratum+tcp://");
	else
		URLOffset = 0;
	
	if(strrchr(Settings.PoolURLs[0] + URLOffset, ':'))
		TmpPort = strrchr(Settings.PoolURLs[0] + URLOffset, ':') + 1;
	else
		TmpPort = "3333";
	
	char *StrippedPoolURL = (char *)malloc(sizeof(char) * (strlen(Settings.PoolURLs[0]) + 1));
	
	int URLSize = URLOffset;
	
	for(; Settings.PoolURLs[0][URLSize] != ':' && Settings.PoolURLs[0][URLSize]; ++URLSize)
		StrippedPoolURL[URLSize - URLOffset] = Settings.PoolURLs[0][URLSize];
	
	StrippedPoolURL[URLSize - URLOffset] = 0x00;
	
	Log(LOG_DEBUG, "Parsed pool URL: %s", StrippedPoolURL);
	
	ret = NetworkingInit();
	
	if(ret)
	{
		Log(LOG_CRITICAL, "Failed to initialize networking with error code %d.", ret);
		return(0);
	}
	
	
	// DO NOT FORGET THIS
	Pool.StrippedURL = strdup(StrippedPoolURL);
	Pool.Port = strdup(TmpPort);
	Pool.WorkerData = Settings.Workers[0];
	Pool.MinerThreadCount = Settings.TotalThreads;
	Pool.MinerThreads = (uint32_t *)malloc(sizeof(uint32_t) * Pool.MinerThreadCount);
	
	for(int i = 0; i < Settings.TotalThreads; ++i) Pool.MinerThreads[i] = -1;
	
	GlobalStatus.ThreadHashCounts = (double *)malloc(sizeof(double) * Settings.TotalThreads);
	GlobalStatus.ThreadTimes = (double *)malloc(sizeof(double) * Settings.TotalThreads);
	
	GlobalStatus.RejectedWork = 0;
	GlobalStatus.SolvedWork = 0;
	
	for(int i = 0; i < Settings.TotalThreads; ++i)
	{
		GlobalStatus.ThreadHashCounts[i] = 0;
		GlobalStatus.ThreadTimes[i] = 0;
	}
	
	for(int i = 0; i < Settings.TotalThreads; ++i) atomic_init(RestartMining + i, false);
	
  for(int x = 0; x < Settings.TotalThreads; ++x)
  {
    MThrInfo[x].ThreadID = x;
    MThrInfo[x].TotalMinerThreads = Settings.TotalThreads;
  }

	// TODO: Have ConnectToPool() return a Pool struct
	poolsocket = ConnectToPool(StrippedPoolURL, TmpPort);
	if(poolsocket == INVALID_SOCKET)
	{
		Log(LOG_CRITICAL, "Fatal error connecting to pool.");
		return(0);
	}
	Pool.sockfd = poolsocket;

	Log(LOG_NOTIFY, "Successfully connected to pool's stratum.");

	ret = pthread_create(&Stratum, NULL, StratumThreadProc, (void *)&Pool);
	if(ret)
	{
		printf("Failed to create Stratum thread.\n");
		return(0);
	}
  CPU_ZERO(&cpuset);
  CPU_SET(0, &cpuset);
  ret = pthread_setaffinity_np(Stratum, sizeof(cpu_set_t), &cpuset);
  if (ret != 0)
  {
    printf("Stratum: Affinity failed.\n");
    return(0);
  }


	// Wait until we've gotten work and filled
	// up the job structure before launching the
	// miner worker threads.
	for(;;)
	{
		if(CurrentJob) break;
		sleep(1);
	}
	
	// Work is ready - time to create the broadcast and miner threads
	pthread_create(&BroadcastThread, NULL, PoolBroadcastThreadProc, (void *)&Pool);
  CPU_ZERO(&cpuset);
  CPU_SET(0, &cpuset);
  ret = pthread_setaffinity_np(BroadcastThread, sizeof(cpu_set_t), &cpuset);
  if (ret != 0)
  {
    printf("Broadcast: Affinity failed.\n");
    return(0);
  }
	
	for(int i = 0; i < Settings.TotalThreads; ++i)
	{
		ret = pthread_create(MinerWorker + i, NULL, MinerThreadProc, MThrInfo + i);
		if(ret)
		{
			printf("Failed to create MinerWorker thread.\n");
			return(0);
		}
    int ncpu = i % sysconf(_SC_NPROCESSORS_ONLN);
    CPU_ZERO(&cpuset);
    CPU_SET(ncpu, &cpuset);
    ret = pthread_setaffinity_np(*(MinerWorker + i), sizeof(cpu_set_t), &cpuset);
    if (ret != 0)
    {
      printf("Miner[%d]: Affinity failed.\n", i);
      return(0);
    }
    else
      Log(LOG_INFO, "Miner[%d] on cpu%d", i, ncpu);
	}
	
	char c;
	read(ExitPipe[0], &c, 1);
	
	
#ifndef __ANDROID__
	for(int i = 0; i < Settings.TotalThreads; ++i) pthread_cancel(MinerWorker[i]);
#endif
	FreeSettings(&Settings);
	free(RestartMining);
	free(Pool.MinerThreads);
	closesocket(poolsocket);
	NetworkingShutdown();
	
	printf("Stratum thread terminated.\n");
	
	return(0);
}
// }}} Functions
