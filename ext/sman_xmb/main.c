#include <sdk_version.h>
#include <cellstatus.h>
#include <cell/cell_fs.h>
#include <cell/rtc.h>
#include <cell/gcm.h>
#include <cell/pad.h>
#include <sys/vm.h>
#include <sysutil/sysutil_common.h>

#include <sys/prx.h>
#include <sys/ppu_thread.h>
#include <sys/event.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/memory.h>
#include <sys/timer.h>
#include <sys/process.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netex/net.h>
#include <netex/errno.h>
#include <netex/libnetctl.h>
#include <netex/sockinfo.h>

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "types.h"

SYS_MODULE_INFO(wm_proxy, 0, 1, 1);
SYS_MODULE_START(prx_start);
SYS_MODULE_STOP(prx_stop);
SYS_MODULE_EXIT(prx_stop);

int prx_start(size_t args, void *argp);
int prx_stop(void);

int strncmp(const char* s1, const char* s2, size_t n)
{
	if(n==0) return 0;
    while(*s1 && (*s1==*s2))
	{
        s1++,s2++;
		n--;
		if(n==0) break;
	}
    return *(const unsigned char*)s1-*(const unsigned char*)s2;
}

size_t strlen(const char *s) {
    const char *p = s;
    while (*s) ++s;
    return s - p;
}

static void * getNIDfunc(const char * vsh_module, uint32_t fnid)
{
	uint32_t table = (*(uint32_t*)0x1008C) + 0x984; // vsh table address

	while(((uint32_t)*(uint32_t*)table) != 0)
	{
		uint32_t* export_stru_ptr = (uint32_t*)*(uint32_t*)table;

		const char* lib_name_ptr =  (const char*)*(uint32_t*)((char*)export_stru_ptr + 0x10);

		if(strncmp(vsh_module, lib_name_ptr, strlen(lib_name_ptr))==0)
		{
			uint32_t lib_fnid_ptr = *(uint32_t*)((char*)export_stru_ptr + 0x14);
			uint32_t lib_func_ptr = *(uint32_t*)((char*)export_stru_ptr + 0x18);
			uint16_t count = *(uint16_t*)((char*)export_stru_ptr + 6); // number of exports
			for(int i=0;i<count;i++)
			{
				if(fnid == *(uint32_t*)((char*)lib_fnid_ptr + i*4))
				{
					return (void**)*((uint32_t*)(lib_func_ptr) + i);
				}
			}
		}
		table=table+4;
	}
	return 0;
}

static void wm_plugin_init (int view);
static int  wm_plugin_start(void * view);
static int  wm_plugin_stop (void);
static void wm_plugin_exit (void);
static void wm_plugin_action(const char * action);
int setInterface(unsigned int view);

static int (*vshtask_notify)(int, const char *);
static int (*plugin_SetInterface)(int view, int interface, void * Handler);
static int (*plugin_SetInterface2)(int view, int interface, void * Handler);

static void *wm_plugin_action_if[3] = {(void*)(wm_plugin_action), 0, 0};

static void wm_plugin_init (int view)		{plugin_SetInterface( view, 0x41435430 /*ACT0*/, wm_plugin_action_if);}
static int  wm_plugin_start(void * view)	{return SYS_PRX_START_OK;}
static int  wm_plugin_stop (void)			{return SYS_PRX_STOP_OK;}
static void wm_plugin_exit (void)			{return;}

static void *wm_plugin_functions[4] =
	{
		(void*)(wm_plugin_init),
		(int* )(wm_plugin_start),
		(int* )(wm_plugin_stop),
		(void*)(wm_plugin_exit)
	};


static int connect_to_webman(void)
{
	struct sockaddr_in sin;
	int s;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = 0x7F000001;	//127.0.0.1 (localhost)
	sin.sin_port = htons(80);			//http port (80)
	s = socket(AF_INET, SOCK_STREAM, 0);
	if(s < 0) return -1;

	struct timeval tv;
	tv.tv_usec = 0;
	tv.tv_sec = 3;

	setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	if(connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		return -1;

	return s;
}

static void wm_plugin_action(const char * action)
{
	int s = connect_to_webman();
	if(s >= 0)
	{
		char proxy_action[256];

		u32 i = 0;
		u32 pa = 0;

		proxy_action[pa++] = 'G';
		proxy_action[pa++] = 'E';
		proxy_action[pa++] = 'T';
		proxy_action[pa++] = ' ';

		if(action[0] != '/') i = 16;
		if(action[i] == '/')
		{
			for(;(i < strlen(action)) && (pa < 250); i++)
			{
				if(action[i] != 0x20)
					proxy_action[pa++] = action[i];
				else
				{
					proxy_action[pa++] = '%';
					proxy_action[pa++] = '2';
					proxy_action[pa++] = '0';
				}
			}

			proxy_action[pa++] = '\r';
			proxy_action[pa++] = '\n';
			proxy_action[pa] = 0;

			send(s, proxy_action, pa, 0);
		}
		else
			send(s, action, strlen(action), 0);

		shutdown(s, SHUT_RDWR);
		socketclose(s);
	}
	else vshtask_notify(0, (char*)"sMAN not ready!");
}

int prx_start(size_t args, void *argp)
{
	plugin_SetInterface		= (void*)((int)getNIDfunc("paf",0xA1DC401));
	plugin_SetInterface2	= (void*)((int)getNIDfunc("paf",0x3F7CB0BF));
	vshtask_notify			= (void*)((int)getNIDfunc("vshtask", 0xA02D46E7));

	plugin_SetInterface2(*(unsigned int*)argp, 1, (void*)wm_plugin_functions);
	return SYS_PRX_RESIDENT;
}


int prx_stop(void)
{
	return SYS_PRX_STOP_OK;
}
