#ifndef __ST_SWARMTALK_H__
#define __ST_SWARMTALK_H__

#include "channel.h"
#include "common_system.h"
#include "packet.h"
#include "publisher.h"
#include "subscriber.h"

#if USE_FUNCTIONAL
#include <functional>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

namespace SwarmTalk {

class Swarmtalk {
   public:
    /* ---- user interfaces ---- */

    Channel* new_channel(int type, int hops, bool listen);

    /* ---- driver interfaces ---- */

    int next_pkt(unsigned char* pkt);
    void receive(unsigned char* pkt, int size, Meta_t* meta);
    void init();
    Common_system* get_common_sys();
    // void set_common_sys(Common_system* common_sys);

    /* ------- constructor ------- */

    Swarmtalk();
    ~Swarmtalk();

   private:
    Common_system common_sys;
    int nodeId;
    int forward_size;
    Packet forwardBuffer[FORWARD_BUFF_SIZE];
    int chan_num;
    Channel chans[TOTAL_CHAN_NUM];
    unsigned char send_cache[CACHE_SIZE][HEADER_BYTE];
    int cache_size;
    int roundRobinIndex;

    void new_id();
    bool check_cache(unsigned char* header);
    void add_cache(unsigned char* header);
};

}  // namespace SwarmTalk

#endif