#ifndef __ST_PUBLISHER_H__
#define __ST_PUBLISHER_H__

#include "common_system.h"

#if USE_FUNCTIONAL
#include <functional>
#endif

namespace SwarmTalk {

class Publisher {
   public:
    int send(unsigned char* msg, int msgSize);
    void sent_callback();
    bool available();
    bool if_initialized();

    Publisher();

#if USE_FUNCTIONAL
    Publisher(void* chan, std::function<void()> callback);
    void publisher_init(void* chan, std::function<void()> callback);
#else
    Publisher(void* chan, void (*callback)());
    void publisher_init(void* chan, void (*callback)());
#endif

   private:
    void* chan;
#if USE_FUNCTIONAL
    std::function<void()> callback;
#else
    void (*callback)();
#endif
};

}  // namespace SwarmTalk

#endif