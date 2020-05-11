#ifndef __ST_SUBSCRIBER_H__
#define __ST_SUBSCRIBER_H__

#include <stddef.h>
#include <stdio.h>

#include "common_system.h"

#if USE_FUNCTIONAL
#include <functional>
#endif

namespace SwarmTalk {

class Subscriber {
   public:
    void receive(unsigned char *msg, int size, int hop, Meta_t *meta);
    bool if_initialized();

    Subscriber();

#if USE_FUNCTIONAL
    Subscriber(
        int dist,
        std::function<void(unsigned char *, int, int, Meta_t *)> callback);
    void subscriber_init(
        int dist,
        std::function<void(unsigned char *, int, int, Meta_t *)> callback);
#else
    Subscriber(int dist, void (*callback)(unsigned char *, int, int, Meta_t *));
    void subscriber_init(int dist,
                         void (*callback)(unsigned char *, int, int, Meta_t *));
#endif

   private:
    int dist;
#if USE_FUNCTIONAL
    std::function<void(unsigned char *, int, int, Meta_t *)> callback;
#else
    void (*callback)(unsigned char *, int, int, Meta_t *);
#endif
};

}  // namespace SwarmTalk

#endif