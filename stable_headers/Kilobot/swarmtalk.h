

/**************************************************/
/********                                  ********/
/********         Start of macro.h         ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_MACRO_H__
#define __ST_MACRO_H__

#include "config.h"

#define BYTE 8U
#define HEADER_BYTE                                                           \
    ((NODE_ID_BITS + MSG_ID_BITS + SEQ_NUM_BITS + CHAN_TYPE_BITS + TTL_BITS + \
      1 + BYTE - 1) /                                                         \
     BYTE)
#define PAYLOAD_BYTE (PKT_SIZE - HEADER_BYTE - (WITH_CRC ? 1 : 0))
#define CRC_BYTE 1U
#define TIMER_BYTE \
    (TIMER_BITS % BYTE == 0 ? TIMER_BITS / BYTE : TIMER_BITS / BYTE + 1)

#define NODE_ID_MAX ((1U << NODE_ID_BITS) - 1)
#define MSG_ID_MAX ((1U << MSG_ID_BITS) - 1)
#define SEQ_NUM_MAX ((1U << SEQ_NUM_BITS) - 1)
#define CHAN_TYPE_MAX ((1U << CHAN_TYPE_BITS) - 1)
#define TTL_MAX ((1U << TTL_BITS) - 1)
#define TIMER_MAX ((1U << TIMER_BITS) - 1)

#define NODE_ID_OFFSET 0
#define MSG_ID_OFFSET (NODE_ID_OFFSET + NODE_ID_BITS)
#define SEQ_NUM_OFFSET (MSG_ID_OFFSET + MSG_ID_BITS)
#define IF_END_OFFSET (SEQ_NUM_OFFSET + SEQ_NUM_BITS)
#define CHAN_TYPE_OFFSET (IF_END_OFFSET + 1)
#define TTL_OFFSET (CHAN_TYPE_OFFSET + CHAN_TYPE_BITS)

#define MAX_PKT_PER_MSG (SEQ_NUM_MAX + 1)

#define SINGLE_PKT_MEM (HEADER_BYTE + PAYLOAD_BYTE + 1)
#define BUFF_MEM_USAGE                                                 \
    ((BUFF_SIZE_PER_CHAN * TOTAL_CHAN_NUM + FORWARD_BUFF_SIZE * PKT) * \
     PKT_MEM_USAGE)
#define CACHE_MEM_USAGE (CACHE_SIZE * HEADER_BYTE)
#define TOTAL_MEM_USAGE (BUFF_MEM_USAGE + CACHE_MEM_USAGE)

#if DEBUG
#define SWARM_LOG(...)         \
    printf("(%s) ", __func__); \
    printf(__VA_ARGS__);       \
    printf("\r\n");
#else
#define SWARM_LOG(...)
#endif

#endif

/**************************************************/
/********                                  ********/
/********          End of macro.h          ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********          Start of util.h         ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_UTIL_H__
#define __ST_UTIL_H__

#include <stdlib.h>


namespace SwarmTalk {

namespace common {

unsigned int decode(unsigned char* header, unsigned int offset,
                    unsigned int len) {
    unsigned int ret = 0;
    unsigned int end_bit = offset + len - 1;
    unsigned int cur_index = offset / BYTE;
    unsigned int end_index = end_bit / BYTE;
    unsigned char mask;
    unsigned int front, rear;
    // printf("start bit: %d; end bit: %d; start index: %d; end index: %d\n",
    // offset, end_bit, cur_index, end_index);
    while (cur_index <= end_index) {
        front = offset - cur_index * BYTE;
        if (cur_index == end_index) {
            ret = ret << (end_bit - offset + 1);
            rear = (cur_index + 1) * BYTE - 1 - end_bit;
        } else {
            ret = ret << ((cur_index + 1) * BYTE - offset);
            rear = 0;
        }
        mask = ((0xFF >> front) >> rear) << rear;
        ret = ret + ((header[cur_index] & mask) >> rear);
        cur_index++;
        offset = cur_index * BYTE;
        // printf("ret = %d\n", ret);
    }

    return ret;
}

void encode(unsigned char* header, unsigned int offset, unsigned int len,
            unsigned int data) {
    int end_bit = offset + len - 1;
    int start_index = offset / BYTE;
    int cur_index = end_bit / BYTE;
    unsigned char mask;
    int front, rear;
    while (cur_index >= start_index) {
        rear = (cur_index + 1) * BYTE - 1 - end_bit;
        if (cur_index == start_index) {
            front = offset - start_index * BYTE;
        } else {
            front = 0;
        }
        mask = ((0xFF >> front) >> rear) << rear;
        header[cur_index] = header[cur_index] & ((unsigned char)~mask);
        header[cur_index] =
            header[cur_index] +
            ((data & (~(0xFF << (BYTE - front - rear)))) << rear);
        data = data >> (BYTE - front - rear);
        cur_index--;
        end_bit = (cur_index + 1) * BYTE - 1;
    }
}

unsigned int clock_diff(unsigned int start, unsigned int end) {
    if (start > end) {
        // based on assumption that if start overflows, end won't overflow
        // assuming the msg processing won't take as long as entire clock
        // overflow
        end = end + TIMER_MAX;
    }
    return end - start;
}

void dummy_lock() {}

unsigned int dummy_clock() { return 0; }

unsigned int dummy_rand_func() { return rand(); }

}  // namespace common

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********           End of util.h          ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********     Start of common_system.h     ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_COMMON_SYSTEM_H__
#define __ST_COMMON_SYSTEM_H__


#if USE_FUNCTIONAL
#include <functional>
#endif

namespace SwarmTalk {

class Common_system {
   public:
    unsigned int get_clock();
    unsigned int random_func();
    void lock();
    void unlock();
    void execute_loop();
    void register_control_factory(void* control_factory);

#if USE_FUNCTIONAL
    void register_user_loop(std::function<void()> user_loop);
    void set_common_sys_get_clock(std::function<unsigned int()> get_clock);
    void set_common_sys_random_func(std::function<unsigned int()> random_func);
    void set_common_sys_lock(std::function<void()> lock);
    void set_common_sys_unlock(std::function<void()> unlock);
#else
    void register_user_loop(void (*user_loop)());
    void set_common_sys_get_clock(unsigned int (*get_clock)());
    void set_common_sys_random_func(unsigned int (*random_func)());
    void set_common_sys_lock(void (*lock)());
    void set_common_sys_unlock(void (*unlock)());
#endif

    Common_system();

   private:
    void* control_factory;
#if USE_FUNCTIONAL
    std::function<void()> user_loop;
    std::function<unsigned int()> common_get_clock;
    std::function<void()> common_lock;
    std::function<void()> common_unlock;
    std::function<unsigned int()> common_random_func;
#else
    void (*user_loop)();
    void (*common_lock)();
    void (*common_unlock)();
    unsigned int (*common_get_clock)();
    unsigned int (*common_random_func)();
#endif
};

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********      End of common_system.h      ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********         Start of macro.h         ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_MACRO_H__
#define __ST_MACRO_H__

#include "config.h"

#define BYTE 8U
#define HEADER_BYTE                                                           \
    ((NODE_ID_BITS + MSG_ID_BITS + SEQ_NUM_BITS + CHAN_TYPE_BITS + TTL_BITS + \
      1 + BYTE - 1) /                                                         \
     BYTE)
#define PAYLOAD_BYTE (PKT_SIZE - HEADER_BYTE - (WITH_CRC ? 1 : 0))
#define CRC_BYTE 1U
#define TIMER_BYTE \
    (TIMER_BITS % BYTE == 0 ? TIMER_BITS / BYTE : TIMER_BITS / BYTE + 1)

#define NODE_ID_MAX ((1U << NODE_ID_BITS) - 1)
#define MSG_ID_MAX ((1U << MSG_ID_BITS) - 1)
#define SEQ_NUM_MAX ((1U << SEQ_NUM_BITS) - 1)
#define CHAN_TYPE_MAX ((1U << CHAN_TYPE_BITS) - 1)
#define TTL_MAX ((1U << TTL_BITS) - 1)
#define TIMER_MAX ((1U << TIMER_BITS) - 1)

#define NODE_ID_OFFSET 0
#define MSG_ID_OFFSET (NODE_ID_OFFSET + NODE_ID_BITS)
#define SEQ_NUM_OFFSET (MSG_ID_OFFSET + MSG_ID_BITS)
#define IF_END_OFFSET (SEQ_NUM_OFFSET + SEQ_NUM_BITS)
#define CHAN_TYPE_OFFSET (IF_END_OFFSET + 1)
#define TTL_OFFSET (CHAN_TYPE_OFFSET + CHAN_TYPE_BITS)

#define MAX_PKT_PER_MSG (SEQ_NUM_MAX + 1)

#define SINGLE_PKT_MEM (HEADER_BYTE + PAYLOAD_BYTE + 1)
#define BUFF_MEM_USAGE                                                 \
    ((BUFF_SIZE_PER_CHAN * TOTAL_CHAN_NUM + FORWARD_BUFF_SIZE * PKT) * \
     PKT_MEM_USAGE)
#define CACHE_MEM_USAGE (CACHE_SIZE * HEADER_BYTE)
#define TOTAL_MEM_USAGE (BUFF_MEM_USAGE + CACHE_MEM_USAGE)

#if DEBUG
#define SWARM_LOG(...)         \
    printf("(%s) ", __func__); \
    printf(__VA_ARGS__);       \
    printf("\r\n");
#else
#define SWARM_LOG(...)
#endif

#endif

/**************************************************/
/********                                  ********/
/********          End of macro.h          ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********          Start of util.h         ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_UTIL_H__
#define __ST_UTIL_H__

#include <stdlib.h>


namespace SwarmTalk {

namespace common {

unsigned int decode(unsigned char* header, unsigned int offset,
                    unsigned int len) {
    unsigned int ret = 0;
    unsigned int end_bit = offset + len - 1;
    unsigned int cur_index = offset / BYTE;
    unsigned int end_index = end_bit / BYTE;
    unsigned char mask;
    unsigned int front, rear;
    // printf("start bit: %d; end bit: %d; start index: %d; end index: %d\n",
    // offset, end_bit, cur_index, end_index);
    while (cur_index <= end_index) {
        front = offset - cur_index * BYTE;
        if (cur_index == end_index) {
            ret = ret << (end_bit - offset + 1);
            rear = (cur_index + 1) * BYTE - 1 - end_bit;
        } else {
            ret = ret << ((cur_index + 1) * BYTE - offset);
            rear = 0;
        }
        mask = ((0xFF >> front) >> rear) << rear;
        ret = ret + ((header[cur_index] & mask) >> rear);
        cur_index++;
        offset = cur_index * BYTE;
        // printf("ret = %d\n", ret);
    }

    return ret;
}

void encode(unsigned char* header, unsigned int offset, unsigned int len,
            unsigned int data) {
    int end_bit = offset + len - 1;
    int start_index = offset / BYTE;
    int cur_index = end_bit / BYTE;
    unsigned char mask;
    int front, rear;
    while (cur_index >= start_index) {
        rear = (cur_index + 1) * BYTE - 1 - end_bit;
        if (cur_index == start_index) {
            front = offset - start_index * BYTE;
        } else {
            front = 0;
        }
        mask = ((0xFF >> front) >> rear) << rear;
        header[cur_index] = header[cur_index] & ((unsigned char)~mask);
        header[cur_index] =
            header[cur_index] +
            ((data & (~(0xFF << (BYTE - front - rear)))) << rear);
        data = data >> (BYTE - front - rear);
        cur_index--;
        end_bit = (cur_index + 1) * BYTE - 1;
    }
}

unsigned int clock_diff(unsigned int start, unsigned int end) {
    if (start > end) {
        // based on assumption that if start overflows, end won't overflow
        // assuming the msg processing won't take as long as entire clock
        // overflow
        end = end + TIMER_MAX;
    }
    return end - start;
}

void dummy_lock() {}

unsigned int dummy_clock() { return 0; }

unsigned int dummy_rand_func() { return rand(); }

}  // namespace common

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********           End of util.h          ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********     Start of common_system.h     ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_COMMON_SYSTEM_H__
#define __ST_COMMON_SYSTEM_H__


#if USE_FUNCTIONAL
#include <functional>
#endif

namespace SwarmTalk {

class Common_system {
   public:
    unsigned int get_clock();
    unsigned int random_func();
    void lock();
    void unlock();
    void execute_loop();
    void register_control_factory(void* control_factory);

#if USE_FUNCTIONAL
    void register_user_loop(std::function<void()> user_loop);
    void set_common_sys_get_clock(std::function<unsigned int()> get_clock);
    void set_common_sys_random_func(std::function<unsigned int()> random_func);
    void set_common_sys_lock(std::function<void()> lock);
    void set_common_sys_unlock(std::function<void()> unlock);
#else
    void register_user_loop(void (*user_loop)());
    void set_common_sys_get_clock(unsigned int (*get_clock)());
    void set_common_sys_random_func(unsigned int (*random_func)());
    void set_common_sys_lock(void (*lock)());
    void set_common_sys_unlock(void (*unlock)());
#endif

    Common_system();

   private:
    void* control_factory;
#if USE_FUNCTIONAL
    std::function<void()> user_loop;
    std::function<unsigned int()> common_get_clock;
    std::function<void()> common_lock;
    std::function<void()> common_unlock;
    std::function<unsigned int()> common_random_func;
#else
    void (*user_loop)();
    void (*common_lock)();
    void (*common_unlock)();
    unsigned int (*common_get_clock)();
    unsigned int (*common_random_func)();
#endif
};

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********      End of common_system.h      ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********         Start of packet.h        ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_PACKET_H__
#define __ST_PACKET_H__

#include <stdint.h>


namespace SwarmTalk {

class Packet {
   public:
    void init(unsigned char *pkt);
    void init(unsigned char *content, int size, unsigned int nodeId,
              unsigned int msgId, unsigned int seqNum, bool ifEnd,
              unsigned int chanNum, unsigned int ttl);

    int to_packet(unsigned char *pkt);
    unsigned char *get_content();
    void set_node_id(unsigned int id);
    void print_data();
    void decrease_hop();
    void set_time_bytes(unsigned int time);
    unsigned int get_node_id();
    unsigned int get_msg_id();
    unsigned int get_seq_num();
    unsigned int get_chan_type();
    unsigned int get_ttl();
    unsigned int get_pay_size();
    bool get_if_end();
    bool if_valid();
    unsigned int get_time_bytes();

    Packet();
    Packet(unsigned char *pkt);
    Packet(unsigned char *content, int size, unsigned int nodeId,
           unsigned int msgId, unsigned int seqNum, bool ifEnd,
           unsigned int chanNum, unsigned int ttl);
    ~Packet();

   private:
#if WITH_CRC
    unsigned char content[PKT_SIZE - HEADER_BYTE - CRC_BYTE];
#else
    unsigned char content[PKT_SIZE - HEADER_BYTE];
#endif
    unsigned char header[HEADER_BYTE];
    bool valid;

    unsigned char crc_check(unsigned char *pkt, int size, int in_crc);
    unsigned char crc(unsigned char *pkt, int size);
};

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********          End of packet.h         ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********         Start of macro.h         ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_MACRO_H__
#define __ST_MACRO_H__

#include "config.h"

#define BYTE 8U
#define HEADER_BYTE                                                           \
    ((NODE_ID_BITS + MSG_ID_BITS + SEQ_NUM_BITS + CHAN_TYPE_BITS + TTL_BITS + \
      1 + BYTE - 1) /                                                         \
     BYTE)
#define PAYLOAD_BYTE (PKT_SIZE - HEADER_BYTE - (WITH_CRC ? 1 : 0))
#define CRC_BYTE 1U
#define TIMER_BYTE \
    (TIMER_BITS % BYTE == 0 ? TIMER_BITS / BYTE : TIMER_BITS / BYTE + 1)

#define NODE_ID_MAX ((1U << NODE_ID_BITS) - 1)
#define MSG_ID_MAX ((1U << MSG_ID_BITS) - 1)
#define SEQ_NUM_MAX ((1U << SEQ_NUM_BITS) - 1)
#define CHAN_TYPE_MAX ((1U << CHAN_TYPE_BITS) - 1)
#define TTL_MAX ((1U << TTL_BITS) - 1)
#define TIMER_MAX ((1U << TIMER_BITS) - 1)

#define NODE_ID_OFFSET 0
#define MSG_ID_OFFSET (NODE_ID_OFFSET + NODE_ID_BITS)
#define SEQ_NUM_OFFSET (MSG_ID_OFFSET + MSG_ID_BITS)
#define IF_END_OFFSET (SEQ_NUM_OFFSET + SEQ_NUM_BITS)
#define CHAN_TYPE_OFFSET (IF_END_OFFSET + 1)
#define TTL_OFFSET (CHAN_TYPE_OFFSET + CHAN_TYPE_BITS)

#define MAX_PKT_PER_MSG (SEQ_NUM_MAX + 1)

#define SINGLE_PKT_MEM (HEADER_BYTE + PAYLOAD_BYTE + 1)
#define BUFF_MEM_USAGE                                                 \
    ((BUFF_SIZE_PER_CHAN * TOTAL_CHAN_NUM + FORWARD_BUFF_SIZE * PKT) * \
     PKT_MEM_USAGE)
#define CACHE_MEM_USAGE (CACHE_SIZE * HEADER_BYTE)
#define TOTAL_MEM_USAGE (BUFF_MEM_USAGE + CACHE_MEM_USAGE)

#if DEBUG
#define SWARM_LOG(...)         \
    printf("(%s) ", __func__); \
    printf(__VA_ARGS__);       \
    printf("\r\n");
#else
#define SWARM_LOG(...)
#endif

#endif

/**************************************************/
/********                                  ********/
/********          End of macro.h          ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********          Start of util.h         ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_UTIL_H__
#define __ST_UTIL_H__

#include <stdlib.h>


namespace SwarmTalk {

namespace common {

unsigned int decode(unsigned char* header, unsigned int offset,
                    unsigned int len) {
    unsigned int ret = 0;
    unsigned int end_bit = offset + len - 1;
    unsigned int cur_index = offset / BYTE;
    unsigned int end_index = end_bit / BYTE;
    unsigned char mask;
    unsigned int front, rear;
    // printf("start bit: %d; end bit: %d; start index: %d; end index: %d\n",
    // offset, end_bit, cur_index, end_index);
    while (cur_index <= end_index) {
        front = offset - cur_index * BYTE;
        if (cur_index == end_index) {
            ret = ret << (end_bit - offset + 1);
            rear = (cur_index + 1) * BYTE - 1 - end_bit;
        } else {
            ret = ret << ((cur_index + 1) * BYTE - offset);
            rear = 0;
        }
        mask = ((0xFF >> front) >> rear) << rear;
        ret = ret + ((header[cur_index] & mask) >> rear);
        cur_index++;
        offset = cur_index * BYTE;
        // printf("ret = %d\n", ret);
    }

    return ret;
}

void encode(unsigned char* header, unsigned int offset, unsigned int len,
            unsigned int data) {
    int end_bit = offset + len - 1;
    int start_index = offset / BYTE;
    int cur_index = end_bit / BYTE;
    unsigned char mask;
    int front, rear;
    while (cur_index >= start_index) {
        rear = (cur_index + 1) * BYTE - 1 - end_bit;
        if (cur_index == start_index) {
            front = offset - start_index * BYTE;
        } else {
            front = 0;
        }
        mask = ((0xFF >> front) >> rear) << rear;
        header[cur_index] = header[cur_index] & ((unsigned char)~mask);
        header[cur_index] =
            header[cur_index] +
            ((data & (~(0xFF << (BYTE - front - rear)))) << rear);
        data = data >> (BYTE - front - rear);
        cur_index--;
        end_bit = (cur_index + 1) * BYTE - 1;
    }
}

unsigned int clock_diff(unsigned int start, unsigned int end) {
    if (start > end) {
        // based on assumption that if start overflows, end won't overflow
        // assuming the msg processing won't take as long as entire clock
        // overflow
        end = end + TIMER_MAX;
    }
    return end - start;
}

void dummy_lock() {}

unsigned int dummy_clock() { return 0; }

unsigned int dummy_rand_func() { return rand(); }

}  // namespace common

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********           End of util.h          ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********     Start of common_system.h     ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_COMMON_SYSTEM_H__
#define __ST_COMMON_SYSTEM_H__


#if USE_FUNCTIONAL
#include <functional>
#endif

namespace SwarmTalk {

class Common_system {
   public:
    unsigned int get_clock();
    unsigned int random_func();
    void lock();
    void unlock();
    void execute_loop();
    void register_control_factory(void* control_factory);

#if USE_FUNCTIONAL
    void register_user_loop(std::function<void()> user_loop);
    void set_common_sys_get_clock(std::function<unsigned int()> get_clock);
    void set_common_sys_random_func(std::function<unsigned int()> random_func);
    void set_common_sys_lock(std::function<void()> lock);
    void set_common_sys_unlock(std::function<void()> unlock);
#else
    void register_user_loop(void (*user_loop)());
    void set_common_sys_get_clock(unsigned int (*get_clock)());
    void set_common_sys_random_func(unsigned int (*random_func)());
    void set_common_sys_lock(void (*lock)());
    void set_common_sys_unlock(void (*unlock)());
#endif

    Common_system();

   private:
    void* control_factory;
#if USE_FUNCTIONAL
    std::function<void()> user_loop;
    std::function<unsigned int()> common_get_clock;
    std::function<void()> common_lock;
    std::function<void()> common_unlock;
    std::function<unsigned int()> common_random_func;
#else
    void (*user_loop)();
    void (*common_lock)();
    void (*common_unlock)();
    unsigned int (*common_get_clock)();
    unsigned int (*common_random_func)();
#endif
};

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********      End of common_system.h      ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********       Start of publisher.h       ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_PUBLISHER_H__
#define __ST_PUBLISHER_H__


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

/**************************************************/
/********                                  ********/
/********        End of publisher.h        ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********         Start of macro.h         ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_MACRO_H__
#define __ST_MACRO_H__

#include "config.h"

#define BYTE 8U
#define HEADER_BYTE                                                           \
    ((NODE_ID_BITS + MSG_ID_BITS + SEQ_NUM_BITS + CHAN_TYPE_BITS + TTL_BITS + \
      1 + BYTE - 1) /                                                         \
     BYTE)
#define PAYLOAD_BYTE (PKT_SIZE - HEADER_BYTE - (WITH_CRC ? 1 : 0))
#define CRC_BYTE 1U
#define TIMER_BYTE \
    (TIMER_BITS % BYTE == 0 ? TIMER_BITS / BYTE : TIMER_BITS / BYTE + 1)

#define NODE_ID_MAX ((1U << NODE_ID_BITS) - 1)
#define MSG_ID_MAX ((1U << MSG_ID_BITS) - 1)
#define SEQ_NUM_MAX ((1U << SEQ_NUM_BITS) - 1)
#define CHAN_TYPE_MAX ((1U << CHAN_TYPE_BITS) - 1)
#define TTL_MAX ((1U << TTL_BITS) - 1)
#define TIMER_MAX ((1U << TIMER_BITS) - 1)

#define NODE_ID_OFFSET 0
#define MSG_ID_OFFSET (NODE_ID_OFFSET + NODE_ID_BITS)
#define SEQ_NUM_OFFSET (MSG_ID_OFFSET + MSG_ID_BITS)
#define IF_END_OFFSET (SEQ_NUM_OFFSET + SEQ_NUM_BITS)
#define CHAN_TYPE_OFFSET (IF_END_OFFSET + 1)
#define TTL_OFFSET (CHAN_TYPE_OFFSET + CHAN_TYPE_BITS)

#define MAX_PKT_PER_MSG (SEQ_NUM_MAX + 1)

#define SINGLE_PKT_MEM (HEADER_BYTE + PAYLOAD_BYTE + 1)
#define BUFF_MEM_USAGE                                                 \
    ((BUFF_SIZE_PER_CHAN * TOTAL_CHAN_NUM + FORWARD_BUFF_SIZE * PKT) * \
     PKT_MEM_USAGE)
#define CACHE_MEM_USAGE (CACHE_SIZE * HEADER_BYTE)
#define TOTAL_MEM_USAGE (BUFF_MEM_USAGE + CACHE_MEM_USAGE)

#if DEBUG
#define SWARM_LOG(...)         \
    printf("(%s) ", __func__); \
    printf(__VA_ARGS__);       \
    printf("\r\n");
#else
#define SWARM_LOG(...)
#endif

#endif

/**************************************************/
/********                                  ********/
/********          End of macro.h          ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********          Start of util.h         ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_UTIL_H__
#define __ST_UTIL_H__

#include <stdlib.h>


namespace SwarmTalk {

namespace common {

unsigned int decode(unsigned char* header, unsigned int offset,
                    unsigned int len) {
    unsigned int ret = 0;
    unsigned int end_bit = offset + len - 1;
    unsigned int cur_index = offset / BYTE;
    unsigned int end_index = end_bit / BYTE;
    unsigned char mask;
    unsigned int front, rear;
    // printf("start bit: %d; end bit: %d; start index: %d; end index: %d\n",
    // offset, end_bit, cur_index, end_index);
    while (cur_index <= end_index) {
        front = offset - cur_index * BYTE;
        if (cur_index == end_index) {
            ret = ret << (end_bit - offset + 1);
            rear = (cur_index + 1) * BYTE - 1 - end_bit;
        } else {
            ret = ret << ((cur_index + 1) * BYTE - offset);
            rear = 0;
        }
        mask = ((0xFF >> front) >> rear) << rear;
        ret = ret + ((header[cur_index] & mask) >> rear);
        cur_index++;
        offset = cur_index * BYTE;
        // printf("ret = %d\n", ret);
    }

    return ret;
}

void encode(unsigned char* header, unsigned int offset, unsigned int len,
            unsigned int data) {
    int end_bit = offset + len - 1;
    int start_index = offset / BYTE;
    int cur_index = end_bit / BYTE;
    unsigned char mask;
    int front, rear;
    while (cur_index >= start_index) {
        rear = (cur_index + 1) * BYTE - 1 - end_bit;
        if (cur_index == start_index) {
            front = offset - start_index * BYTE;
        } else {
            front = 0;
        }
        mask = ((0xFF >> front) >> rear) << rear;
        header[cur_index] = header[cur_index] & ((unsigned char)~mask);
        header[cur_index] =
            header[cur_index] +
            ((data & (~(0xFF << (BYTE - front - rear)))) << rear);
        data = data >> (BYTE - front - rear);
        cur_index--;
        end_bit = (cur_index + 1) * BYTE - 1;
    }
}

unsigned int clock_diff(unsigned int start, unsigned int end) {
    if (start > end) {
        // based on assumption that if start overflows, end won't overflow
        // assuming the msg processing won't take as long as entire clock
        // overflow
        end = end + TIMER_MAX;
    }
    return end - start;
}

void dummy_lock() {}

unsigned int dummy_clock() { return 0; }

unsigned int dummy_rand_func() { return rand(); }

}  // namespace common

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********           End of util.h          ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********     Start of common_system.h     ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_COMMON_SYSTEM_H__
#define __ST_COMMON_SYSTEM_H__


#if USE_FUNCTIONAL
#include <functional>
#endif

namespace SwarmTalk {

class Common_system {
   public:
    unsigned int get_clock();
    unsigned int random_func();
    void lock();
    void unlock();
    void execute_loop();
    void register_control_factory(void* control_factory);

#if USE_FUNCTIONAL
    void register_user_loop(std::function<void()> user_loop);
    void set_common_sys_get_clock(std::function<unsigned int()> get_clock);
    void set_common_sys_random_func(std::function<unsigned int()> random_func);
    void set_common_sys_lock(std::function<void()> lock);
    void set_common_sys_unlock(std::function<void()> unlock);
#else
    void register_user_loop(void (*user_loop)());
    void set_common_sys_get_clock(unsigned int (*get_clock)());
    void set_common_sys_random_func(unsigned int (*random_func)());
    void set_common_sys_lock(void (*lock)());
    void set_common_sys_unlock(void (*unlock)());
#endif

    Common_system();

   private:
    void* control_factory;
#if USE_FUNCTIONAL
    std::function<void()> user_loop;
    std::function<unsigned int()> common_get_clock;
    std::function<void()> common_lock;
    std::function<void()> common_unlock;
    std::function<unsigned int()> common_random_func;
#else
    void (*user_loop)();
    void (*common_lock)();
    void (*common_unlock)();
    unsigned int (*common_get_clock)();
    unsigned int (*common_random_func)();
#endif
};

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********      End of common_system.h      ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********       Start of subscriber.h      ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_SUBSCRIBER_H__
#define __ST_SUBSCRIBER_H__

#include <stddef.h>
#include <stdio.h>


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

/**************************************************/
/********                                  ********/
/********        End of subscriber.h       ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********        Start of channel.h        ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_CHANNEL_H__
#define __ST_CHANNEL_H__

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#if USE_FUNCTIONAL
#include <functional>
#endif

#define DUMMY_ID 0
#define MAX_BUFF 8
#define MAX_MSG_ID 16

#define ERROR_NOT_READY 1
#define ERROR_TOO_LONG 2
#define SUCCESS 0
#define ERROR_FULL 1
#define ERROR_EMPTY 1

namespace SwarmTalk {

class Channel {
   public:
    void init(int type, int hops, bool listen);
    int send(unsigned char *msg, int msgSize);

#if USE_FUNCTIONAL
    Subscriber *new_subscriber(
        int dist,
        std::function<void(unsigned char *, int, int, Meta_t *)> callback);
    Publisher *new_publisher(std::function<void()> callback);
#else
    Subscriber *new_subscriber(int dist, void (*callback)(unsigned char *, int,
                                                          int, Meta_t *));
    Publisher *new_publisher(void (*callback)());
#endif

    bool available();
    bool overflow_status();
    int next_pkt(Packet *ret);
    void receive(Packet *newPkt, Meta_t *meta);
    int get_type();

    void print_channel_status();

    Channel();
    Channel(int type, int hops, bool time_chan);
    ~Channel();

    void set_common_sys(Common_system *common_sys);

   private:
    Common_system *common_sys;
    int type;
    int hops;
    bool time_chan;
    int send_index;
    int send_pktNum;
    int recv_pktNum;
    bool ready;
    Publisher publishers[MAX_PUB_PER_CHAN];
    Subscriber subscribers[MAX_SUB_PER_CHAN];
    Packet recvBuffer[BUFF_SIZE_PER_CHAN];
    Packet sendBuffer[MAX_PKT_PER_MSG];
    int assembler[MAX_PKT_PER_MSG];
    int overflowCounter;
    bool overflowFlag;
    void try_merge(int nodeId, int msgId, int hopCount, Meta_t *meta);
};

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********         End of channel.h         ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********         Start of macro.h         ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_MACRO_H__
#define __ST_MACRO_H__

#include "config.h"

#define BYTE 8U
#define HEADER_BYTE                                                           \
    ((NODE_ID_BITS + MSG_ID_BITS + SEQ_NUM_BITS + CHAN_TYPE_BITS + TTL_BITS + \
      1 + BYTE - 1) /                                                         \
     BYTE)
#define PAYLOAD_BYTE (PKT_SIZE - HEADER_BYTE - (WITH_CRC ? 1 : 0))
#define CRC_BYTE 1U
#define TIMER_BYTE \
    (TIMER_BITS % BYTE == 0 ? TIMER_BITS / BYTE : TIMER_BITS / BYTE + 1)

#define NODE_ID_MAX ((1U << NODE_ID_BITS) - 1)
#define MSG_ID_MAX ((1U << MSG_ID_BITS) - 1)
#define SEQ_NUM_MAX ((1U << SEQ_NUM_BITS) - 1)
#define CHAN_TYPE_MAX ((1U << CHAN_TYPE_BITS) - 1)
#define TTL_MAX ((1U << TTL_BITS) - 1)
#define TIMER_MAX ((1U << TIMER_BITS) - 1)

#define NODE_ID_OFFSET 0
#define MSG_ID_OFFSET (NODE_ID_OFFSET + NODE_ID_BITS)
#define SEQ_NUM_OFFSET (MSG_ID_OFFSET + MSG_ID_BITS)
#define IF_END_OFFSET (SEQ_NUM_OFFSET + SEQ_NUM_BITS)
#define CHAN_TYPE_OFFSET (IF_END_OFFSET + 1)
#define TTL_OFFSET (CHAN_TYPE_OFFSET + CHAN_TYPE_BITS)

#define MAX_PKT_PER_MSG (SEQ_NUM_MAX + 1)

#define SINGLE_PKT_MEM (HEADER_BYTE + PAYLOAD_BYTE + 1)
#define BUFF_MEM_USAGE                                                 \
    ((BUFF_SIZE_PER_CHAN * TOTAL_CHAN_NUM + FORWARD_BUFF_SIZE * PKT) * \
     PKT_MEM_USAGE)
#define CACHE_MEM_USAGE (CACHE_SIZE * HEADER_BYTE)
#define TOTAL_MEM_USAGE (BUFF_MEM_USAGE + CACHE_MEM_USAGE)

#if DEBUG
#define SWARM_LOG(...)         \
    printf("(%s) ", __func__); \
    printf(__VA_ARGS__);       \
    printf("\r\n");
#else
#define SWARM_LOG(...)
#endif

#endif

/**************************************************/
/********                                  ********/
/********          End of macro.h          ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********          Start of util.h         ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_UTIL_H__
#define __ST_UTIL_H__

#include <stdlib.h>


namespace SwarmTalk {

namespace common {

unsigned int decode(unsigned char* header, unsigned int offset,
                    unsigned int len) {
    unsigned int ret = 0;
    unsigned int end_bit = offset + len - 1;
    unsigned int cur_index = offset / BYTE;
    unsigned int end_index = end_bit / BYTE;
    unsigned char mask;
    unsigned int front, rear;
    // printf("start bit: %d; end bit: %d; start index: %d; end index: %d\n",
    // offset, end_bit, cur_index, end_index);
    while (cur_index <= end_index) {
        front = offset - cur_index * BYTE;
        if (cur_index == end_index) {
            ret = ret << (end_bit - offset + 1);
            rear = (cur_index + 1) * BYTE - 1 - end_bit;
        } else {
            ret = ret << ((cur_index + 1) * BYTE - offset);
            rear = 0;
        }
        mask = ((0xFF >> front) >> rear) << rear;
        ret = ret + ((header[cur_index] & mask) >> rear);
        cur_index++;
        offset = cur_index * BYTE;
        // printf("ret = %d\n", ret);
    }

    return ret;
}

void encode(unsigned char* header, unsigned int offset, unsigned int len,
            unsigned int data) {
    int end_bit = offset + len - 1;
    int start_index = offset / BYTE;
    int cur_index = end_bit / BYTE;
    unsigned char mask;
    int front, rear;
    while (cur_index >= start_index) {
        rear = (cur_index + 1) * BYTE - 1 - end_bit;
        if (cur_index == start_index) {
            front = offset - start_index * BYTE;
        } else {
            front = 0;
        }
        mask = ((0xFF >> front) >> rear) << rear;
        header[cur_index] = header[cur_index] & ((unsigned char)~mask);
        header[cur_index] =
            header[cur_index] +
            ((data & (~(0xFF << (BYTE - front - rear)))) << rear);
        data = data >> (BYTE - front - rear);
        cur_index--;
        end_bit = (cur_index + 1) * BYTE - 1;
    }
}

unsigned int clock_diff(unsigned int start, unsigned int end) {
    if (start > end) {
        // based on assumption that if start overflows, end won't overflow
        // assuming the msg processing won't take as long as entire clock
        // overflow
        end = end + TIMER_MAX;
    }
    return end - start;
}

void dummy_lock() {}

unsigned int dummy_clock() { return 0; }

unsigned int dummy_rand_func() { return rand(); }

}  // namespace common

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********           End of util.h          ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********     Start of common_system.h     ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_COMMON_SYSTEM_H__
#define __ST_COMMON_SYSTEM_H__


#if USE_FUNCTIONAL
#include <functional>
#endif

namespace SwarmTalk {

class Common_system {
   public:
    unsigned int get_clock();
    unsigned int random_func();
    void lock();
    void unlock();
    void execute_loop();
    void register_control_factory(void* control_factory);

#if USE_FUNCTIONAL
    void register_user_loop(std::function<void()> user_loop);
    void set_common_sys_get_clock(std::function<unsigned int()> get_clock);
    void set_common_sys_random_func(std::function<unsigned int()> random_func);
    void set_common_sys_lock(std::function<void()> lock);
    void set_common_sys_unlock(std::function<void()> unlock);
#else
    void register_user_loop(void (*user_loop)());
    void set_common_sys_get_clock(unsigned int (*get_clock)());
    void set_common_sys_random_func(unsigned int (*random_func)());
    void set_common_sys_lock(void (*lock)());
    void set_common_sys_unlock(void (*unlock)());
#endif

    Common_system();

   private:
    void* control_factory;
#if USE_FUNCTIONAL
    std::function<void()> user_loop;
    std::function<unsigned int()> common_get_clock;
    std::function<void()> common_lock;
    std::function<void()> common_unlock;
    std::function<unsigned int()> common_random_func;
#else
    void (*user_loop)();
    void (*common_lock)();
    void (*common_unlock)();
    unsigned int (*common_get_clock)();
    unsigned int (*common_random_func)();
#endif
};

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********      End of common_system.h      ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********         Start of macro.h         ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_MACRO_H__
#define __ST_MACRO_H__

#include "config.h"

#define BYTE 8U
#define HEADER_BYTE                                                           \
    ((NODE_ID_BITS + MSG_ID_BITS + SEQ_NUM_BITS + CHAN_TYPE_BITS + TTL_BITS + \
      1 + BYTE - 1) /                                                         \
     BYTE)
#define PAYLOAD_BYTE (PKT_SIZE - HEADER_BYTE - (WITH_CRC ? 1 : 0))
#define CRC_BYTE 1U
#define TIMER_BYTE \
    (TIMER_BITS % BYTE == 0 ? TIMER_BITS / BYTE : TIMER_BITS / BYTE + 1)

#define NODE_ID_MAX ((1U << NODE_ID_BITS) - 1)
#define MSG_ID_MAX ((1U << MSG_ID_BITS) - 1)
#define SEQ_NUM_MAX ((1U << SEQ_NUM_BITS) - 1)
#define CHAN_TYPE_MAX ((1U << CHAN_TYPE_BITS) - 1)
#define TTL_MAX ((1U << TTL_BITS) - 1)
#define TIMER_MAX ((1U << TIMER_BITS) - 1)

#define NODE_ID_OFFSET 0
#define MSG_ID_OFFSET (NODE_ID_OFFSET + NODE_ID_BITS)
#define SEQ_NUM_OFFSET (MSG_ID_OFFSET + MSG_ID_BITS)
#define IF_END_OFFSET (SEQ_NUM_OFFSET + SEQ_NUM_BITS)
#define CHAN_TYPE_OFFSET (IF_END_OFFSET + 1)
#define TTL_OFFSET (CHAN_TYPE_OFFSET + CHAN_TYPE_BITS)

#define MAX_PKT_PER_MSG (SEQ_NUM_MAX + 1)

#define SINGLE_PKT_MEM (HEADER_BYTE + PAYLOAD_BYTE + 1)
#define BUFF_MEM_USAGE                                                 \
    ((BUFF_SIZE_PER_CHAN * TOTAL_CHAN_NUM + FORWARD_BUFF_SIZE * PKT) * \
     PKT_MEM_USAGE)
#define CACHE_MEM_USAGE (CACHE_SIZE * HEADER_BYTE)
#define TOTAL_MEM_USAGE (BUFF_MEM_USAGE + CACHE_MEM_USAGE)

#if DEBUG
#define SWARM_LOG(...)         \
    printf("(%s) ", __func__); \
    printf(__VA_ARGS__);       \
    printf("\r\n");
#else
#define SWARM_LOG(...)
#endif

#endif

/**************************************************/
/********                                  ********/
/********          End of macro.h          ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********          Start of util.h         ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_UTIL_H__
#define __ST_UTIL_H__

#include <stdlib.h>


namespace SwarmTalk {

namespace common {

unsigned int decode(unsigned char* header, unsigned int offset,
                    unsigned int len) {
    unsigned int ret = 0;
    unsigned int end_bit = offset + len - 1;
    unsigned int cur_index = offset / BYTE;
    unsigned int end_index = end_bit / BYTE;
    unsigned char mask;
    unsigned int front, rear;
    // printf("start bit: %d; end bit: %d; start index: %d; end index: %d\n",
    // offset, end_bit, cur_index, end_index);
    while (cur_index <= end_index) {
        front = offset - cur_index * BYTE;
        if (cur_index == end_index) {
            ret = ret << (end_bit - offset + 1);
            rear = (cur_index + 1) * BYTE - 1 - end_bit;
        } else {
            ret = ret << ((cur_index + 1) * BYTE - offset);
            rear = 0;
        }
        mask = ((0xFF >> front) >> rear) << rear;
        ret = ret + ((header[cur_index] & mask) >> rear);
        cur_index++;
        offset = cur_index * BYTE;
        // printf("ret = %d\n", ret);
    }

    return ret;
}

void encode(unsigned char* header, unsigned int offset, unsigned int len,
            unsigned int data) {
    int end_bit = offset + len - 1;
    int start_index = offset / BYTE;
    int cur_index = end_bit / BYTE;
    unsigned char mask;
    int front, rear;
    while (cur_index >= start_index) {
        rear = (cur_index + 1) * BYTE - 1 - end_bit;
        if (cur_index == start_index) {
            front = offset - start_index * BYTE;
        } else {
            front = 0;
        }
        mask = ((0xFF >> front) >> rear) << rear;
        header[cur_index] = header[cur_index] & ((unsigned char)~mask);
        header[cur_index] =
            header[cur_index] +
            ((data & (~(0xFF << (BYTE - front - rear)))) << rear);
        data = data >> (BYTE - front - rear);
        cur_index--;
        end_bit = (cur_index + 1) * BYTE - 1;
    }
}

unsigned int clock_diff(unsigned int start, unsigned int end) {
    if (start > end) {
        // based on assumption that if start overflows, end won't overflow
        // assuming the msg processing won't take as long as entire clock
        // overflow
        end = end + TIMER_MAX;
    }
    return end - start;
}

void dummy_lock() {}

unsigned int dummy_clock() { return 0; }

unsigned int dummy_rand_func() { return rand(); }

}  // namespace common

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********           End of util.h          ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********     Start of common_system.h     ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_COMMON_SYSTEM_H__
#define __ST_COMMON_SYSTEM_H__


#if USE_FUNCTIONAL
#include <functional>
#endif

namespace SwarmTalk {

class Common_system {
   public:
    unsigned int get_clock();
    unsigned int random_func();
    void lock();
    void unlock();
    void execute_loop();
    void register_control_factory(void* control_factory);

#if USE_FUNCTIONAL
    void register_user_loop(std::function<void()> user_loop);
    void set_common_sys_get_clock(std::function<unsigned int()> get_clock);
    void set_common_sys_random_func(std::function<unsigned int()> random_func);
    void set_common_sys_lock(std::function<void()> lock);
    void set_common_sys_unlock(std::function<void()> unlock);
#else
    void register_user_loop(void (*user_loop)());
    void set_common_sys_get_clock(unsigned int (*get_clock)());
    void set_common_sys_random_func(unsigned int (*random_func)());
    void set_common_sys_lock(void (*lock)());
    void set_common_sys_unlock(void (*unlock)());
#endif

    Common_system();

   private:
    void* control_factory;
#if USE_FUNCTIONAL
    std::function<void()> user_loop;
    std::function<unsigned int()> common_get_clock;
    std::function<void()> common_lock;
    std::function<void()> common_unlock;
    std::function<unsigned int()> common_random_func;
#else
    void (*user_loop)();
    void (*common_lock)();
    void (*common_unlock)();
    unsigned int (*common_get_clock)();
    unsigned int (*common_random_func)();
#endif
};

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********      End of common_system.h      ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********         Start of packet.h        ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_PACKET_H__
#define __ST_PACKET_H__

#include <stdint.h>


namespace SwarmTalk {

class Packet {
   public:
    void init(unsigned char *pkt);
    void init(unsigned char *content, int size, unsigned int nodeId,
              unsigned int msgId, unsigned int seqNum, bool ifEnd,
              unsigned int chanNum, unsigned int ttl);

    int to_packet(unsigned char *pkt);
    unsigned char *get_content();
    void set_node_id(unsigned int id);
    void print_data();
    void decrease_hop();
    void set_time_bytes(unsigned int time);
    unsigned int get_node_id();
    unsigned int get_msg_id();
    unsigned int get_seq_num();
    unsigned int get_chan_type();
    unsigned int get_ttl();
    unsigned int get_pay_size();
    bool get_if_end();
    bool if_valid();
    unsigned int get_time_bytes();

    Packet();
    Packet(unsigned char *pkt);
    Packet(unsigned char *content, int size, unsigned int nodeId,
           unsigned int msgId, unsigned int seqNum, bool ifEnd,
           unsigned int chanNum, unsigned int ttl);
    ~Packet();

   private:
#if WITH_CRC
    unsigned char content[PKT_SIZE - HEADER_BYTE - CRC_BYTE];
#else
    unsigned char content[PKT_SIZE - HEADER_BYTE];
#endif
    unsigned char header[HEADER_BYTE];
    bool valid;

    unsigned char crc_check(unsigned char *pkt, int size, int in_crc);
    unsigned char crc(unsigned char *pkt, int size);
};

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********          End of packet.h         ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********         Start of macro.h         ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_MACRO_H__
#define __ST_MACRO_H__

#include "config.h"

#define BYTE 8U
#define HEADER_BYTE                                                           \
    ((NODE_ID_BITS + MSG_ID_BITS + SEQ_NUM_BITS + CHAN_TYPE_BITS + TTL_BITS + \
      1 + BYTE - 1) /                                                         \
     BYTE)
#define PAYLOAD_BYTE (PKT_SIZE - HEADER_BYTE - (WITH_CRC ? 1 : 0))
#define CRC_BYTE 1U
#define TIMER_BYTE \
    (TIMER_BITS % BYTE == 0 ? TIMER_BITS / BYTE : TIMER_BITS / BYTE + 1)

#define NODE_ID_MAX ((1U << NODE_ID_BITS) - 1)
#define MSG_ID_MAX ((1U << MSG_ID_BITS) - 1)
#define SEQ_NUM_MAX ((1U << SEQ_NUM_BITS) - 1)
#define CHAN_TYPE_MAX ((1U << CHAN_TYPE_BITS) - 1)
#define TTL_MAX ((1U << TTL_BITS) - 1)
#define TIMER_MAX ((1U << TIMER_BITS) - 1)

#define NODE_ID_OFFSET 0
#define MSG_ID_OFFSET (NODE_ID_OFFSET + NODE_ID_BITS)
#define SEQ_NUM_OFFSET (MSG_ID_OFFSET + MSG_ID_BITS)
#define IF_END_OFFSET (SEQ_NUM_OFFSET + SEQ_NUM_BITS)
#define CHAN_TYPE_OFFSET (IF_END_OFFSET + 1)
#define TTL_OFFSET (CHAN_TYPE_OFFSET + CHAN_TYPE_BITS)

#define MAX_PKT_PER_MSG (SEQ_NUM_MAX + 1)

#define SINGLE_PKT_MEM (HEADER_BYTE + PAYLOAD_BYTE + 1)
#define BUFF_MEM_USAGE                                                 \
    ((BUFF_SIZE_PER_CHAN * TOTAL_CHAN_NUM + FORWARD_BUFF_SIZE * PKT) * \
     PKT_MEM_USAGE)
#define CACHE_MEM_USAGE (CACHE_SIZE * HEADER_BYTE)
#define TOTAL_MEM_USAGE (BUFF_MEM_USAGE + CACHE_MEM_USAGE)

#if DEBUG
#define SWARM_LOG(...)         \
    printf("(%s) ", __func__); \
    printf(__VA_ARGS__);       \
    printf("\r\n");
#else
#define SWARM_LOG(...)
#endif

#endif

/**************************************************/
/********                                  ********/
/********          End of macro.h          ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********          Start of util.h         ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_UTIL_H__
#define __ST_UTIL_H__

#include <stdlib.h>


namespace SwarmTalk {

namespace common {

unsigned int decode(unsigned char* header, unsigned int offset,
                    unsigned int len) {
    unsigned int ret = 0;
    unsigned int end_bit = offset + len - 1;
    unsigned int cur_index = offset / BYTE;
    unsigned int end_index = end_bit / BYTE;
    unsigned char mask;
    unsigned int front, rear;
    // printf("start bit: %d; end bit: %d; start index: %d; end index: %d\n",
    // offset, end_bit, cur_index, end_index);
    while (cur_index <= end_index) {
        front = offset - cur_index * BYTE;
        if (cur_index == end_index) {
            ret = ret << (end_bit - offset + 1);
            rear = (cur_index + 1) * BYTE - 1 - end_bit;
        } else {
            ret = ret << ((cur_index + 1) * BYTE - offset);
            rear = 0;
        }
        mask = ((0xFF >> front) >> rear) << rear;
        ret = ret + ((header[cur_index] & mask) >> rear);
        cur_index++;
        offset = cur_index * BYTE;
        // printf("ret = %d\n", ret);
    }

    return ret;
}

void encode(unsigned char* header, unsigned int offset, unsigned int len,
            unsigned int data) {
    int end_bit = offset + len - 1;
    int start_index = offset / BYTE;
    int cur_index = end_bit / BYTE;
    unsigned char mask;
    int front, rear;
    while (cur_index >= start_index) {
        rear = (cur_index + 1) * BYTE - 1 - end_bit;
        if (cur_index == start_index) {
            front = offset - start_index * BYTE;
        } else {
            front = 0;
        }
        mask = ((0xFF >> front) >> rear) << rear;
        header[cur_index] = header[cur_index] & ((unsigned char)~mask);
        header[cur_index] =
            header[cur_index] +
            ((data & (~(0xFF << (BYTE - front - rear)))) << rear);
        data = data >> (BYTE - front - rear);
        cur_index--;
        end_bit = (cur_index + 1) * BYTE - 1;
    }
}

unsigned int clock_diff(unsigned int start, unsigned int end) {
    if (start > end) {
        // based on assumption that if start overflows, end won't overflow
        // assuming the msg processing won't take as long as entire clock
        // overflow
        end = end + TIMER_MAX;
    }
    return end - start;
}

void dummy_lock() {}

unsigned int dummy_clock() { return 0; }

unsigned int dummy_rand_func() { return rand(); }

}  // namespace common

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********           End of util.h          ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********     Start of common_system.h     ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_COMMON_SYSTEM_H__
#define __ST_COMMON_SYSTEM_H__


#if USE_FUNCTIONAL
#include <functional>
#endif

namespace SwarmTalk {

class Common_system {
   public:
    unsigned int get_clock();
    unsigned int random_func();
    void lock();
    void unlock();
    void execute_loop();
    void register_control_factory(void* control_factory);

#if USE_FUNCTIONAL
    void register_user_loop(std::function<void()> user_loop);
    void set_common_sys_get_clock(std::function<unsigned int()> get_clock);
    void set_common_sys_random_func(std::function<unsigned int()> random_func);
    void set_common_sys_lock(std::function<void()> lock);
    void set_common_sys_unlock(std::function<void()> unlock);
#else
    void register_user_loop(void (*user_loop)());
    void set_common_sys_get_clock(unsigned int (*get_clock)());
    void set_common_sys_random_func(unsigned int (*random_func)());
    void set_common_sys_lock(void (*lock)());
    void set_common_sys_unlock(void (*unlock)());
#endif

    Common_system();

   private:
    void* control_factory;
#if USE_FUNCTIONAL
    std::function<void()> user_loop;
    std::function<unsigned int()> common_get_clock;
    std::function<void()> common_lock;
    std::function<void()> common_unlock;
    std::function<unsigned int()> common_random_func;
#else
    void (*user_loop)();
    void (*common_lock)();
    void (*common_unlock)();
    unsigned int (*common_get_clock)();
    unsigned int (*common_random_func)();
#endif
};

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********      End of common_system.h      ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********       Start of publisher.h       ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_PUBLISHER_H__
#define __ST_PUBLISHER_H__


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

/**************************************************/
/********                                  ********/
/********        End of publisher.h        ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********         Start of macro.h         ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_MACRO_H__
#define __ST_MACRO_H__

#include "config.h"

#define BYTE 8U
#define HEADER_BYTE                                                           \
    ((NODE_ID_BITS + MSG_ID_BITS + SEQ_NUM_BITS + CHAN_TYPE_BITS + TTL_BITS + \
      1 + BYTE - 1) /                                                         \
     BYTE)
#define PAYLOAD_BYTE (PKT_SIZE - HEADER_BYTE - (WITH_CRC ? 1 : 0))
#define CRC_BYTE 1U
#define TIMER_BYTE \
    (TIMER_BITS % BYTE == 0 ? TIMER_BITS / BYTE : TIMER_BITS / BYTE + 1)

#define NODE_ID_MAX ((1U << NODE_ID_BITS) - 1)
#define MSG_ID_MAX ((1U << MSG_ID_BITS) - 1)
#define SEQ_NUM_MAX ((1U << SEQ_NUM_BITS) - 1)
#define CHAN_TYPE_MAX ((1U << CHAN_TYPE_BITS) - 1)
#define TTL_MAX ((1U << TTL_BITS) - 1)
#define TIMER_MAX ((1U << TIMER_BITS) - 1)

#define NODE_ID_OFFSET 0
#define MSG_ID_OFFSET (NODE_ID_OFFSET + NODE_ID_BITS)
#define SEQ_NUM_OFFSET (MSG_ID_OFFSET + MSG_ID_BITS)
#define IF_END_OFFSET (SEQ_NUM_OFFSET + SEQ_NUM_BITS)
#define CHAN_TYPE_OFFSET (IF_END_OFFSET + 1)
#define TTL_OFFSET (CHAN_TYPE_OFFSET + CHAN_TYPE_BITS)

#define MAX_PKT_PER_MSG (SEQ_NUM_MAX + 1)

#define SINGLE_PKT_MEM (HEADER_BYTE + PAYLOAD_BYTE + 1)
#define BUFF_MEM_USAGE                                                 \
    ((BUFF_SIZE_PER_CHAN * TOTAL_CHAN_NUM + FORWARD_BUFF_SIZE * PKT) * \
     PKT_MEM_USAGE)
#define CACHE_MEM_USAGE (CACHE_SIZE * HEADER_BYTE)
#define TOTAL_MEM_USAGE (BUFF_MEM_USAGE + CACHE_MEM_USAGE)

#if DEBUG
#define SWARM_LOG(...)         \
    printf("(%s) ", __func__); \
    printf(__VA_ARGS__);       \
    printf("\r\n");
#else
#define SWARM_LOG(...)
#endif

#endif

/**************************************************/
/********                                  ********/
/********          End of macro.h          ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********          Start of util.h         ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_UTIL_H__
#define __ST_UTIL_H__

#include <stdlib.h>


namespace SwarmTalk {

namespace common {

unsigned int decode(unsigned char* header, unsigned int offset,
                    unsigned int len) {
    unsigned int ret = 0;
    unsigned int end_bit = offset + len - 1;
    unsigned int cur_index = offset / BYTE;
    unsigned int end_index = end_bit / BYTE;
    unsigned char mask;
    unsigned int front, rear;
    // printf("start bit: %d; end bit: %d; start index: %d; end index: %d\n",
    // offset, end_bit, cur_index, end_index);
    while (cur_index <= end_index) {
        front = offset - cur_index * BYTE;
        if (cur_index == end_index) {
            ret = ret << (end_bit - offset + 1);
            rear = (cur_index + 1) * BYTE - 1 - end_bit;
        } else {
            ret = ret << ((cur_index + 1) * BYTE - offset);
            rear = 0;
        }
        mask = ((0xFF >> front) >> rear) << rear;
        ret = ret + ((header[cur_index] & mask) >> rear);
        cur_index++;
        offset = cur_index * BYTE;
        // printf("ret = %d\n", ret);
    }

    return ret;
}

void encode(unsigned char* header, unsigned int offset, unsigned int len,
            unsigned int data) {
    int end_bit = offset + len - 1;
    int start_index = offset / BYTE;
    int cur_index = end_bit / BYTE;
    unsigned char mask;
    int front, rear;
    while (cur_index >= start_index) {
        rear = (cur_index + 1) * BYTE - 1 - end_bit;
        if (cur_index == start_index) {
            front = offset - start_index * BYTE;
        } else {
            front = 0;
        }
        mask = ((0xFF >> front) >> rear) << rear;
        header[cur_index] = header[cur_index] & ((unsigned char)~mask);
        header[cur_index] =
            header[cur_index] +
            ((data & (~(0xFF << (BYTE - front - rear)))) << rear);
        data = data >> (BYTE - front - rear);
        cur_index--;
        end_bit = (cur_index + 1) * BYTE - 1;
    }
}

unsigned int clock_diff(unsigned int start, unsigned int end) {
    if (start > end) {
        // based on assumption that if start overflows, end won't overflow
        // assuming the msg processing won't take as long as entire clock
        // overflow
        end = end + TIMER_MAX;
    }
    return end - start;
}

void dummy_lock() {}

unsigned int dummy_clock() { return 0; }

unsigned int dummy_rand_func() { return rand(); }

}  // namespace common

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********           End of util.h          ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********     Start of common_system.h     ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_COMMON_SYSTEM_H__
#define __ST_COMMON_SYSTEM_H__


#if USE_FUNCTIONAL
#include <functional>
#endif

namespace SwarmTalk {

class Common_system {
   public:
    unsigned int get_clock();
    unsigned int random_func();
    void lock();
    void unlock();
    void execute_loop();
    void register_control_factory(void* control_factory);

#if USE_FUNCTIONAL
    void register_user_loop(std::function<void()> user_loop);
    void set_common_sys_get_clock(std::function<unsigned int()> get_clock);
    void set_common_sys_random_func(std::function<unsigned int()> random_func);
    void set_common_sys_lock(std::function<void()> lock);
    void set_common_sys_unlock(std::function<void()> unlock);
#else
    void register_user_loop(void (*user_loop)());
    void set_common_sys_get_clock(unsigned int (*get_clock)());
    void set_common_sys_random_func(unsigned int (*random_func)());
    void set_common_sys_lock(void (*lock)());
    void set_common_sys_unlock(void (*unlock)());
#endif

    Common_system();

   private:
    void* control_factory;
#if USE_FUNCTIONAL
    std::function<void()> user_loop;
    std::function<unsigned int()> common_get_clock;
    std::function<void()> common_lock;
    std::function<void()> common_unlock;
    std::function<unsigned int()> common_random_func;
#else
    void (*user_loop)();
    void (*common_lock)();
    void (*common_unlock)();
    unsigned int (*common_get_clock)();
    unsigned int (*common_random_func)();
#endif
};

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********      End of common_system.h      ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********       Start of subscriber.h      ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_SUBSCRIBER_H__
#define __ST_SUBSCRIBER_H__

#include <stddef.h>
#include <stdio.h>


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

/**************************************************/
/********                                  ********/
/********        End of subscriber.h       ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********       Start of swarmtalk.h       ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_SWARMTALK_H__
#define __ST_SWARMTALK_H__


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

    /* ------- constructor ------- */

    Swarmtalk();
    ~Swarmtalk();
    Common_system sys;

   private:
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

/**************************************************/
/********                                  ********/
/********        End of swarmtalk.h        ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********         Start of macro.h         ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_MACRO_H__
#define __ST_MACRO_H__

#include "config.h"

#define BYTE 8U
#define HEADER_BYTE                                                           \
    ((NODE_ID_BITS + MSG_ID_BITS + SEQ_NUM_BITS + CHAN_TYPE_BITS + TTL_BITS + \
      1 + BYTE - 1) /                                                         \
     BYTE)
#define PAYLOAD_BYTE (PKT_SIZE - HEADER_BYTE - (WITH_CRC ? 1 : 0))
#define CRC_BYTE 1U
#define TIMER_BYTE \
    (TIMER_BITS % BYTE == 0 ? TIMER_BITS / BYTE : TIMER_BITS / BYTE + 1)

#define NODE_ID_MAX ((1U << NODE_ID_BITS) - 1)
#define MSG_ID_MAX ((1U << MSG_ID_BITS) - 1)
#define SEQ_NUM_MAX ((1U << SEQ_NUM_BITS) - 1)
#define CHAN_TYPE_MAX ((1U << CHAN_TYPE_BITS) - 1)
#define TTL_MAX ((1U << TTL_BITS) - 1)
#define TIMER_MAX ((1U << TIMER_BITS) - 1)

#define NODE_ID_OFFSET 0
#define MSG_ID_OFFSET (NODE_ID_OFFSET + NODE_ID_BITS)
#define SEQ_NUM_OFFSET (MSG_ID_OFFSET + MSG_ID_BITS)
#define IF_END_OFFSET (SEQ_NUM_OFFSET + SEQ_NUM_BITS)
#define CHAN_TYPE_OFFSET (IF_END_OFFSET + 1)
#define TTL_OFFSET (CHAN_TYPE_OFFSET + CHAN_TYPE_BITS)

#define MAX_PKT_PER_MSG (SEQ_NUM_MAX + 1)

#define SINGLE_PKT_MEM (HEADER_BYTE + PAYLOAD_BYTE + 1)
#define BUFF_MEM_USAGE                                                 \
    ((BUFF_SIZE_PER_CHAN * TOTAL_CHAN_NUM + FORWARD_BUFF_SIZE * PKT) * \
     PKT_MEM_USAGE)
#define CACHE_MEM_USAGE (CACHE_SIZE * HEADER_BYTE)
#define TOTAL_MEM_USAGE (BUFF_MEM_USAGE + CACHE_MEM_USAGE)

#if DEBUG
#define SWARM_LOG(...)         \
    printf("(%s) ", __func__); \
    printf(__VA_ARGS__);       \
    printf("\r\n");
#else
#define SWARM_LOG(...)
#endif

#endif

/**************************************************/
/********                                  ********/
/********          End of macro.h          ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********          Start of util.h         ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_UTIL_H__
#define __ST_UTIL_H__

#include <stdlib.h>


namespace SwarmTalk {

namespace common {

unsigned int decode(unsigned char* header, unsigned int offset,
                    unsigned int len) {
    unsigned int ret = 0;
    unsigned int end_bit = offset + len - 1;
    unsigned int cur_index = offset / BYTE;
    unsigned int end_index = end_bit / BYTE;
    unsigned char mask;
    unsigned int front, rear;
    // printf("start bit: %d; end bit: %d; start index: %d; end index: %d\n",
    // offset, end_bit, cur_index, end_index);
    while (cur_index <= end_index) {
        front = offset - cur_index * BYTE;
        if (cur_index == end_index) {
            ret = ret << (end_bit - offset + 1);
            rear = (cur_index + 1) * BYTE - 1 - end_bit;
        } else {
            ret = ret << ((cur_index + 1) * BYTE - offset);
            rear = 0;
        }
        mask = ((0xFF >> front) >> rear) << rear;
        ret = ret + ((header[cur_index] & mask) >> rear);
        cur_index++;
        offset = cur_index * BYTE;
        // printf("ret = %d\n", ret);
    }

    return ret;
}

void encode(unsigned char* header, unsigned int offset, unsigned int len,
            unsigned int data) {
    int end_bit = offset + len - 1;
    int start_index = offset / BYTE;
    int cur_index = end_bit / BYTE;
    unsigned char mask;
    int front, rear;
    while (cur_index >= start_index) {
        rear = (cur_index + 1) * BYTE - 1 - end_bit;
        if (cur_index == start_index) {
            front = offset - start_index * BYTE;
        } else {
            front = 0;
        }
        mask = ((0xFF >> front) >> rear) << rear;
        header[cur_index] = header[cur_index] & ((unsigned char)~mask);
        header[cur_index] =
            header[cur_index] +
            ((data & (~(0xFF << (BYTE - front - rear)))) << rear);
        data = data >> (BYTE - front - rear);
        cur_index--;
        end_bit = (cur_index + 1) * BYTE - 1;
    }
}

unsigned int clock_diff(unsigned int start, unsigned int end) {
    if (start > end) {
        // based on assumption that if start overflows, end won't overflow
        // assuming the msg processing won't take as long as entire clock
        // overflow
        end = end + TIMER_MAX;
    }
    return end - start;
}

void dummy_lock() {}

unsigned int dummy_clock() { return 0; }

unsigned int dummy_rand_func() { return rand(); }

}  // namespace common

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********           End of util.h          ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********     Start of common_system.h     ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_COMMON_SYSTEM_H__
#define __ST_COMMON_SYSTEM_H__


#if USE_FUNCTIONAL
#include <functional>
#endif

namespace SwarmTalk {

class Common_system {
   public:
    unsigned int get_clock();
    unsigned int random_func();
    void lock();
    void unlock();
    void execute_loop();
    void register_control_factory(void* control_factory);

#if USE_FUNCTIONAL
    void register_user_loop(std::function<void()> user_loop);
    void set_common_sys_get_clock(std::function<unsigned int()> get_clock);
    void set_common_sys_random_func(std::function<unsigned int()> random_func);
    void set_common_sys_lock(std::function<void()> lock);
    void set_common_sys_unlock(std::function<void()> unlock);
#else
    void register_user_loop(void (*user_loop)());
    void set_common_sys_get_clock(unsigned int (*get_clock)());
    void set_common_sys_random_func(unsigned int (*random_func)());
    void set_common_sys_lock(void (*lock)());
    void set_common_sys_unlock(void (*unlock)());
#endif

    Common_system();

   private:
    void* control_factory;
#if USE_FUNCTIONAL
    std::function<void()> user_loop;
    std::function<unsigned int()> common_get_clock;
    std::function<void()> common_lock;
    std::function<void()> common_unlock;
    std::function<unsigned int()> common_random_func;
#else
    void (*user_loop)();
    void (*common_lock)();
    void (*common_unlock)();
    unsigned int (*common_get_clock)();
    unsigned int (*common_random_func)();
#endif
};

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********      End of common_system.h      ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/******** Start of control_unit_template.h ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_CONTROL_UNIT_TEMPLATE_H__
#define __ST_CONTROL_UNIT_TEMPLATE_H__


namespace SwarmTalk {

class Control_factory_template {
   public:
    virtual void update_control() = 0;
    virtual void register_common_sys(Common_system* common_sys) = 0;

   protected:
    Common_system* common_sys;
};

class Control_unit_template {
   public:
    virtual void update_control() = 0;
    virtual void register_common_sys(Common_system* common_sys) = 0;

   protected:
    Common_system* common_sys;
};

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********  End of control_unit_template.h  ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********     Start of control_driver.h    ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_KILOBOT_CONTROL_DRIVER_H__
#define __ST_KILOBOT_CONTROL_DRIVER_H__

extern "C" {
#include <kilolib.h>
}


namespace SwarmTalk {

#define NUM_OF_CONTROL_UNITS 2
enum control_units { Motor, Led };
enum motor_state { Stop, Move_forward, Turn_left, Turn_right };
enum LED_state { On, Off };

class Motor_control_unit : public Control_unit_template {
   public:
    void update_control() {
        // if (this->common_sys->get_clock == NULL) return;
        if (this->status == Stop || this->time_left == 0) return;
        unsigned long cur_time = this->common_sys->get_clock();
        if (cur_time - this->start_time > this->time_left) {
            status = Stop;
            time_left = 0;
            set_motors(0, 0);
        }
    }

    void move_forward(unsigned long time) {
        // if (this->common_sys->get_clock == NULL) return;
        this->start_time = (this->common_sys)->get_clock();
        if (this->status != Move_forward) spinup_motors();
        this->status = Move_forward;
        this->time_left = time;
        set_motors(kilo_straight_left, kilo_straight_right);
    }

    void turn_left(unsigned long time) {
        // if (this->common_sys->get_clock == NULL) return;
        this->start_time = this->common_sys->get_clock();
        if (this->status != Turn_left) spinup_motors();
        this->status = Turn_left;
        this->time_left = time;
        set_motors(kilo_turn_left, 0);
    }

    void turn_right(unsigned long time) {
        // if (this->common_sys->get_clock == NULL) return;
        this->start_time = this->common_sys->get_clock();
        if (this->status != Turn_right) spinup_motors();
        this->status = Turn_right;
        this->time_left = time;
        set_motors(0, kilo_turn_left);
    }

    void stop_motor() {
        // if (this->common_sys->get_clock == NULL) return;
        this->start_time = this->common_sys->get_clock();
        this->status = Stop;
        this->time_left = 0;
        set_motors(0, 0);
    }

    int current_status() { return this->status; }

    void register_common_sys(Common_system* common_sys) {
        this->common_sys = common_sys;
    }

    Motor_control_unit() {
        time_left = 0;
        status = Stop;
    }

    ~Motor_control_unit() {}

   private:
    int status;
    unsigned long time_left;
    unsigned long start_time;
    Common_system* common_sys;
};

class LED_control_unit : public Control_unit_template {
   public:
    void update_control() {
        // if (this->common_sys->get_clock == NULL) return;
        if (this->status == Off || this->time_left == 0) return;
        unsigned long cur_time = this->common_sys->get_clock();
        if (cur_time - this->start_time > this->time_left) {
            status = Off;
            time_left = 0;
            set_color(RGB(0, 0, 0));
            ;
        }
    }

    void turn_on(int red, int green, int blue, int time) {
        // if (this->common_sys->get_clock == NULL) return;
        this->start_time = (this->common_sys)->get_clock();
        this->status = On;
        this->time_left = time;
        set_color(RGB(red, green, blue));
        ;
    }

    int current_status() { return this->status; }

    void register_common_sys(Common_system* common_sys) {
        this->common_sys = common_sys;
    }

    LED_control_unit() {
        time_left = 0;
        status = Off;
    }

    ~LED_control_unit() {}

   private:
    int status;
    unsigned long time_left;
    unsigned long start_time;
    Common_system* common_sys;
};

class My_control_factory : public Control_factory_template {
   public:
    void update_control() {
        for (int i = 0; i < NUM_OF_CONTROL_UNITS; i++) {
            if (my_control_unit[i] != NULL) {
                my_control_unit[i]->update_control();
            }
        }
    }

    Control_unit_template* get_control_unit(int index) {
        return my_control_unit[index];
    }

    void register_common_sys(Common_system* common_sys) {
        this->common_sys = common_sys;
        for (int i = 0; i < NUM_OF_CONTROL_UNITS; i++) {
            my_control_unit[i]->register_common_sys(this->common_sys);
        }
    }

    My_control_factory() {
        my_control_unit[Motor] = &my_motor_control;
        my_control_unit[Led] = &my_LED_control;
    }

    ~My_control_factory() {}

   private:
    Control_unit_template* my_control_unit[NUM_OF_CONTROL_UNITS];
    Motor_control_unit my_motor_control;
    LED_control_unit my_LED_control;
};

}  // namespace SwarmTalk

#endif

/**************************************************/
/********                                  ********/
/********      End of control_driver.h     ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********   Start of st_kilobot_driver.h   ********/
/********                                  ********/
/**************************************************/

#ifndef __ST_KILOBOT_DRIVER_H__
#define __ST_KILOBOT_DRIVER_H__

#define DEBUG

extern "C" {
#include <kilolib.h>

// #include "debug.h"
}


#define START_USER_PROGRAM
#define END_USER_PROGRAM

using namespace SwarmTalk;

message_t message;
Swarmtalk swarmtalk;
Common_system *st_common_sys;
Motor_control_unit *motor_control;
LED_control_unit *LED_control;
My_control_factory my_control_factory;

void message_tx_success() {}

void driver_loop() { st_common_sys->execute_loop(); }

message_t *message_tx() {
    message.type = NORMAL;
    int ret = swarmtalk.next_pkt(message.data);
    message.crc = message_crc(&message);
    if (ret == 0)
        return NULL;
    else
        return &message;
}

void message_rx(message_t *message,
                distance_measurement_t *distance_measurement) {
    // Set the flag on message reception.
    int dist = estimate_distance(distance_measurement);
    // printf("P Recv dist = %d, theta = %f\n", dist, t);
    Meta_t meta;
    meta.dist = dist;
    swarmtalk.receive(message->data, PKT_SIZE, &meta);
}

unsigned int get_clock() { return (unsigned int)kilo_ticks; }

unsigned int custom_rand() { return rand_hard(); }

// forward declear loop & setup
void loop();
void setup();

void swarmtalk_init() {
    kilo_message_tx = message_tx;
    kilo_message_tx_success = message_tx_success;
    kilo_message_rx = message_rx;
    st_common_sys = swarmtalk.get_common_sys();
    st_common_sys->set_common_sys_get_clock(get_clock);
    st_common_sys->set_common_sys_random_func(custom_rand);
    st_common_sys->register_user_loop(loop);
    st_common_sys->register_control_factory(&my_control_factory);
    motor_control =
        (Motor_control_unit *)my_control_factory.get_control_unit(Motor);
    LED_control = (LED_control_unit *)my_control_factory.get_control_unit(Led);
}

extern "C" {
int main() {
    kilo_init();
    swarmtalk_init();
    kilo_start(setup, driver_loop);
}
}

#endif

/**************************************************/
/********                                  ********/
/********    End of st_kilobot_driver.h    ********/
/********                                  ********/
/**************************************************/

