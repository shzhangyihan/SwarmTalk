

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



/**************************************************/
/********                                  ********/
/********      Start of swarmtalk.cpp      ********/
/********                                  ********/
/**************************************************/


namespace SwarmTalk {

Swarmtalk::Swarmtalk() {
    roundRobinIndex = 0;
    chan_num = 0;
    forward_size = 0;
}

Swarmtalk::~Swarmtalk() {}

void Swarmtalk::init() { new_id(); }

Common_system *Swarmtalk::get_common_sys() { return &(this->sys); }

Channel *Swarmtalk::new_channel(int type, int hops, bool listen) {
    if (type > CHAN_TYPE_MAX) {
        // type invalid
        return NULL;
    }

    if (chan_num >= TOTAL_CHAN_NUM) {
        // too many channels
        return NULL;
    }

    chans[chan_num].init(type, hops, listen);
    chans[chan_num].set_common_sys(&sys);
    chan_num++;
    return &(chans[chan_num - 1]);
}

void Swarmtalk::new_id() { this->nodeId = sys.random_func() % NODE_ID_MAX; }

int Swarmtalk::next_pkt(unsigned char *pkt) {
    // no channel created
    if (chan_num == 0) return 0;
    Packet send;
    int flag;
    for (int i = roundRobinIndex; i < roundRobinIndex + chan_num + 1; i++) {
        if (i == chan_num) {
            SWARM_LOG("Pulling from forward buffer");
            if (forward_size == 0) {
                SWARM_LOG("Forward buff empty");
                flag = SUCCESS + 1;
            } else {
                memcpy(&send, forwardBuffer, sizeof(Packet));
                memmove(forwardBuffer, forwardBuffer + 1,
                        (forward_size - 1) * sizeof(Packet));
                forward_size--;
                flag = SUCCESS;
            }
        } else {
            int index = i % (chan_num + 1);
            SWARM_LOG("Pulling from channel %d", chans[index].get_type());
            flag = chans[index].next_pkt(&send);
            if (flag == SUCCESS) {
                send.set_node_id(nodeId);
            } else {
                SWARM_LOG("Channel %d buff empty", chans[index].get_type());
            }
        }
        if (flag == SUCCESS) {
            // next packet ready to send
            SWARM_LOG("Next packet ready to send");
            int size;
            size = send.to_packet(pkt);
            roundRobinIndex = (i + 1) % (chan_num + 1);
            // cache the outgoing packet
            add_cache(pkt);
            return size;
        }
    }
    return 0;
}

void Swarmtalk::receive(unsigned char *pkt, int size, Meta_t *meta) {
    if (size == 0) return;

    Packet newPkt(pkt);

    // packet parsing failed, abort
    if (!newPkt.if_valid()) return;

    int chanNum = newPkt.get_chan_type();
    int nodeId = newPkt.get_node_id();
    int ttl = newPkt.get_ttl();

    int msgId = newPkt.get_msg_id();
    int seqNum = newPkt.get_seq_num();
    SWARM_LOG("Pkg received: %d, %d, %d, %d, %d", nodeId, msgId, seqNum,
              chanNum, ttl);

    if (check_cache(pkt)) {
        // already in cache, abort
        SWARM_LOG("Pkt cached already, abort");
        return;
    }

    // id collision, change self id
    if (nodeId == this->nodeId) {
        new_id();
        SWARM_LOG("NodeId collision, changed to new id: %d", this->nodeId);
    }

    // if hopCount > 0, store in forward
    if (ttl > 0) {
        // only cache if forward buffer is not full
        if (forward_size + 1 <= FORWARD_BUFF_SIZE) {
            memcpy(forwardBuffer + forward_size, &newPkt, sizeof(Packet));
            forwardBuffer[forward_size].decrease_hop();
            forward_size++;
        }
    }

    for (int i = 0; i < chan_num; i++) {
        if (chans[i].get_type() == chanNum) {
            chans[i].receive(&newPkt, meta);
        }
    }
}

bool Swarmtalk::check_cache(unsigned char *header) {
    unsigned int node_id = common::decode(header, NODE_ID_OFFSET, NODE_ID_BITS);
    unsigned int msg_id = common::decode(header, MSG_ID_OFFSET, MSG_ID_BITS);
    unsigned int seq_num = common::decode(header, SEQ_NUM_OFFSET, SEQ_NUM_BITS);
    unsigned int ttl = common::decode(header, TTL_OFFSET, TTL_BITS);
    SWARM_LOG("Check cache -- nodeId: %d msg_id: %d seq_num: %d ttl: %d",
              node_id, msg_id, seq_num, ttl);
    for (int i = 0; i < cache_size; i++) {
        unsigned int check_node_id =
            common::decode(send_cache[i], NODE_ID_OFFSET, NODE_ID_BITS);
        unsigned int check_msg_id =
            common::decode(send_cache[i], MSG_ID_OFFSET, MSG_ID_BITS);
        unsigned int check_seq_num =
            common::decode(send_cache[i], SEQ_NUM_OFFSET, SEQ_NUM_BITS);
        unsigned int check_ttl =
            common::decode(send_cache[i], TTL_OFFSET, TTL_BITS);
        if (node_id == check_node_id && msg_id == check_msg_id &&
            seq_num == check_seq_num) {
            // SWARM_LOG("Cache hit");
            if (ttl > check_ttl) {
                // SWARM_LOG("Need to update ttl\n");
                memcpy(send_cache[i], header,
                       HEADER_BYTE * sizeof(unsigned char));
                return false;
            }
            return true;
        }
    }

    return false;
}

void Swarmtalk::add_cache(unsigned char *header) {
    if (CACHE_SIZE == 0) return;
    unsigned int node_id = common::decode(header, NODE_ID_OFFSET, NODE_ID_BITS);
    unsigned int msg_id = common::decode(header, MSG_ID_OFFSET, MSG_ID_BITS);
    unsigned int seq_num = common::decode(header, SEQ_NUM_OFFSET, SEQ_NUM_BITS);
    unsigned int ttl = common::decode(header, TTL_OFFSET, TTL_BITS);
    SWARM_LOG(
        "Add cache -- nodeId: %d msg_id: %d seq_num: %d ttl: %d cache_buffer: "
        "%d/%d",
        node_id, msg_id, seq_num, ttl, cache_size, CACHE_SIZE);
    if (cache_size >= CACHE_SIZE) {
        // cache full
        // SWARM_LOG("Cache full, discard oldest");
        memmove(send_cache, send_cache + 1,
                (cache_size - 1) * HEADER_BYTE * sizeof(unsigned char));
        cache_size--;
    }
    memcpy(send_cache + cache_size, header,
           HEADER_BYTE * sizeof(unsigned char));
    cache_size++;
}

}  // namespace SwarmTalk

/**************************************************/
/********                                  ********/
/********       End of swarmtalk.cpp       ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********       Start of channel.cpp       ********/
/********                                  ********/
/**************************************************/


namespace SwarmTalk {

Channel::Channel() { init(0, 0, false); }

Channel::Channel(int type, int hops, bool time_chan) {
    init(type, hops, time_chan);
}

void Channel::init(int type, int hops, bool time_chan) {
    this->type = type;
    this->hops = hops;
    this->time_chan = time_chan;
    this->overflowCounter = 0;
    this->overflowFlag = false;
    this->send_index = 0;
    this->send_pktNum = 0;
    this->recv_pktNum = 0;
    this->ready = true;
}

Channel::~Channel() {}

void Channel::set_common_sys(Common_system *common_sys) {
    this->common_sys = common_sys;
}

#if FUNC
Subscriber *Channel::new_subscriber(
    int dist,
    std::function<void(unsigned char *, int, int, Meta_t *)> callback) {
#else
Subscriber *Channel::new_subscriber(int dist,
                                    void (*callback)(unsigned char *, int, int,
                                                     Meta_t *)) {
#endif
    for (int i = 0; i < MAX_SUB_PER_CHAN; i++) {
        if (subscribers[i].if_initialized() == false) {
            subscribers[i].subscriber_init(dist, callback);
            return &(subscribers[i]);
        }
    }
    return NULL;
}

#if FUNC
Publisher *Channel::new_publisher(std::function<void()> callback) {
#else
Publisher *Channel::new_publisher(void (*callback)()) {
#endif
    for (int i = 0; i < MAX_PUB_PER_CHAN; i++) {
        if (publishers[i].if_initialized() == false) {
            publishers[i].publisher_init(this, callback);
            return &(publishers[i]);
        }
    }
    return NULL;
}

bool Channel::available() { return ready; }

bool Channel::overflow_status() { return overflowFlag; }

void Channel::print_channel_status() {
    SWARM_LOG("Channel %d", get_type());
    SWARM_LOG("Send Buffer Status: (%d / %d)", (send_pktNum - send_index),
              MAX_BUFF);
    SWARM_LOG("Recv Buffer Status: (%d / %d)", recv_pktNum, BUFF_SIZE_PER_CHAN);
}

int Channel::send(unsigned char *msg, int msgSize) {
    if (!this->ready) {
        // buffer not ready to send
        SWARM_LOG("Send failed, due to channel not ready");
        return ERROR_NOT_READY;
    }

    int msgId = common_sys->random_func() % MAX_MSG_ID;
    int payloadSize;
    int header_byte = HEADER_BYTE;
    unsigned int cur_time = common_sys->get_clock();
    if (time_chan) {
        header_byte = header_byte + TIMER_BYTE;
    }

#if WITH_CRC
    payloadSize = PKT_SIZE - header_byte - CRC_BYTE;
#else
    payloadSize = PKT_SIZE - header_byte;
#endif

    // round up msgSize / payloadSize
    int totalPkt = (msgSize + payloadSize - 1) / payloadSize;
    if (totalPkt > MAX_BUFF) {
        // msg too long
        SWARM_LOG("Send failed, due to message too long");
        return ERROR_TOO_LONG;
    }

    for (int i = 0; i < totalPkt; i++) {
        if (i != totalPkt - 1) {
            // not last pkt
            sendBuffer[i].init(msg + i * payloadSize, payloadSize, DUMMY_ID,
                               msgId, i, false, type, hops);
        } else {
            // last pkt
            sendBuffer[i].init(msg + i * payloadSize, msgSize - i * payloadSize,
                               DUMMY_ID, msgId, i, true, type, hops);
        }
        if (time_chan) {
            sendBuffer[i].set_time_bytes(cur_time);
        }
    }
    SWARM_LOG("Set ready to false");
    this->ready = false;
    this->send_pktNum = totalPkt;
    this->send_index = 0;
    return SUCCESS;
}

int Channel::next_pkt(Packet *ret) {
    // buffer empty
    SWARM_LOG("Start fetching next packet %d from channel %d", send_pktNum,
              this->get_type());
    if (send_pktNum == 0) return ERROR_EMPTY;

    memcpy(ret, &sendBuffer[send_index], sizeof(Packet));
    if (send_index + 1 < send_pktNum) {
        // sendBuffer[send_index] = NULL;
        send_index++;
    } else {
        // finish sending the entire msg
        send_index = 0;
        send_pktNum = 0;
        SWARM_LOG("Set ready to true");
        ready = true;
        // callback on all sents
        for (int i = 0; i < MAX_PUB_PER_CHAN; i++)
            if (publishers[i].if_initialized() == true)
                publishers[i].sent_callback();
    }
    if (time_chan) {
        unsigned int cur_time = common_sys->get_clock();
        unsigned int old_time = ret->get_time_bytes();
        unsigned int diff_time = common::clock_diff(old_time, cur_time);
        ret->set_time_bytes(diff_time);
    }

    return SUCCESS;
}

void Channel::receive(Packet *newPkt, Meta_t *meta) {
    int nodeId = newPkt->get_node_id();
    int msgId = newPkt->get_msg_id();
    int seqNum = newPkt->get_seq_num();
    int ttl = newPkt->get_ttl();
    SWARM_LOG("Received message with node_id %d msg_id %d seq_num %d", nodeId,
              msgId, seqNum);
    for (int i = recv_pktNum - 1; i > 0; i--) {
        if (recvBuffer[i].get_node_id() == nodeId &&
            recvBuffer[i].get_msg_id() == msgId &&
            recvBuffer[i].get_seq_num() == seqNum &&
            recvBuffer[i].get_ttl() == ttl) {
            // delete duplicate
            SWARM_LOG("Find duplicate at %d", i);
            if (i != recv_pktNum - 1)
                // dont need to move if its the last pkt
                memmove(recvBuffer + i, recvBuffer + i + 1,
                        (recv_pktNum - i - 1) * sizeof(Packet));
            recv_pktNum--;
        }
    }

    if (recv_pktNum >= BUFF_SIZE_PER_CHAN) {
        memmove(recvBuffer, recvBuffer + 1, (recv_pktNum - 1) * sizeof(Packet));
        overflowCounter++;
        if (overflowCounter >= BUFF_SIZE_PER_CHAN) {
            // entire buffer has been refreshed
            overflowFlag = true;
        }
        recv_pktNum--;
    }

    // add new packet to buffer
    memcpy(recvBuffer + recv_pktNum, newPkt, sizeof(Packet));
    // update timer if needed
    if (time_chan) {
        unsigned int cur_time = common_sys->get_clock();
        unsigned int prev_time = recvBuffer[recv_pktNum].get_time_bytes();
        unsigned int diff_time = 0;
        if (cur_time < prev_time) {
            // overflow detection for (cur_time - read_time)
            diff_time = TIMER_MAX - (prev_time - cur_time);
        } else {
            diff_time = cur_time - prev_time;
        }
        recvBuffer[recv_pktNum].set_time_bytes(diff_time);
    }
    recv_pktNum++;
    SWARM_LOG("Pkt num after insert: %d", recv_pktNum);

    try_merge(nodeId, msgId, ttl, meta);
}

int Channel::get_type() { return type; }

void Channel::try_merge(int nodeId, int msgId, int ttl, Meta_t *meta) {
    SWARM_LOG("Try merge!!");
    for (int i = 0; i < MAX_BUFF; i++) assembler[i] = -1;

    for (int i = 0; i < recv_pktNum; i++) {
        SWARM_LOG("Inspecting packet node_id %d msg_id %d seq_num %d if_end %d",
                  recvBuffer[i].get_node_id(), recvBuffer[i].get_msg_id(),
                  recvBuffer[i].get_seq_num(), recvBuffer[i].get_if_end())
        if (recvBuffer[i].get_node_id() == nodeId &&
            recvBuffer[i].get_msg_id() == msgId &&
            recvBuffer[i].get_ttl() == ttl) {
            if (assembler[recvBuffer[i].get_seq_num()] == -1)
                assembler[recvBuffer[i].get_seq_num()] = i;
        }
    }

    int final_pkt = -1;
    for (int i = 0; i < MAX_BUFF; i++) {
        if (assembler[i] == -1) {
            break;
        }
        SWARM_LOG("%d at %d", i, assembler[i]);
        final_pkt = i;
    }

    SWARM_LOG("Final pkt at %d; if_end? %d", final_pkt,
              recvBuffer[assembler[final_pkt]].get_if_end());

    unsigned int longest_diff_time = 0;
    unsigned int cur_time = common_sys->get_clock();
    // if all continuous and is finished, then merge
    if (final_pkt != -1 && recvBuffer[assembler[final_pkt]].get_if_end()) {
        SWARM_LOG("!!! Start merging msg !!!");
        SWARM_LOG("Total size: %d", final_pkt + 1);
        int payload_byte = PAYLOAD_BYTE;
        if (time_chan) {
            payload_byte = payload_byte - TIMER_BYTE;
        }
        int msgSize = (final_pkt + 1) * payload_byte;
        unsigned char msg[msgSize];
        for (int i = 0; i < final_pkt + 1; i++) {
            memcpy(msg + i * payload_byte,
                   recvBuffer[assembler[i]].get_content(), payload_byte);
            if (time_chan) {
                // measure the time diff from the time bytes
                unsigned int prev_time =
                    recvBuffer[assembler[i]].get_time_bytes();
                unsigned int diff_time =
                    common::clock_diff(prev_time, cur_time);
                if (diff_time > longest_diff_time)
                    longest_diff_time = diff_time;
            }
        }

        SWARM_LOG("Msg formed: %.*s", msgSize, msg);
        /*
        for(int i = 0; i < msgSize; i++) {
            printf("%d %c\n", i, msg[i]);
        }
        */
        if (time_chan) {
            SWARM_LOG("Timer channel msg formed, time diff = %d",
                      longest_diff_time);
            meta->msg_delay = longest_diff_time;
        } else {
            meta->msg_delay = 0;
        }
        overflowCounter = 0;
        overflowFlag = false;
        /*
        printf("?????   BEFORE REVERSELY DELETE\n");
        // reversely delete the pkts
        for(int i = 0; i < (final_pkt + 1); i++) {
            printf("Assembler[%d] = %d\n", i, assembler[i]);
        }
        */
        for (int i = 0; i < (final_pkt + 1); i++) {
            int max_index = -1;
            int ass_index = -1;
            for (int j = 0; j < (final_pkt + 1); j++) {
                if (assembler[j] > max_index) {
                    ass_index = j;
                    max_index = assembler[j];
                }
            }
            /*
            printf("Max index = %d, Ass index = %d, pkt Num = %d\n", max_index,
            ass_index, recv_pktNum);
            */
            assembler[ass_index] = -1;
            memmove(recvBuffer + max_index, recvBuffer + max_index + 1,
                    (recv_pktNum - max_index - 1) * sizeof(Packet));
            recv_pktNum--;
        }

        // callback on all recvs
        for (int i = 0; i < MAX_SUB_PER_CHAN; i++) {
            if (subscribers[i].if_initialized() == true) {
                // TODO:: assuming /0 terminating
                SWARM_LOG("Callback on sub %d", i);
                subscribers[i].receive(msg, msgSize, ttl, meta);
            }
        }
    }
}

}  // namespace SwarmTalk

/**************************************************/
/********                                  ********/
/********        End of channel.cpp        ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********    Start of common_system.cpp    ********/
/********                                  ********/
/**************************************************/



#include <stdio.h>


namespace SwarmTalk {

Common_system::Common_system() {
    this->control_factory = NULL;
    this->user_loop = NULL;
    this->common_lock = common::dummy_lock;
    this->common_unlock = common::dummy_lock;
    this->common_get_clock = common::dummy_clock;
    this->common_random_func = common::dummy_rand_func;
}

unsigned int Common_system::get_clock() { return this->common_get_clock(); }

unsigned int Common_system::random_func() { return this->common_random_func(); }

void Common_system::lock() { this->common_lock(); }

void Common_system::unlock() { this->common_unlock(); }

void Common_system::execute_loop() {
    if (control_factory != NULL) {
        ((Control_factory_template*)control_factory)->update_control();
    }
    if (this->user_loop != NULL) {
        this->user_loop();
    }
}
void Common_system::register_control_factory(void* control_factory) {
    this->control_factory = control_factory;
    ((Control_factory_template*)this->control_factory)
        ->register_common_sys(this);
}

#if USE_FUNCTIONAL
void Common_system::register_user_loop(std::function<void()> user_loop) {
    this->user_loop = user_loop;
}

void Common_system::set_common_sys_get_clock(
    std::function<unsigned int()> get_clock) {
    this->common_get_clock = get_clock;
}

void Common_system::set_common_sys_random_func(
    std::function<unsigned int()> random_func) {
    this->common_random_func = random_func;
}

void Common_system::set_common_sys_lock(std::function<void()> lock) {
    this->common_lock = lock;
}

void Common_system::set_common_sys_unlock(std::function<void()> unlock) {
    this->common_unlock = unlock;
}

#else
void Common_system::register_user_loop(void (*user_loop)()) {
    this->user_loop = user_loop;
}

void Common_system::set_common_sys_get_clock(unsigned int (*get_clock)()) {
    this->common_get_clock = get_clock;
}

void Common_system::set_common_sys_random_func(unsigned int (*random_func)()) {
    this->common_random_func = random_func;
}

void Common_system::set_common_sys_lock(void (*lock)()) {
    this->common_lock = lock;
}

void Common_system::set_common_sys_unlock(void (*unlock)()) {
    this->common_unlock = unlock;
}
#endif

}  // namespace SwarmTalk

/**************************************************/
/********                                  ********/
/********     End of common_system.cpp     ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********        Start of packet.cpp       ********/
/********                                  ********/
/**************************************************/


#include <stdio.h>
#include <string.h>

namespace SwarmTalk {

Packet::Packet() { this->valid = false; }

Packet::Packet(unsigned char *pkt) { init(pkt); }

Packet::Packet(unsigned char *content, int size, unsigned int nodeId,
               unsigned int msgId, unsigned int seqNum, bool ifEnd,
               unsigned int chanNum, unsigned int ttl) {
    init(content, size, nodeId, msgId, seqNum, ifEnd, chanNum, ttl);
}

void Packet::init(unsigned char *pkt) {
    // create packet from raw packet
    SWARM_LOG("Create packet from raw packet");
    /*
    printf("== New Packet arrived! ==\r\n");
    // print out raw packet
    printf("*************************\r\n");
    for(int i = 0; i < PKT_SIZE; i++) {
        unsigned char n = pkt[i];
        for(int j = 0; j < 8; j++) {
            if (n & 1)
                printf("1");
            else
                printf("0");

            n >>= 1;
        }
        printf("  %c\r\n", n);
    }
    printf("*************************\r\n");
    */

    valid = true;
#if WITH_CRC
    {
        // check if CRC match
        int c = crc(pkt, PKT_SIZE - CRC_BYTE);

        SWARM_LOG("CRC checking ...\r\n");
        SWARM_LOG("CRC_in = %d; CRC_check = %d\r\n",
                  int(pkt[PKT_SIZE - CRC_BYTE]), c);

        if (pkt[PKT_SIZE - CRC_BYTE] == c) {
            SWARM_LOG("CRC passed\r\n");
            valid = true;
        } else {
            SWARM_LOG("CRC failed, abort!\r\n");
            valid = false;
            return;
        }
    }
#endif

    memcpy(header, pkt, HEADER_BYTE);

#if WITH_CRC
    memcpy(content, pkt + HEADER_BYTE, PKT_SIZE - HEADER_BYTE - CRC_BYTE);
#else
    memcpy(content, pkt + HEADER_BYTE, PKT_SIZE - HEADER_BYTE);
#endif

    print_data();
}

void Packet::init(unsigned char *content, int size, unsigned int nodeId,
                  unsigned int msgId, unsigned int seqNum, bool ifEnd,
                  unsigned int chanNum, unsigned int ttl) {
    // clear out header and content
    memset(this->content, 0, sizeof(this->content));
    memset(this->header, 0, sizeof(this->header));
    // create packet from meta data
    memcpy(this->content, content, size);
    common::encode(header, NODE_ID_OFFSET, NODE_ID_BITS, nodeId);
    common::encode(header, MSG_ID_OFFSET, MSG_ID_BITS, msgId);
    common::encode(header, SEQ_NUM_OFFSET, SEQ_NUM_BITS, seqNum);
    common::encode(header, IF_END_OFFSET, 1, ifEnd);
    common::encode(header, CHAN_TYPE_OFFSET, CHAN_TYPE_BITS, chanNum);
    common::encode(header, TTL_OFFSET, TTL_BITS, ttl);

    SWARM_LOG("Create packet from meta data");
    print_data();
}

Packet::~Packet() {}

int Packet::to_packet(unsigned char *pkt) {
    // convert to raw packet
    memcpy(pkt, header, HEADER_BYTE);
    memcpy(pkt + HEADER_BYTE, content, sizeof(content));
#if WITH_CRC
    pkt[PKT_SIZE - CRC_BYTE] = crc(pkt, PKT_SIZE - CRC_BYTE);
#endif

    // print out raw packet
    /*
    printf("*************************\r\n");
    for(int i = 0; i < PKT_SIZE; i++) {
        unsigned char n = pkt[i];
        for(int j = 0; j < 8; j++) {
            if (n & 1)
                printf("1");
            else
                printf("0");

            n >>= 1;
        }
        printf("  %c\r\n", n);
    }
    printf("*************************\r\n");
    */

    return PKT_SIZE;
}

void Packet::set_node_id(unsigned int id) {
    common::encode(header, NODE_ID_OFFSET, NODE_ID_BITS, id);
}

void Packet::print_data() {
    // print out meta data
    SWARM_LOG(
        "Size %d; Node id %d; Msg id %d; Seq num %d; If end %d; Channel %d; "
        "TTL %d",
        PAYLOAD_BYTE, get_node_id(), get_msg_id(), get_seq_num(), get_if_end(),
        get_chan_type(), get_ttl());
    SWARM_LOG("Message: %.*s", PAYLOAD_BYTE, content);
}

void Packet::decrease_hop() {
    uint8_t ttl = get_ttl() - 1;
    if (ttl == 0xFF) ttl = 0;
    common::encode(header, TTL_OFFSET, TTL_BITS, ttl);
}

void Packet::set_time_bytes(unsigned int time) {
    // clear the potential dirty bits
    time = time & (~(~(0U) << TIMER_BITS));
#if WITH_CRC
    memcpy(this->content + (PKT_SIZE - HEADER_BYTE - CRC_BYTE - TIMER_BYTE),
           &time, TIMER_BYTE);
#else
    memcpy(this->content + (PKT_SIZE - HEADER_BYTE - TIMER_BYTE), &time,
           TIMER_BYTE);
#endif
}

unsigned char *Packet::get_content() { return content; }

unsigned int Packet::get_node_id() {
    return common::decode(header, NODE_ID_OFFSET, NODE_ID_BITS);
}

unsigned int Packet::get_msg_id() {
    return common::decode(header, MSG_ID_OFFSET, MSG_ID_BITS);
}

unsigned int Packet::get_seq_num() {
    return common::decode(header, SEQ_NUM_OFFSET, SEQ_NUM_BITS);
}

bool Packet::get_if_end() {
    if (common::decode(header, IF_END_OFFSET, 1) == 0)
        return false;
    else
        return true;
}

unsigned int Packet::get_chan_type() {
    return common::decode(header, CHAN_TYPE_OFFSET, CHAN_TYPE_BITS);
}

unsigned int Packet::get_ttl() {
    return common::decode(header, TTL_OFFSET, TTL_BITS);
}

bool Packet::if_valid() { return valid; }

unsigned int Packet::get_time_bytes() {
    unsigned int ret = 0;
#if WITH_CRC
    memcpy(&ret,
           this->content + (PKT_SIZE - HEADER_BYTE - CRC_BYTE - TIMER_BYTE),
           TIMER_BYTE);
#else
    memcpy(&ret, this->content + (PKT_SIZE - HEADER_BYTE - TIMER_BYTE),
           TIMER_BYTE);
#endif
    // clear the potential dirty bits
    ret = ret & (~(~(0U) << TIMER_BITS));
    SWARM_LOG("Get timer: %d", ret);
    return ret;
}

unsigned char Packet::crc_check(unsigned char *pkt, int size, int in_crc) {
    // check CRC match
    SWARM_LOG("CRC checking ...");
    int c = crc(pkt, size);
    if (in_crc == c) {
        SWARM_LOG("CRC passed");
        return true;
    } else {
        SWARM_LOG("CRC failed, abort!");
        return false;
    }
}

unsigned char Packet::crc(unsigned char *pkt, int size) {
    // calculate CRC
    int crc = 0;
    for (int i = 0; i < size; i++) crc += pkt[i];
    return crc % 256;
}

}  // namespace SwarmTalk

/**************************************************/
/********                                  ********/
/********         End of packet.cpp        ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********      Start of publisher.cpp      ********/
/********                                  ********/
/**************************************************/



namespace SwarmTalk {

int Publisher::send(unsigned char *msg, int msgSize) {
    if (chan == NULL) return 0;
    return ((Channel *)chan)->send(msg, msgSize);
}

void Publisher::sent_callback() {
    if (callback != NULL) {
        callback();
    }
}

bool Publisher::available() {
    if (chan == NULL) return false;
    return ((Channel *)chan)->available();
}

bool Publisher::if_initialized() {
    if (callback == NULL)
        return false;
    else
        return true;
}

Publisher::Publisher() {
    this->chan = NULL;
    this->callback = NULL;
}

#if USE_FUNCTIONAL
Publisher::Publisher(void *chan, std::function<void()> callback) {
#else
Publisher::Publisher(void *chan, void (*callback)()) {
#endif
    publisher_init(chan, callback);
}

#if USE_FUNCTIONAL
void Publisher::publisher_init(void *chan, std::function<void()> callback) {
#else
void Publisher::publisher_init(void *chan, void (*callback)()) {
#endif
    this->chan = chan;
    this->callback = callback;
}

}  // namespace SwarmTalk

/**************************************************/
/********                                  ********/
/********       End of publisher.cpp       ********/
/********                                  ********/
/**************************************************/



/**************************************************/
/********                                  ********/
/********      Start of subscriber.cpp     ********/
/********                                  ********/
/**************************************************/


namespace SwarmTalk {

void Subscriber::receive(unsigned char *msg, int size, int hop, Meta_t *meta) {
    // if(dist < this->dist && this->callback != NULL) {
    if (this->callback != NULL && meta->dist < this->dist) {
        callback(msg, size, hop, meta);
    }
}

Subscriber::Subscriber() {
    this->dist = 0;
    this->callback = NULL;
}

bool Subscriber::if_initialized() {
    if (callback == NULL)
        return false;
    else
        return true;
}

#if USE_FUNCTIONAL
Subscriber::Subscriber(
    int dist,
    std::function<void(unsigned char *, int, int, Meta_t *)> callback) {
    subscriber_init(dist, callback);
}
void Subscriber::subscriber_init(
    int dist,
    std::function<void(unsigned char *, int, int, Meta_t *)> callback) {
    this->dist = dist;
    this->callback = callback;
}

#else
Subscriber::Subscriber(int dist,
                       void (*callback)(unsigned char *, int, int, Meta_t *)) {
    subscriber_init(dist, callback);
}
void Subscriber::subscriber_init(int dist,
                                 void (*callback)(unsigned char *, int, int,
                                                  Meta_t *)) {
    this->dist = dist;
    this->callback = callback;
}
#endif

}  // namespace SwarmTalk

/**************************************************/
/********                                  ********/
/********       End of subscriber.cpp      ********/
/********                                  ********/
/**************************************************/

