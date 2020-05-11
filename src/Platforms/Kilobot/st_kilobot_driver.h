#ifndef __ST_KILOBOT_DRIVER_H__
#define __ST_KILOBOT_DRIVER_H__

#define DEBUG

extern "C" {
#include <kilolib.h>

// #include "debug.h"
}

#include "../../Swarmtalk/swarmtalk.h"
#include "control_driver.h"

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