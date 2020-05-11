#ifndef __ST_KILOBOT_CONTROL_DRIVER_H__
#define __ST_KILOBOT_CONTROL_DRIVER_H__

extern "C" {
#include <kilolib.h>
}

#include "../../Swarmtalk/control_unit_template.h"

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