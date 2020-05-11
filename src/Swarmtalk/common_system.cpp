
#include "common_system.h"

#include <stdio.h>

#include "control_unit_template.h"

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