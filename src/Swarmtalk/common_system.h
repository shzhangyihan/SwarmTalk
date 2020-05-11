#ifndef __ST_COMMON_SYSTEM_H__
#define __ST_COMMON_SYSTEM_H__

#include "util.h"

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