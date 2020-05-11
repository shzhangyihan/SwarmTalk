#ifndef __ST_CONTROL_UNIT_TEMPLATE_H__
#define __ST_CONTROL_UNIT_TEMPLATE_H__

#include "common_system.h"

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