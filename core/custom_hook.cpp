//
// Created by reverccqin on 25-5-15.
//
#include "custom_hook.h"
#include <frida-gum.h>
#include <jni.h>
#include <unistd.h>
#include <sys/system_properties.h>
#include "common.h"
#include "instruction_tracer_manager.h"
bool repeat_trace = false;      // 是否重复trace
bool trace_is_running = false;  // 是否已经开始trace
int tid_call_sum = 1;           // trace 线程调用回调函数深度


// 9.10.35.105  com.taobao.trip doCommand
void trip_doCommand_enter(GumInvocationContext * ic, gpointer user_data) {
    auto self = (InstructionTracerManager *)user_data;
    if (ic->cpu_context->x[0] == 7 &&
        ic->cpu_context->x[1] == 1 &&
        ic->cpu_context->x[2] == 2 ) {

        LOGD("FridaStalker::frida_on_enter : %d", gettid());
        trace_is_running = true;
        self->set_trace_tid(gettid());
        // 添加其他需要trace 的模块
        self->add_trace_other_module_entry("libsgsecuritybodyso-6.6.230703.so", false);
        self->add_trace_other_module_entry("libsgmiddletierso-6.6.230703.so", false);
        // start trace
        self->follow();
    }
}


void hook_common_enter(GumInvocationContext * ic, gpointer user_data) {
    auto self = (InstructionTracerManager *)user_data;
    if (self->get_trace_tid() == 0 || self->get_trace_tid() == gettid()) {
        // 回调函数调用深度 + 1
        if (self->get_trace_tid() == gettid()) {
            tid_call_sum++;
        }

        // trace 是否已经再跑，不允许重复进入trace
        if (trace_is_running == false) {
            trip_doCommand_enter(ic, user_data);
        }
    }
}

void hook_common_leave(GumInvocationContext * ic, gpointer user_data) {
    auto self = (InstructionTracerManager *)user_data;
    if (self->get_trace_tid() == gettid()) {
        tid_call_sum--;
        if (tid_call_sum == 0) {
            LOGD("FridaStalker::frida_on_leave");
            if (repeat_trace == false) {
                self->unfollow();
                // 取消hook
                gum_interceptor_detach(self->get_gum_insterceptor(), self->get_common_invocation_listener());
                // 更新关闭trace文件
                self->get_logger_manager()->set_enable_to_file(false, "");
            }
        }
    }
}