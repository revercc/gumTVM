//
// Created by reverccqin on 25-5-15.
//
#include "custom_hook.h"
#include <frida-gum.h>
#include <jni.h>
#include <unistd.h>
#include "common.h"
#include "instruction_tracer_manager.h"
// 是否重复trace
bool repeat_trace = true;

void hook_common_enter(GumInvocationContext * ic, gpointer user_data) {
    auto self = (InstructionTracerManager *)user_data;
    if (self->get_trace_tid() == 0 || self->get_trace_tid() == gettid()) {
        // 0x107618
        LOGD("FridaStalker::frida_on_enter : %d", gettid());
        self->set_trace_tid(gettid());
        // start trace
        self->follow();
    }
}

void hook_common_leave(GumInvocationContext * ic, gpointer user_data) {
    auto self = (InstructionTracerManager *)user_data;
    if (self->get_trace_tid() == gettid()) {
        LOGD("FridaStalker::frida_on_leave");
        self->unfollow();
        if (repeat_trace == false) {
            // 取消hook
            gum_interceptor_detach(self->get_gum_insterceptor(), self->get_common_invocation_listener());
            // 更新关闭trace文件
            self->get_logger_manager()->set_enable_to_file(false, "");
        }
    }
}