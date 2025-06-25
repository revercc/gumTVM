//
// Created by reverccqin on 25-5-15.
//

#include "instruction_tracer_manager.h"

#include <dlfcn.h>

#include <cassert>

#include "Utils.h"
#include "common.h"
#include "custom_hook.h"
#include "instruction_call_back.h"

InstructionTracerManager *InstructionTracerManager::get_instance() {
    static InstructionTracerManager instance;
    return &instance;
}

bool InstructionTracerManager::init(std::string module_name, uintptr_t offset) {
    this->trace_tid = 0;
    this->module_name = module_name;
    auto target_module = gum_process_find_module_by_name(module_name.c_str());
    if (target_module == nullptr) {
        LOGE("target module not found:%s", module_name.c_str());
        return false;
    }
    gum_module_ensure_initialized(target_module);
    auto target_range = gum_module_get_range(target_module);
    this->module_range.base = target_range->base_address;
    this->module_range.end = target_range->base_address + target_range->size;
    LOGD("target range: %lx %lx", this->module_range.base, this->module_range.end);
    if (offset > target_range->size) {
        LOGE("offset out of range:%s", module_name.c_str());
        g_object_unref(target_module);
        return false;
    }
    this->target_trace_address = target_range->base_address + offset;
    // 获取plt段偏移范围
    Dl_info dlInfo;
    dladdr(reinterpret_cast<void*>(this->module_range.base), &dlInfo);
    this->plt_range = Utils::get_plt_range(dlInfo.dli_fname);
    logger = std::make_unique<LoggerManager>(module_name, module_range);
    g_object_unref(target_module);
    return true;
}

InstructionTracerManager::InstructionTracerManager() {
    assert(gum_stalker_is_supported());
    m_stalker = gum_stalker_new();
    assert(m_stalker);
    // 信任阀值为始终信任
    gum_stalker_set_trust_threshold(m_stalker, 0);
    m_transformer = gum_stalker_transformer_make_from_callback(transform_callback, nullptr, nullptr);
    // m_sink = gum_event_sink_make_from_callback(GUM_CALL, event_sink_callback, nullptr, nullptr);
    assert(m_transformer);
}

InstructionTracerManager::~InstructionTracerManager() {
    g_object_unref(m_stalker);
    g_object_unref(m_transformer);
    g_object_unref(gum_insterceptor);
    g_object_unref(common_invocation_listener);
}

bool InstructionTracerManager::run_attach() {
    gum_insterceptor = gum_interceptor_obtain();
    gum_interceptor_begin_transaction(gum_insterceptor);
    common_invocation_listener = gum_make_call_listener(hook_common_enter, hook_common_leave, this, NULL);
    auto ret = gum_interceptor_attach(gum_insterceptor,
        (gpointer)target_trace_address,
        common_invocation_listener,nullptr, GUM_ATTACH_FLAGS_UNIGNORABLE);
    gum_interceptor_end_transaction(gum_insterceptor);
    return ret == GUM_ATTACH_OK;
}

GumInvocationListener* InstructionTracerManager::get_common_invocation_listener() const{
    return common_invocation_listener;
}

GumInterceptor* InstructionTracerManager::get_gum_insterceptor() const{
    return gum_insterceptor;
}

LoggerManager* InstructionTracerManager::get_logger_manager() const {
    return logger.get();
}

void InstructionTracerManager::set_trace_tid(pid_t trace_tid) {
    this->trace_tid = trace_tid;
}

pid_t InstructionTracerManager::get_trace_tid() const {
    return this->trace_tid;
}

void InstructionTracerManager::follow() {
    // gum_stalker_follow_me(m_stalker, m_transformer, m_sink);
    gum_stalker_follow_me(m_stalker, m_transformer, nullptr);
}

void InstructionTracerManager::follow(size_t thread_id) {
    // gum_stalker_follow(m_stalker, thread_id, m_transformer, m_sink);
    gum_stalker_follow(m_stalker, thread_id, m_transformer, nullptr);
}

void InstructionTracerManager::unfollow() {
    gum_stalker_unfollow_me(m_stalker);
}

void InstructionTracerManager::unfollow(size_t thread_id) {
    gum_stalker_unfollow(m_stalker, thread_id);
}

bool InstructionTracerManager::is_address_in_module_range(uintptr_t addr) const {
    if (addr < this->module_range.base) {
        return false;
    }
    if (addr > this->module_range.end) {
        return false;
    }
    return true;
}

module_range_t InstructionTracerManager::get_module_range() const {
    return this->module_range;
}

std::pair<size_t, size_t> InstructionTracerManager::get_plt_range() const {
    return this->plt_range;
}
