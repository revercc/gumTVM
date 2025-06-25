//
// Created by reverccqin on 25-5-15.
//

#ifndef STALKER_H
#define STALKER_H
#include "logger_manager.h"
#include "common.h"
#include <frida-gum.h>
#include <fstream>
#include <string>



struct _GumStalker;
typedef _GumStalker GumStalker;
struct _GumStalkerTransformer;
typedef _GumStalkerTransformer GumStalkerTransformer;

struct REG_LIST{
    int num = 0;
    arm64_reg regs[31] = {};
};

class InstructionTracerManager {
public:
    static InstructionTracerManager *get_instance();
    explicit InstructionTracerManager();
    ~InstructionTracerManager();
    [[nodiscard]] bool init(std::string module_name, uintptr_t offset);
    void follow();
    void follow(size_t thread_id);
    void unfollow();
    void unfollow(size_t thread_id);
    [[nodiscard]] bool is_address_in_module_range(uintptr_t addr) const;
    [[nodiscard]] module_range_t get_module_range() const;
    [[nodiscard]] std::pair<size_t, size_t> get_plt_range() const;
    bool run_attach();
    [[nodiscard]] GumInvocationListener* get_common_invocation_listener() const;
    [[nodiscard]] GumInterceptor* get_gum_insterceptor() const;
    [[nodiscard]] LoggerManager* get_logger_manager() const;
    void set_trace_tid(pid_t trace_tid);
    [[nodiscard]] pid_t get_trace_tid() const;
    // write reg list
    REG_LIST write_reg_list;
    // 下一条br指令是plt_jmp指令
    bool is_plt_jmp;
private:

    GumStalker *m_stalker;
    GumStalkerTransformer *m_transformer;
    GumEventSink *m_sink;
    GumInterceptor *gum_insterceptor;
    GumInvocationListener* common_invocation_listener;
    std::unique_ptr<LoggerManager> logger;
    //target address
    uintptr_t target_trace_address = 0;
    //trace tid
    pid_t trace_tid;
    //trace library name
    std::string module_name;
    //trace symbol name
    std::string symbol_name;
    //trace library memory range
    module_range_t module_range;
    //trace library plt range
    std::pair<size_t, size_t> plt_range;
};
#endif //STALKER_H
