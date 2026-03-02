//
// Created by reverccqin on 25-5-15.
//

#ifndef STALKER_H
#define STALKER_H
#include <frida-gum.h>
#include <fstream>
#include <map>
#include <string>
#include "common.h"
#include "logger_manager.h"


struct _GumStalker;
typedef _GumStalker GumStalker;
struct _GumStalkerTransformer;
typedef _GumStalkerTransformer GumStalkerTransformer;

struct REG_LIST{
    int num = 0;
    arm64_reg regs[31] = {};
};

// 寄存器计数器结构 - 用于为每个寄存器分配唯一编号
struct RegisterCounter {
    std::map<std::string, uint64_t> reg_counters;  // 寄存器名 -> 当前计数
    uint64_t global_counter = 0;                    // 全局计数器

    // 获取寄存器的下一个编号
    uint64_t get_next_id(const std::string& reg_name) {
        return ++global_counter;
    }

    // 重置计数器
    void reset() {
        reg_counters.clear();
        global_counter = 0;
    }
};

// 内存地址计数器结构 - 用于为每个内存地址分配唯一编号
struct MemoryAddressCounter {
    uint64_t global_counter = 0;  // 全局内存地址计数器

    // 获取下一个内存地址编号
    uint64_t get_next_id() {
        return ++global_counter;
    }

    // 重置计数器
    void reset() {
        global_counter = 0;
    }
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
    bool is_address_in_other_module_range(uintptr_t addr) const;
    bool add_trace_other_module_entry(const std::string& name, bool status);
    bool add_trace_other_module_range_entry(const std::string& name, std::pair<size_t, size_t> range);
    std::map<std::string, bool>& get_trace_other_modules();
    std::map<std::string, std::pair<size_t, size_t>>& get_trace_other_modules_range();
    [[nodiscard]] module_range_t get_module_range() const;
    void set_plt_range(std::pair<size_t, size_t> range);
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
    // 寄存器计数器 - 用于日志中的寄存器编号
    RegisterCounter reg_counter;
    // 内存地址计数器 - 用于日志中的内存地址编号
    MemoryAddressCounter mem_counter;
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
    // trace other modules
    std::map<std::string, bool> trace_other_modules;
    // trace other modules range
    std::map<std::string, std::pair<size_t, size_t>> trace_other_modules_range;
};
#endif //STALKER_H
