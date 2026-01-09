//
// Created by reverccqin on 25-5-17.
//

#include "instruction_call_back.h"

#include <dlfcn.h>

#include <frida-gum.h>
#include <iomanip>
#include <ios>
#include <iosfwd>
#include <sstream>
#include <unordered_set>
#include "common.h"
#include "instruction_tracer_manager.h"

bool get_register_value(arm64_reg reg, GumCpuContext* ctx, uint64_t& out_value) {
    uint64_t value = 0;

    // 特殊处理零寄存器
    if (reg == ARM64_REG_WZR || reg == ARM64_REG_XZR || reg == ARM64_REG_WSP) {
        out_value = value;
        return true;
    }

    // 支持 W0 ~ W30 映射为 Xn & 0xFFFFFFFF
    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) {
        int idx = reg - ARM64_REG_W0;
        value = ctx->x[idx] & 0xFFFFFFFF;
    }
    // 支持 X0 ~ X30
    else if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) {
        int idx = reg - ARM64_REG_X0;
        value = ctx->x[idx];
    }
    else {
        switch (reg) {
            case ARM64_REG_SP: value = ctx->sp; break;
            case ARM64_REG_FP: value = ctx->fp; break;      // ARM64_REG_X29
            case ARM64_REG_LR: value = ctx->lr; break;      // ARM64_REG_X30
            default:
                return false; // 不支持的寄存器
        }
    }

    out_value = value;
    return true;
}

// 获取STP/LDP指令的访问大小
size_t get_stp_ldp_access_size(const InstructionInfo *insn) {
    // 检查寄存器类型
    for (int i = 0; i < insn->insn_copy.detail->arm64.op_count; i++) {
        cs_arm64_op &op = insn->insn_copy.detail->arm64.operands[i];
        if (op.type == ARM64_OP_REG) {
            // 判断寄存器类型
            if (op.reg >= ARM64_REG_Q0 && op.reg <= ARM64_REG_Q31) {
                return 16;  // Q寄存器: 128位
            } else if (op.reg >= ARM64_REG_D0 && op.reg <= ARM64_REG_D31) {
                return 8;   // D寄存器: 64位
            } else if (op.reg >= ARM64_REG_S0 && op.reg <= ARM64_REG_S31) {
                return 4;   // S寄存器: 32位
            } else if (op.reg >= ARM64_REG_H0 && op.reg <= ARM64_REG_H31) {
                return 2;   // H寄存器: 16位
            } else if (op.reg >= ARM64_REG_B0 && op.reg <= ARM64_REG_B31) {
                return 1;   // B寄存器: 8位
            } else if (op.reg >= ARM64_REG_W0 && op.reg <= ARM64_REG_W30) {
                return 4;   // W寄存器: 32位
            }
            // X寄存器: 64位 (默认)
        }
    }
    return 8;  // 默认64位
}

// 判断是否是内存访问指令
bool is_memory_access_instruction(int insn_id) {
    static const std::unordered_set<int> memory_instructions = {
        // 存储指令
        ARM64_INS_STR, ARM64_INS_STRB, ARM64_INS_STRH,
        ARM64_INS_STUR, ARM64_INS_STURB, ARM64_INS_STURH,
        ARM64_INS_STLR, ARM64_INS_STLRB, ARM64_INS_STLRH,
        ARM64_INS_STP, ARM64_INS_STNP,
        ARM64_INS_STXP, ARM64_INS_STLXP,

        // 加载指令
        ARM64_INS_LDR, ARM64_INS_LDRB, ARM64_INS_LDRH,
        ARM64_INS_LDUR, ARM64_INS_LDURB, ARM64_INS_LDURH,
        ARM64_INS_LDAR, ARM64_INS_LDARB, ARM64_INS_LDARH,
        ARM64_INS_LDP, ARM64_INS_LDNP,
        ARM64_INS_LDXP, ARM64_INS_LDAXP,
        ARM64_INS_LDRSW, ARM64_INS_LDURSW,
        ARM64_INS_LDRSH, ARM64_INS_LDURSH,

        // 原子/排他
        ARM64_INS_LDAPR, ARM64_INS_LDAPRB, ARM64_INS_LDAPRH,
        ARM64_INS_LDAPUR, ARM64_INS_LDAPURB, ARM64_INS_LDAPURH,
        ARM64_INS_LDAPURSW,
    };

    return memory_instructions.count(insn_id) > 0;
}

// 获取指令的访问大小
size_t get_memory_access_size(const InstructionInfo *insn) {
    size_t access_size = 8;  // 默认64位
    int insn_id = insn->insn_copy.id;
    const char* mnemonic = insn->insn_copy.mnemonic;

    switch (insn_id) {
        // ============ 1字节访问 ============
        case ARM64_INS_STRB:
        case ARM64_INS_STURB:
        case ARM64_INS_STLRB:
        case ARM64_INS_LDRB:
        case ARM64_INS_LDURB:
        case ARM64_INS_LDARB:
        case ARM64_INS_LDAPRB:
        case ARM64_INS_LDAPURB:
            access_size = 1;
            break;

        // ============ 2字节访问 ============
        case ARM64_INS_STRH:
        case ARM64_INS_STURH:
        case ARM64_INS_STLRH:
        case ARM64_INS_LDRH:
        case ARM64_INS_LDURH:
        case ARM64_INS_LDARH:
        case ARM64_INS_LDAPRH:
        case ARM64_INS_LDAPURH:
        case ARM64_INS_LDRSH:   // 有符号半字加载
        case ARM64_INS_LDURSH:
            access_size = 2;
            break;

        // ============ 4字节访问 ============
        case ARM64_INS_STR:
        case ARM64_INS_STUR:
        case ARM64_INS_STLR:
            // 需要检查是否是w寄存器
            if (strstr(insn->insn_copy.op_str, "w") != nullptr) {
                access_size = 4;
            }
            break;

        case ARM64_INS_LDR:
        case ARM64_INS_LDUR:
        case ARM64_INS_LDAR:
        case ARM64_INS_LDAPR:
        case ARM64_INS_LDAPUR:
            // 检查是否是w寄存器或有符号字加载
            if (strstr(insn->insn_copy.op_str, "w") != nullptr ||
                strstr(mnemonic, "ldrsw") != nullptr ||
                strstr(mnemonic, "ldursw") != nullptr) {
                access_size = 4;
            }
            break;

        case ARM64_INS_LDRSW:   // 有符号字加载
        case ARM64_INS_LDURSW:
        case ARM64_INS_LDAPURSW:
            access_size = 4;
            break;

        // ============ STP/LDP 指令 ============
        case ARM64_INS_STP:
        case ARM64_INS_STNP:
        case ARM64_INS_LDP:
        case ARM64_INS_LDNP:
            // STP/LDP需要根据寄存器类型确定大小
            access_size = get_stp_ldp_access_size(insn);
            break;
        // ============ 原子/排他访问 ============
        case ARM64_INS_STXP:
        case ARM64_INS_STLXP:
        case ARM64_INS_LDXP:
        case ARM64_INS_LDAXP:
            // 排他访问通常是8字节，但取决于寄存器类型
            access_size = 8;
            break;

        // ============ 默认: 8字节 ============
        default:
            // 对于其他内存访问指令，检查操作数
            if (is_memory_access_instruction(insn_id)) {
                // 尝试从操作字符串推断
                if (strstr(insn->insn_copy.op_str, "w") != nullptr) {
                    access_size = 4;
                }
            }
            break;
    }

    return access_size;
}


// 获取内存地址和相关寄存器信息
struct MemoryAddressInfo {
    uintptr_t addr;           // 计算后的内存地址
    uint64_t base_value;      // 基址寄存器值
    uint64_t index_value;     // 索引寄存器值
    std::string base_name;    // 基址寄存器名
    std::string index_name;   // 索引寄存器名
    bool has_base;           // 是否有基址寄存器
    bool has_index;          // 是否有索引寄存器
};

bool get_memory_address_info(csh handle, const cs_arm64_op &op, GumCpuContext *ctx,
                            MemoryAddressInfo &info) {
    // 初始化
    info.addr = 0;
    info.base_value = 0;
    info.index_value = 0;
    info.has_base = false;
    info.has_index = false;
    info.base_name = "";
    info.index_name = "";

    // 处理基址寄存器
    if (op.mem.base != ARM64_REG_INVALID) {
        if (!get_register_value(op.mem.base, ctx, info.base_value)) {
            return false;
        }
        info.has_base = true;
        info.base_name = cs_reg_name(handle, op.mem.base);
    }

    // 处理索引寄存器
    if (op.mem.index != ARM64_REG_INVALID) {
        if (!get_register_value(op.mem.index, ctx, info.index_value)) {
            return false;
        }
        info.has_index = true;
        info.index_name = cs_reg_name(handle, op.mem.index);
    }

    // 计算地址
    info.addr = info.base_value + info.index_value + op.mem.disp;
    return true;
}

// 获取要存储的寄存器值
bool get_store_register_values(const InstructionInfo *insn, GumCpuContext *ctx,
                              std::vector<uint64_t> &values) {
    values.clear();

    for (int i = 0; i < insn->detail_copy->arm64.op_count; i++) {
        cs_arm64_op &op = insn->detail_copy->arm64.operands[i];
        if (op.type == ARM64_OP_REG && (op.access & CS_AC_READ)) {
            uint64_t reg_value = 0;
            if (get_register_value(op.reg, ctx, reg_value)) {
                values.push_back(reg_value);
            }
        }
    }

    return !values.empty();
}

// 读取内存值
bool read_memory_value(uintptr_t addr, size_t size, uint64_t &value) {
    if (size == 1) value = *(uint8_t*)addr;
    else if (size == 2) value = *(uint16_t*)addr;
    else if (size == 4) value = *(uint32_t*)addr;
    else if (size == 8) value = *(uint64_t*)addr;
    return true;
}

// 是否是原子操作指令
bool is_lse(cs_insn* insn) {
    bool skip = false;
    switch (insn->id)
    {
        case ARM64_INS_LDAXR:
        case ARM64_INS_LDAXP:
        case ARM64_INS_LDAXRB:
        case ARM64_INS_LDAXRH:
        case ARM64_INS_LDXR:
        case ARM64_INS_LDXP:
        case ARM64_INS_LDXRB:
        case ARM64_INS_LDXRH:
        case ARM64_INS_STXR:
        case ARM64_INS_STXP:
        case ARM64_INS_STXRB:
        case ARM64_INS_STXRH:
        case ARM64_INS_STLXR:
        case ARM64_INS_STLXP:
        case ARM64_INS_STLXRB:
        case ARM64_INS_STLXRH: {
            skip = true;
            break;
        }
        default:
            skip = false;
    }
    return skip;
}

// 基本块回调
void transform_callback(GumStalkerIterator *iterator, GumStalkerOutput *output, gpointer user_data) {
    const auto self = InstructionTracerManager::get_instance();
    if (self == nullptr) {
        LOGE("transform_callback data is nullptr");
        return;
    }

    // 添加其他待trace模块到追踪范围中
    auto& other_modules = self->get_trace_other_modules();
    for (const auto& [name, status] : other_modules) {
        if (!status) {
            GumModule* gum_module = gum_process_find_module_by_name(name.c_str());
            if (gum_module != nullptr) {
                const GumMemoryRange* gumMemoryRange = gum_module_get_range(gum_module);
                self->add_trace_other_module_range_entry(name, std::make_pair(gumMemoryRange->base_address, gumMemoryRange->base_address + gumMemoryRange->size));
                other_modules[name] = true;
            }
        }
    }


    cs_insn *p_insn;
    auto *it = iterator;
    while (gum_stalker_iterator_next(it, (const cs_insn **)&p_insn)) {
        if (is_lse(p_insn) == false && (self->is_address_in_module_range(p_insn->address) || self->is_address_in_other_module_range(p_insn->address))) {
            auto *instruction_info = new InstructionInfo(p_insn,gum_stalker_iterator_get_capstone(it));
            gum_stalker_iterator_put_callout(it,
                instruction_callback,
                instruction_info,
                [](gpointer user_data) {
                auto *ctx = static_cast<InstructionInfo *>(user_data);
                delete ctx;
            });
        }
        gum_stalker_iterator_keep(it);
    }
}

void instruction_callback(GumCpuContext *context, void *user_data) {
    const auto ctx = context;
    auto insn_info = (InstructionInfo *)user_data;
    if (insn_info == nullptr) {
        LOGE("instruction_callback data is nullptr");
        return;
    }
    auto self = InstructionTracerManager::get_instance();

    std::stringstream outinfo;
    std::stringstream postOutput;
    std::stringstream regOutput;
    // 遍历操作数并记录写入的寄存器状态
    if (self->write_reg_list.num) {
        for (int i = 0; i < self->write_reg_list.num; i++) {
            uint64_t reg_value = 0;
            if (get_register_value(self->write_reg_list.regs[i], ctx, reg_value)) {
                const char* reg_name = cs_reg_name( insn_info->handle, self->write_reg_list.regs[i]);
                postOutput << reg_name << "=0x" << std::hex << reg_value << " ";
                postOutput.flush();
                regOutput << self->get_logger_manager()->dump_reg_value(reg_value, reg_name);
            }
        }
        self->write_reg_list.num = 0;
    }
    if (!postOutput.str().empty()) {
        outinfo << "\t w[" << postOutput.str() << "]" << std::endl << regOutput.str();
    }


    uint64_t current_ins_base = self->get_module_range().base;
    if (self->is_address_in_module_range(ctx->pc)) {
        // 输出当前指令地址和反汇编信息
        outinfo << "0x" << std::left << std::setw(8) << std::hex << (ctx->pc - current_ins_base) << "   "
        << std::left << insn_info->insn_copy.mnemonic << "\t"
        << insn_info->insn_copy.op_str;
    } else{
        auto& other_modules_range = self->get_trace_other_modules_range();
        for (const auto& [name, range] : other_modules_range) {
            if (ctx->pc > range.first && ctx->pc < range.second) {
                current_ins_base = range.first;
            }
        }

        // 输出当前指令地址和反汇编信息
        outinfo << "0x" << std::left << std::setw(8) << std::hex << ctx->pc << "(" << (ctx->pc - current_ins_base) << ")    "
        << std::left << insn_info->insn_copy.mnemonic << "\t"
        << insn_info->insn_copy.op_str;
    }


    // 针对立即数跳转指令需要计算出其对应偏移
    if (cs_insn_group(insn_info->handle, &insn_info->insn_copy, CS_GRP_JUMP) ||
        cs_insn_group(insn_info->handle, &insn_info->insn_copy, CS_GRP_CALL) ||
        cs_insn_group(insn_info->handle, &insn_info->insn_copy, CS_GRP_RET)) {
        if (insn_info->detail_copy->arm64.operands[0].type == CS_OP_IMM) {
            outinfo << "(0x" << std::hex << insn_info->detail_copy->arm64.operands[0].imm - current_ins_base << ")";
        }
    }
    outinfo << "   ;";


    std::stringstream memory_access_info;
    for (int i = 0; i < insn_info->detail_copy->arm64.op_count; i++) {
        cs_arm64_op &op = insn_info->detail_copy->arm64.operands[i];
        // 获取读寄存器
        if (op.access & CS_AC_READ && op.type == ARM64_OP_REG) {
            uint64_t reg_value = 0;
            if (get_register_value(op.reg, ctx, reg_value)) {
                const char* reg_name = cs_reg_name(insn_info->handle, op.reg);
                outinfo << std::right << reg_name << " = 0x"
                       << std::left << std::hex << reg_value << ", ";
            }
        }

        // 获取写寄存器
        if (op.access & CS_AC_WRITE && op.type == ARM64_OP_REG) {
            self->write_reg_list.regs[self->write_reg_list.num++] = op.reg;
        }

        // 解析内存访问信息
        if (op.type == ARM64_OP_MEM) {
            MemoryAddressInfo memory_address_info = {0};
            if (!get_memory_address_info(insn_info->handle, op, ctx, memory_address_info)) {
                continue;
            }
            // 如果有基地址寄存器/索引地址寄存器，先打印
            if (memory_address_info.has_base) {
                outinfo << std::right << memory_address_info.base_name << " = 0x"
                       << std::left << std::hex << memory_address_info.base_value << ", ";
            }
            if (memory_address_info.has_index) {
                outinfo << std::right << memory_address_info.index_name << " = 0x"
                       << std::left << std::hex << memory_address_info.index_value << ", ";
            }

            // 获取指令访问size
            size_t access_size = get_memory_access_size(insn_info);
            bool is_pair_instruction = false;
            if (insn_info->insn_copy.id == ARM64_INS_STP || insn_info->insn_copy.id == ARM64_INS_LDP) {
                is_pair_instruction = true;
            }

            // 解析内存写信息
            if (op.access & CS_AC_WRITE) {
                // 内存写入
                if (is_pair_instruction) {
                    // stp/ldp 指令（对于ldp，如果是CS_AC_WRITE，表示写入寄存器，不是内存）
                    std::vector<uint64_t> reg_values;
                    if (get_store_register_values(insn_info, ctx, reg_values)) {
                        if (reg_values.size() >= 2) {
                            if (!memory_access_info.str().empty()) {
                                memory_access_info << ", ";
                            }
                            memory_access_info << "mem[w]:0x" << std::hex << memory_address_info.addr
                                              << " size:" << access_size
                                              << " value:0x" << std::hex << reg_values[0];
                            memory_access_info << ", mem[w]:0x" << std::hex << (memory_address_info.addr + access_size)
                                              << " size:" << access_size
                                              << " value:0x" << std::hex << reg_values[1];
                        }
                    }
                } else {
                    // 普通存储指令
                    std::vector<uint64_t> reg_values;
                    if (get_store_register_values(insn_info, ctx, reg_values)) {
                        if (!reg_values.empty()) {
                            if (!memory_access_info.str().empty()) {
                                memory_access_info << ", ";
                            }
                            memory_access_info << "mem[w]:0x" << std::hex << memory_address_info.addr
                                              << " size:" << access_size
                                              << " value:0x" << std::hex << reg_values[0];
                        }
                    }
                }
            }
            // 解析内存读信息
            else if (op.access & CS_AC_READ) {
                // 内存读取
                uint64_t mem_value = 0;
                if (read_memory_value(memory_address_info.addr, access_size, mem_value)) {
                    if (!memory_access_info.str().empty()) {
                        memory_access_info << ", ";
                    }

                    if (is_pair_instruction) {
                        // ldp 指令读取两个值
                        uint64_t mem_value2 = 0;
                        read_memory_value(memory_address_info.addr + access_size, access_size, mem_value2);

                        memory_access_info << "mem[r]:0x" << std::hex << memory_address_info.addr
                                          << " size:" << access_size
                                          << " value:0x" << std::hex << mem_value;
                        memory_access_info << ", mem[r]:0x" << std::hex << (memory_address_info.addr + access_size)
                                          << " size:" << access_size
                                          << " value:0x" << std::hex << mem_value2;
                    } else {
                        // 普通加载指令
                        memory_access_info << "mem[r]:0x" << std::hex << memory_address_info.addr
                                          << " size:" << access_size
                                          << " value:0x" << std::hex << mem_value;
                    }
                }
            }
        }
    }
    outinfo << std::endl;

    // 解析函数调用信息
    uintptr_t jmp_addr = 0;
    if (insn_info->insn_copy.id == ARM64_INS_BL &&
        insn_info->detail_copy->arm64.operands[0].type == CS_OP_IMM) {
        jmp_addr = insn_info->detail_copy->arm64.operands[0].imm;
    } else if (insn_info->insn_copy.id == ARM64_INS_BLR &&
        insn_info->detail_copy->arm64.operands[0].type == CS_OP_REG) {
        get_register_value(insn_info->detail_copy->arm64.operands[0].reg, ctx, jmp_addr);
    } else if (insn_info->insn_copy.id == ARM64_INS_BR && self->is_plt_jmp &&
        insn_info->detail_copy->arm64.operands[0].type == CS_OP_REG) {
        self->is_plt_jmp = false;
        get_register_value(insn_info->detail_copy->arm64.operands[0].reg, ctx, jmp_addr);
    }
    if (jmp_addr != 0) {
        Dl_info dlInfo;
        if(dladdr(reinterpret_cast<const void *>(jmp_addr), &dlInfo) && dlInfo.dli_fname != nullptr){
            const char * soName = strrchr(dlInfo.dli_fname, '/') + 1;
            const char * symName = dlInfo.dli_sname;
            if (symName == nullptr) {
                std::ostringstream oss;
                oss << "sub_" << std::hex << (jmp_addr - (uintptr_t)dlInfo.dli_fbase);
                symName = oss.str().c_str();
            }
            outinfo << "call addr: " << std::hex << jmp_addr << " [" << soName << "!" << symName << "]" << std::endl;
        }
    }
    // 开启打印 plt表的外部函数调用会很耗时
    /*
    else if (jmp_addr != 0 &&
        (jmp_addr - self->get_module_range().base) <= self->get_plt_range().second &&
        (jmp_addr - self->get_module_range().base) >= self->get_plt_range().first) {
        self->is_plt_jmp = true;
    }
    */

    // 打印内存读写信息
    if (!memory_access_info.str().empty()) {
        outinfo << "   " << memory_access_info.str() << std::endl;
    }

    // 写入日志文件
    self->get_logger_manager()->write_info(outinfo);
}

// typedef void (* GumEventSinkCallback) (const GumEvent * event, GumCpuContext * cpu_context, gpointer user_data);
void event_sink_callback(const GumEvent * event, GumCpuContext * cpu_context, gpointer user_data) {
    std::stringstream outinfo;
    auto self = InstructionTracerManager::get_instance();
    switch (event->type) {
        case GUM_CALL:
            if (!self->is_address_in_module_range((uintptr_t)event->call.target) && self->is_address_in_module_range(cpu_context->pc)) {
                outinfo << "call addr: " << "event_sink_callback" << std::endl;
            }
            break;
        default:
            break;
    }
    // 写入日志文件
    self->get_logger_manager()->write_info(outinfo);
}