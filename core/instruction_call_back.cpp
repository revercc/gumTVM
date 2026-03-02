//
// Created by reverccqin on 25-5-17.
//

#include "instruction_call_back.h"

#include <dlfcn.h>

#include <frida-gum.h>
#include <xdl.h>

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

// 获取128位向量寄存器完整值 (用于 Q/V 寄存器)
bool get_vector_register_value(arm64_reg reg, GumCpuContext* ctx, uint8_t out_value[16]) {
    int idx = -1;

    if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) {
        idx = reg - ARM64_REG_Q0;
    } else if (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31) {
        idx = reg - ARM64_REG_V0;
    } else if (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31) {
        idx = reg - ARM64_REG_D0;
    } else if (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) {
        idx = reg - ARM64_REG_S0;
    } else if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31) {
        idx = reg - ARM64_REG_H0;
    } else if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31) {
        idx = reg - ARM64_REG_B0;
    }

    if (idx < 0 || idx > 31) {
        return false;
    }

    memcpy(out_value, ctx->v[idx].q, 16);
    return true;
}

// 获取浮点寄存器值并格式化为字符串
std::string get_fp_register_string(arm64_reg reg, GumCpuContext* ctx) {
    std::stringstream ss;
    int idx = -1;

    // Q寄存器 (128位)
    if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) {
        idx = reg - ARM64_REG_Q0;
        uint64_t low, high;
        memcpy(&low, ctx->v[idx].q, sizeof(uint64_t));
        memcpy(&high, ctx->v[idx].q + 8, sizeof(uint64_t));
        ss << "Q" << idx << "=0x" << std::hex << std::setfill('0')
           << std::setw(16) << high << std::setw(16) << low;
    }
        // V寄存器 (128位向量)
    else if (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31) {
        idx = reg - ARM64_REG_V0;
        uint64_t low, high;
        memcpy(&low, ctx->v[idx].q, sizeof(uint64_t));
        memcpy(&high, ctx->v[idx].q + 8, sizeof(uint64_t));
        ss << "V" << idx << "=0x" << std::hex << std::setfill('0')
           << std::setw(16) << high << std::setw(16) << low;
    }
        // D寄存器 (64位 double)
    else if (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31) {
        idx = reg - ARM64_REG_D0;
        double d_val;
        uint64_t raw_val;
        memcpy(&d_val, ctx->v[idx].q, sizeof(double));
        memcpy(&raw_val, ctx->v[idx].q, sizeof(uint64_t));
        ss << "D" << idx << "=" << d_val << " (0x" << std::hex << raw_val << ")";
    }
        // S寄存器 (32位 float)
    else if (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) {
        idx = reg - ARM64_REG_S0;
        float s_val;
        uint32_t raw_val;
        memcpy(&s_val, ctx->v[idx].q, sizeof(float));
        memcpy(&raw_val, ctx->v[idx].q, sizeof(uint32_t));
        ss << "S" << idx << "=" << s_val << " (0x" << std::hex << raw_val << ")";
    }
        // H寄存器 (16位 half)
    else if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31) {
        idx = reg - ARM64_REG_H0;
        uint16_t raw_val;
        memcpy(&raw_val, ctx->v[idx].q, sizeof(uint16_t));
        ss << "H" << idx << "=0x" << std::hex << raw_val;
    }
        // B寄存器 (8位 byte)
    else if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31) {
        idx = reg - ARM64_REG_B0;
        ss << "B" << idx << "=0x" << std::hex << (int)ctx->v[idx].q[0];
    }
    else {
        return "";
    }

    return ss.str();
}

// 判断是否是浮点/向量寄存器
bool is_fp_vector_register(arm64_reg reg) {
    return (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) ||
           (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31) ||
           (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) ||
           (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31) ||
           (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31) ||
           (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31);
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


// ============ SIMD 指令支持 ============

// 判断是否是SIMD加载指令
bool is_simd_load(int insn_id) {
    return insn_id == ARM64_INS_LD1 || insn_id == ARM64_INS_LD2 ||
           insn_id == ARM64_INS_LD3 || insn_id == ARM64_INS_LD4 ||
           insn_id == ARM64_INS_LD1R || insn_id == ARM64_INS_LD2R ||
           insn_id == ARM64_INS_LD3R || insn_id == ARM64_INS_LD4R;
}

// 判断是否是SIMD存储指令
bool is_simd_store(int insn_id) {
    return insn_id == ARM64_INS_ST1 || insn_id == ARM64_INS_ST2 ||
           insn_id == ARM64_INS_ST3 || insn_id == ARM64_INS_ST4;
}

// 判断是否是向量寄存器
bool is_vector_register(arm64_reg reg) {
    return (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31) ||
           (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31);
}

// 根据VAS获取元素大小
size_t get_element_size_from_vas(arm64_vas vas) {
    switch (vas) {
        case ARM64_VAS_16B:
        case ARM64_VAS_8B:
            return 1;  // .b 元素
        case ARM64_VAS_8H:
        case ARM64_VAS_4H:
            return 2;  // .h 元素
        case ARM64_VAS_4S:
        case ARM64_VAS_2S:
            return 4;  // .s 元素
        case ARM64_VAS_2D:
        case ARM64_VAS_1D:
            return 8;  // .d 元素
        case ARM64_VAS_1Q:
            return 16; // .q 元素
        default:
            return 8;
    }
}

// 计算SIMD单次访问大小
size_t get_simd_access_size(arm64_vas vas, int vector_index) {
    if (vector_index >= 0) {
        // 单元素访问
        return get_element_size_from_vas(vas);
    } else {
        // 整向量访问
        switch (vas) {
            case ARM64_VAS_16B:
            case ARM64_VAS_8H:
            case ARM64_VAS_4S:
            case ARM64_VAS_2D:
            case ARM64_VAS_1Q:
                return 16;
            case ARM64_VAS_8B:
            case ARM64_VAS_4H:
            case ARM64_VAS_2S:
            case ARM64_VAS_1D:
                return 8;
            default:
                return 16;
        }
    }
}

// 获取向量寄存器中指定元素的值
uint64_t get_vector_element(GumCpuContext* ctx, arm64_reg reg, arm64_vas vas, int vector_index) {
    // 获取寄存器索引
    int idx = -1;
    if (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31) {
        idx = reg - ARM64_REG_V0;
    } else if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) {
        idx = reg - ARM64_REG_Q0;
    }
    if (idx < 0 || idx > 31) return 0;

    // 获取向量数据
    uint8_t data[16];
    memcpy(data, ctx->v[idx].q, 16);

    // 根据元素类型提取值
    switch (vas) {
        case ARM64_VAS_4S:
        case ARM64_VAS_2S: {
            uint32_t* elements = (uint32_t*)data;
            if (vector_index >= 0 && vector_index < 4) {
                return elements[vector_index];
            }
            break;
        }
        case ARM64_VAS_2D:
        case ARM64_VAS_1D: {
            uint64_t* elements = (uint64_t*)data;
            if (vector_index >= 0 && vector_index < 2) {
                return elements[vector_index];
            }
            break;
        }
        case ARM64_VAS_8H:
        case ARM64_VAS_4H: {
            uint16_t* elements = (uint16_t*)data;
            if (vector_index >= 0 && vector_index < 8) {
                return elements[vector_index];
            }
            break;
        }
        case ARM64_VAS_16B:
        case ARM64_VAS_8B: {
            if (vector_index >= 0 && vector_index < 16) {
                return data[vector_index];
            }
            break;
        }
        default:
            break;
    }
    return 0;
}

// 获取浮点寄存器大小
size_t get_fp_register_size(arm64_reg reg) {
    if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) return 16;
    if (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31) return 8;
    if (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) return 4;
    if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31) return 2;
    if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31) return 1;
    if (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31) return 16;
    return 8;
}

// SIMD指令信息结构
struct SimdInsnInfo {
    bool is_simd;           // 是否是SIMD指令
    bool is_store;          // 是否是存储指令
    int reg_count;          // 涉及的向量寄存器数量
    arm64_reg regs[4];      // 向量寄存器列表
    arm64_vas vas;          // 向量排列类型
    int vector_index;       // 元素索引，-1表示整向量
    size_t element_size;    // 单元素大小
    size_t access_size;     // 单次访问大小
};

// 解析SIMD指令信息
SimdInsnInfo parse_simd_instruction(const InstructionInfo *insn) {
    SimdInsnInfo info = {0};
    info.is_simd = false;
    info.is_store = false;
    info.reg_count = 0;
    info.vas = ARM64_VAS_INVALID;
    info.vector_index = -1;
    info.element_size = 8;
    info.access_size = 8;

    int insn_id = insn->insn_copy.id;

    // 检查是否是SIMD指令
    if (!is_simd_load(insn_id) && !is_simd_store(insn_id)) {
        return info;
    }

    info.is_simd = true;
    info.is_store = is_simd_store(insn_id);

    // 遍历操作数，查找向量寄存器
    for (int i = 0; i < insn->detail_copy->arm64.op_count; i++) {
        cs_arm64_op &op = insn->detail_copy->arm64.operands[i];
        if (op.type == ARM64_OP_REG && is_vector_register(op.reg)) {
            if (info.reg_count < 4) {
                info.regs[info.reg_count++] = op.reg;
            }
            // 获取VAS和vector_index（从第一个向量寄存器获取）
            if (info.vas == ARM64_VAS_INVALID) {
                info.vas = op.vas;
                info.vector_index = op.vector_index;
            }
        }
    }

    // 计算元素大小和访问大小
    info.element_size = get_element_size_from_vas(info.vas);
    info.access_size = get_simd_access_size(info.vas, info.vector_index);

    return info;
}

// 判断是否是内存访问指令
bool is_memory_access_instruction(unsigned int insn_id) {
    static const std::unordered_set<unsigned int> memory_instructions = {
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

        // SIMD 加载指令
        ARM64_INS_LD1, ARM64_INS_LD2, ARM64_INS_LD3, ARM64_INS_LD4,
        ARM64_INS_LD1R, ARM64_INS_LD2R, ARM64_INS_LD3R, ARM64_INS_LD4R,

        // SIMD 存储指令
        ARM64_INS_ST1, ARM64_INS_ST2, ARM64_INS_ST3, ARM64_INS_ST4,
    };

    return memory_instructions.count(insn_id) > 0;
}

// 获取指令的访问大小
size_t get_memory_access_size(const InstructionInfo *insn) {
    size_t access_size = 8;  // 默认64位
    unsigned int insn_id = insn->insn_copy.id;
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
            // 检查浮点/向量寄存器类型
            for (int i = 0; i < insn->insn_copy.detail->arm64.op_count; i++) {
                cs_arm64_op &op = insn->insn_copy.detail->arm64.operands[i];
                if (op.type == ARM64_OP_REG && is_fp_vector_register(op.reg)) {
                    access_size = get_fp_register_size(op.reg);
                    return access_size;
                }
            }
            // 检查是否是w寄存器
            if (strstr(insn->insn_copy.op_str, "w") != nullptr) {
                access_size = 4;
            }
            break;

        case ARM64_INS_LDR:
        case ARM64_INS_LDUR:
        case ARM64_INS_LDAR:
        case ARM64_INS_LDAPR:
        case ARM64_INS_LDAPUR:
            // 检查浮点/向量寄存器类型
            for (int i = 0; i < insn->insn_copy.detail->arm64.op_count; i++) {
                cs_arm64_op &op = insn->insn_copy.detail->arm64.operands[i];
                if (op.type == ARM64_OP_REG && is_fp_vector_register(op.reg)) {
                    access_size = get_fp_register_size(op.reg);
                    return access_size;
                }
            }
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
void read_memory_value(uintptr_t addr, size_t size, uint64_t &value) {
    if (size == 1) value = *(uint8_t*)addr;
    else if (size == 2) value = *(uint16_t*)addr;
    else if (size == 4) value = *(uint32_t*)addr;
    else if (size == 8) value = *(uint64_t*)addr;
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

    std::stringstream out_info;
    std::stringstream post_info;
    std::stringstream dump_reg_info;
    // 遍历操作数并记录写入的寄存器状态
    if (self->write_reg_list.num) {
        for (int i = 0; i < self->write_reg_list.num; i++) {
            arm64_reg reg = self->write_reg_list.regs[i];
            // 检查是否是浮点/向量寄存器，使用专门的格式化函数
            if (is_fp_vector_register(reg)) {
                std::string fp_str = get_fp_register_string(reg, ctx);
                if (!fp_str.empty()) {
                    // 为浮点寄存器也添加编号
                    uint64_t reg_id = self->reg_counter.get_next_id(fp_str);
                    // 解析寄存器名和值，重新格式化
                    size_t eq_pos = fp_str.find('=');
                    if (eq_pos != std::string::npos) {
                        std::string reg_name = fp_str.substr(0, eq_pos);
                        std::string reg_val = fp_str.substr(eq_pos);
                        post_info << reg_name << "_" << std::dec << reg_id << reg_val << " ";
                    } else {
                        post_info << fp_str << " ";
                    }
                }
            } else {
                uint64_t reg_value = 0;
                if (get_register_value(reg, ctx, reg_value)) {
                    const char* reg_name = cs_reg_name(insn_info->handle, reg);
                    uint64_t reg_id = self->reg_counter.get_next_id(reg_name);
                    post_info << reg_name << "_" << std::dec << reg_id << "=0x" << std::hex << reg_value << " ";
                    dump_reg_info << self->get_logger_manager()->dump_reg_value(reg_value, reg_name);
                }
            }
        }
        self->write_reg_list.num = 0;
    }

    // 输出当前指令地址和反汇编信息
    std::stringstream disasm_info;
    uint64_t current_ins_base = self->get_module_range().base;
    if (self->is_address_in_module_range(ctx->pc)) {
        // 当前主trace模块指令
        disasm_info << "0x" << std::left << std::setw(8) << std::hex << (ctx->pc - current_ins_base) << "   "
        << std::left << insn_info->insn_copy.mnemonic << "\t"
        << insn_info->insn_copy.op_str;
    } else{
        // 其他副trace模块指令
        auto& other_modules_range = self->get_trace_other_modules_range();
        for (const auto& [name, range] : other_modules_range) {
            if (ctx->pc > range.first && ctx->pc < range.second) {
                current_ins_base = range.first;
            }
        }

        disasm_info << "0x" << std::left << std::setw(8) << std::hex << ctx->pc << "(" << (ctx->pc - current_ins_base) << ")    "
        << std::left << insn_info->insn_copy.mnemonic << "\t"
        << insn_info->insn_copy.op_str;
    }

    // 针对立即数跳转指令需要计算出其对应偏移
    if (cs_insn_group(insn_info->handle, &insn_info->insn_copy, CS_GRP_JUMP) ||
        cs_insn_group(insn_info->handle, &insn_info->insn_copy, CS_GRP_CALL) ||
        cs_insn_group(insn_info->handle, &insn_info->insn_copy, CS_GRP_RET)) {
        if (insn_info->detail_copy->arm64.operands[0].type == ARM64_OP_IMM) {
            disasm_info << "(0x" << std::hex << insn_info->detail_copy->arm64.operands[0].imm - current_ins_base << ")";
        }
        }


    // 获取寄存器和内存访问信息
    std::stringstream pre_info;
    std::stringstream memory_access_info;
    for (int i = 0; i < insn_info->detail_copy->arm64.op_count; i++) {
        cs_arm64_op &op = insn_info->detail_copy->arm64.operands[i];
        // 获取读寄存器
        if (op.access & CS_AC_READ && op.type == ARM64_OP_REG) {
            // 检查是否是浮点/向量寄存器
            if (is_fp_vector_register(op.reg)) {
                std::string fp_str = get_fp_register_string(op.reg, ctx);
                if (!fp_str.empty()) {
                    // 为浮点寄存器也添加编号
                    uint64_t reg_id = self->reg_counter.get_next_id(fp_str);
                    size_t eq_pos = fp_str.find('=');
                    if (eq_pos != std::string::npos) {
                        std::string reg_name_str = fp_str.substr(0, eq_pos);
                        std::string reg_val = fp_str.substr(eq_pos);
                        pre_info << "r[" << reg_name_str << "_" << std::dec << reg_id << reg_val << "] ";
                    } else {
                        pre_info << "r[" << fp_str << "] ";
                    }
                }
            } else {
                uint64_t reg_value = 0;
                if (get_register_value(op.reg, ctx, reg_value)) {
                    const char* reg_name = cs_reg_name(insn_info->handle, op.reg);
                    uint64_t reg_id = self->reg_counter.get_next_id(reg_name);
                    pre_info << "r[" << reg_name << "_" << std::dec << reg_id << "=0x"
                             << std::hex << reg_value << "] ";
                }
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
                uint64_t base_reg_id = self->reg_counter.get_next_id(memory_address_info.base_name);
                pre_info << "r[" << memory_address_info.base_name << "_" << std::dec << base_reg_id
                         << "=0x" << std::hex << memory_address_info.base_value << "] ";
            }
            if (memory_address_info.has_index) {
                uint64_t index_reg_id = self->reg_counter.get_next_id(memory_address_info.index_name);
                pre_info << "r[" << memory_address_info.index_name << "_" << std::dec << index_reg_id
                         << "=0x" << std::hex << memory_address_info.index_value << "] ";
            }

           // 解析SIMD指令信息
            SimdInsnInfo simd_info = parse_simd_instruction(insn_info);

            if (simd_info.is_simd) {
                // ========== SIMD 指令处理 ==========
                if (simd_info.is_store) {
                    // SIMD 存储指令
                    uintptr_t current_addr = memory_address_info.addr;

                    for (int reg_idx = 0; reg_idx < simd_info.reg_count; reg_idx++) {
                        uint64_t value = 0;

                        if (simd_info.vector_index >= 0) {
                            // 单元素存储
                            value = get_vector_element(ctx, simd_info.regs[reg_idx],
                                                       simd_info.vas, simd_info.vector_index);
                        } else {
                            // 整向量存储 - 获取低64位
                            int idx = -1;
                            if (simd_info.regs[reg_idx] >= ARM64_REG_V0 && simd_info.regs[reg_idx] <= ARM64_REG_V31) {
                                idx = simd_info.regs[reg_idx] - ARM64_REG_V0;
                            } else if (simd_info.regs[reg_idx] >= ARM64_REG_Q0 && simd_info.regs[reg_idx] <= ARM64_REG_Q31) {
                                idx = simd_info.regs[reg_idx] - ARM64_REG_Q0;
                            }
                            if (idx >= 0 && idx <= 31) {
                                memcpy(&value, ctx->v[idx].q, sizeof(uint64_t));
                            }
                        }

                        if (!memory_access_info.str().empty()) {
                            memory_access_info << ", ";
                        }
                        uint64_t mem_id = self->mem_counter.get_next_id();
                        memory_access_info << "mem[w]_" << std::dec << mem_id << " addr[ 0x" << std::hex << current_addr << " ]"
                                           << " size:" << std::dec << simd_info.access_size
                                           << " value:0x" << std::hex << value;

                        current_addr += simd_info.access_size;
                    }
                } else {
                    // SIMD 加载指令
                    uintptr_t current_addr = memory_address_info.addr;

                    for (int reg_idx = 0; reg_idx < simd_info.reg_count; reg_idx++) {
                        uint64_t mem_value = 0;
                        size_t read_size = (simd_info.access_size > 8) ? 8 : simd_info.access_size;

                        if (self->get_logger_manager()->safeReadMemory(
                                current_addr, reinterpret_cast<uint8_t*>(&mem_value), read_size)) {
                            if (!memory_access_info.str().empty()) {
                                memory_access_info << ", ";
                            }
                            uint64_t mem_id = self->mem_counter.get_next_id();
                            memory_access_info << "mem[r]_" << std::dec << mem_id << " addr[ 0x" << std::hex << current_addr << " ]"
                                               << " size:" << std::dec << simd_info.access_size
                                               << " value:0x" << std::hex << mem_value;
                        }

                        current_addr += simd_info.access_size;
                    }
                }
            } else {
                // ========== 普通内存指令处理 ==========
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
                                uint64_t mem_id1 = self->mem_counter.get_next_id();
                                memory_access_info << "mem[w]_" << std::dec << mem_id1 << " addr[ 0x" << std::hex << memory_address_info.addr << " ]"
                                                   << " size:" << std::dec << access_size
                                                   << " value:0x" << std::hex << reg_values[0];
                                uint64_t mem_id2 = self->mem_counter.get_next_id();
                                memory_access_info << ", mem[w]_" << std::dec << mem_id2 << " addr[ 0x" << std::hex << (memory_address_info.addr + access_size) << " ]"
                                                   << " size:" << std::dec << access_size
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
                                uint64_t mem_id = self->mem_counter.get_next_id();
                                memory_access_info << "mem[w]_" << std::dec << mem_id << " addr[ 0x" << std::hex << memory_address_info.addr << " ]"
                                                   << " size:" << std::dec << access_size
                                                   << " value:0x" << std::hex << reg_values[0];
                            }
                        }
                    }
                }
                    // 解析内存读信息
                else if (op.access & CS_AC_READ) {
                    // 内存读取
                    uint64_t mem_value = 0;
                    if (self->get_logger_manager()->safeReadMemory(
                            memory_address_info.addr, reinterpret_cast<uint8_t*>(&mem_value), access_size)) {
                        if (!memory_access_info.str().empty()) {
                            memory_access_info << ", ";
                        }

                        if (is_pair_instruction) {
                            uint64_t mem_id1 = self->mem_counter.get_next_id();
                            memory_access_info << "mem[r]_" << std::dec << mem_id1 << " addr[ 0x" << std::hex << memory_address_info.addr << " ]"
                                               << " size:" << std::dec << access_size
                                               << " value:0x" << std::hex << mem_value;
                            // ldp 指令读取两个值
                            uint64_t mem_value2 = 0;
                            if (self->get_logger_manager()->safeReadMemory(memory_address_info.addr + access_size, reinterpret_cast<uint8_t*>(&mem_value2), access_size)) {
                                uint64_t mem_id2 = self->mem_counter.get_next_id();
                                memory_access_info << ", mem[r]_" << std::dec << mem_id2 << " addr[ 0x" << std::hex << (memory_address_info.addr + access_size) << " ]"
                                                   << " size:" << std::dec << access_size
                                                   << " value:0x" << std::hex << mem_value2;
                            }
                        } else {
                            // 普通加载指令
                            uint64_t mem_id = self->mem_counter.get_next_id();
                            memory_access_info << "mem[r]_" << std::dec << mem_id << " addr[ 0x" << std::hex << memory_address_info.addr << " ]"
                                               << " size:" << std::dec << access_size
                                               << " value:0x" << std::hex << mem_value;
                        }
                    }
                }
            }
        }
    }


    // 解析函数调用信息
    std::stringstream call_info;
    uintptr_t jmp_addr = 0;
    if (insn_info->insn_copy.id == ARM64_INS_BL &&
        insn_info->detail_copy->arm64.operands[0].type == ARM64_OP_IMM) {
        jmp_addr = insn_info->detail_copy->arm64.operands[0].imm;
    } else if (insn_info->insn_copy.id == ARM64_INS_BLR &&
        insn_info->detail_copy->arm64.operands[0].type == ARM64_OP_REG) {
        get_register_value(insn_info->detail_copy->arm64.operands[0].reg, ctx, jmp_addr);
    } else if (insn_info->insn_copy.id == ARM64_INS_BR &&
        insn_info->detail_copy->arm64.op_count == 1 && insn_info->detail_copy->arm64.operands[0].type == ARM64_OP_REG) {
        get_register_value(insn_info->detail_copy->arm64.operands[0].reg, ctx, jmp_addr);
        if (self->is_address_in_module_range(jmp_addr) || self->is_address_in_other_module_range(jmp_addr)) {
            jmp_addr = 0;
        }
    }

    if (jmp_addr != 0) {
        if ((jmp_addr - self->get_module_range().base) <= self->get_plt_range().second &&
            (jmp_addr - self->get_module_range().base) >= self->get_plt_range().first) {
            self->is_plt_jmp = true;
        } else {
            xdl_info_t xdl_info;
            void *cache = nullptr;
            if (xdl_addr(reinterpret_cast<void*>(jmp_addr), &xdl_info, &cache)) {
                const char * soName = strrchr(xdl_info.dli_fname, '/') + 1;
                const char * symName = xdl_info.dli_sname;
                if (symName == nullptr) {
                    std::ostringstream oss;
                    oss << "sub_" << std::hex << (jmp_addr - (uintptr_t)xdl_info.dli_fbase);
                    symName = oss.str().c_str();
                }
                call_info << "call addr: " << std::hex << jmp_addr << " [" << soName << "!" << symName << "]";
            }
        }
    }

    // trace信息写入文件
    if (!post_info.str().empty()) {
        out_info << "\t w[" << post_info.str() << "]" << std::endl << dump_reg_info.str();
    }
    out_info << disasm_info.str() << "   ;" << pre_info.str() << std::endl;
    if (!call_info.str().empty()) {
        out_info << call_info.str() << std::endl;
    }
    if (!memory_access_info.str().empty()) {
        out_info << "   " << memory_access_info.str() << std::endl;
    }
    self->get_logger_manager()->write_info(out_info);
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