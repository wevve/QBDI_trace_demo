#include "vm.h"
#include "assert.h"
#include "hexdump.h"
#include <unordered_map>

using namespace std;
using namespace QBDI;


// 地址范围的结构体，用于缓存 maps 文件中的每个模块范围
struct MemoryRange {
    uint64_t startAddr;
    uint64_t endAddr;
    std::string pathname;
};

// 缓存地址范围和已解析的符号信息
std::unordered_map<uint64_t, std::string> symbolCache;
std::vector<MemoryRange> memoryRanges;

// 从 /proc/self/maps 读取并缓存模块地址范围
void loadMemoryRanges() {
    std::ifstream mapsFile("/proc/self/maps");
    std::string line;

    while (std::getline(mapsFile, line)) {
        std::istringstream iss(line);
        std::string addrRange, perms, offset, dev, inode, pathname;
        uint64_t startAddr, endAddr;

        // 解析 maps 文件的一行内容
        iss >> addrRange >> perms >> offset >> dev >> inode;
        if (!(iss >> pathname)) {
            pathname = ""; // 如果没有路径，将其设为空字符串
        }


        size_t pos = pathname.find_last_of('/');
        std::string filename = (pos == std::string::npos) ? pathname : pathname.substr(pos + 1);


        // 解析地址范围
        std::replace(addrRange.begin(), addrRange.end(), '-', ' ');
        std::istringstream addrStream(addrRange);
        addrStream >> std::hex >> startAddr >> endAddr;

        // 添加到缓存的内存范围
        memoryRanges.push_back({startAddr, endAddr, filename});
    }
}

// 从缓存中查找地址范围内的符号信息
std::string getSymbolFromCache(uint64_t address) {
    // 检查缓存
    if (symbolCache.find(address) != symbolCache.end()) {
        return symbolCache[address];
    }

    // 遍历已缓存的地址范围
    for (const auto& range : memoryRanges) {
        if (address >= range.startAddr && address < range.endAddr) {
            uint64_t addrOffset = address - range.startAddr;
            std::ostringstream symbolStream;
            symbolStream << range.pathname << "[0x" << std::hex << addrOffset << "]";
            std::string symbol = symbolStream.str();

            // 将结果存入缓存
            symbolCache[address] = symbol;
            return symbol;
        }
    }

    // 未找到时返回空字符串
    symbolCache[address] = "";  // 记录无符号信息，避免重复查找
    return "";
}

// 判断内存内容是否为有效的 ASCII 可打印字符串，且不为全空格
bool isAsciiPrintableString(const uint8_t* data, size_t length) {
    bool hasNonSpaceChar = false;  // 标记是否包含非空格字符

    for (size_t i = 0; i < length; ++i) {
        if (data[i] == '\0') {
            return hasNonSpaceChar;  // 如果遇到终止符，且包含非空格字符，则认为是有效字符串
        }
        if (data[i] < 0x20 || data[i] > 0x7E) {
            return false;  // 如果包含非 ASCII 可打印字符，视为无效字符串
        }
        if (data[i] != ' ') {
            hasNonSpaceChar = true;  // 检测到非空格字符
        }
    }
    return hasNonSpaceChar;  // 字符串没有终止符时，检查是否包含非空格字符
}


// 显示指令执行后的寄存器状态
QBDI::VMAction showPostInstruction(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
    auto thiz = (class vm *) data;

    // 获取当前指令的分析信息，包括指令、符号、操作数等
    const QBDI::InstAnalysis *instAnalysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_SYMBOL | QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_OPERANDS);

    std::stringstream output;
    std::stringstream regOutput;

    // 开关：选择输出 hexdump 或者字符串

    // 遍历操作数并记录写入的寄存器状态
    for (int i = 0; i < instAnalysis->numOperands; ++i) {
        auto op = instAnalysis->operands[i];
        if (op.regAccess == REGISTER_WRITE || op.regAccess == REGISTER_READ_WRITE) {
            if (op.regCtxIdx != -1 && op.type == OPERAND_GPR) {
                // 获取寄存器值
                uint64_t regValue = QBDI_GPR_GET(gprState, op.regCtxIdx);

                // 输出寄存器名称和值
                output << op.regName << "=0x" << std::hex << regValue << " ";
                output.flush();

                // 对可能为地址的寄存器值进行 hexdump 或字符串输出，仅在值为有效地址时执行
                if (isValidAddress(regValue)) {
                    const uint8_t* dataPtr = reinterpret_cast<const uint8_t*>(regValue);
                    size_t maxLen = 256;  // 最大显示字节数
                    if (isAsciiPrintableString(dataPtr, maxLen)) {
                        regOutput << "Strings :"<< std::string(reinterpret_cast<const char*>(dataPtr)) << "\n";
                    } else {
                        regOutput << "Hexdump for " << op.regName << " at address 0x" << std::hex << regValue << ":\n";
                        hexdump_memory(regOutput, reinterpret_cast<const uint8_t*>(regValue), 32, regValue);  // 显示32字节内容
                    }

                }
            }
        }
    }

    // 如果有写入的寄存器信息，格式化输出；否则，仅换行
    if (!output.str().empty()) {
        thiz->logbuf << "\tw[" << output.str() << "]" << std::endl;
        thiz->logbuf << regOutput.str();
    } else {
        thiz->logbuf << std::endl;
        thiz->logbuf << regOutput.str();
    }
    return QBDI::VMAction::CONTINUE;
}


// 显示指令执行前的寄存器状态
QBDI::VMAction showPreInstruction(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
    auto thiz = (class vm *) data;

    // 获取当前指令的分析信息
    const QBDI::InstAnalysis *instAnalysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_SYMBOL | QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_OPERANDS);

    // 输出符号名和偏移量，如果没有符号，则仅输出地址和反汇编信息
    if (instAnalysis->symbol != nullptr) {
        thiz->logbuf << instAnalysis->symbol << "[0x" << std::hex << instAnalysis->symbolOffset << "]:0x" << instAnalysis->address << ": " << instAnalysis->disassembly;
    } else {
        std::string symbolInfo = getSymbolFromCache(instAnalysis->address);
        if (!symbolInfo.empty()) {
            thiz->logbuf << symbolInfo << ":0x" << std::hex << instAnalysis->address << ": " << instAnalysis->disassembly;
        } else {
            // 如果 /proc/self/maps 中也找不到对应信息，仅输出地址和反汇编信息
            thiz->logbuf << "0x" << std::hex << instAnalysis->address << ": " << instAnalysis->disassembly;
        }
    }

    std::stringstream output;
    // 遍历操作数并记录读取的寄存器状态
    for (int i = 0; i < instAnalysis->numOperands; ++i) {
        auto op = instAnalysis->operands[i];
        if (op.regAccess == QBDI::REGISTER_READ || op.regAccess == REGISTER_READ_WRITE) {
            if (op.regCtxIdx != -1 && op.type == OPERAND_GPR) {
                // 将寄存器名称和值添加到输出流
                output << op.regName << "=0x" << std::hex << QBDI_GPR_GET(gprState, op.regCtxIdx) << " ";
                output.flush();
            }
        }
    }

    // 如果有读取的寄存器信息，格式化输出
    if (!output.str().empty()) {
        thiz->logbuf << "\tr[" << output.str() << "]";
    }
    return QBDI::VMAction::CONTINUE;
}

// 显示指令执行时的内存访问
QBDI::VMAction
showMemoryAccess(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState,
                 void *data) {
    auto thiz = (class vm *) data;
    if (vm->getInstMemoryAccess().empty()) {
        thiz->logbuf << std::endl;
    }
    for (const auto &acc: vm->getInstMemoryAccess()) {
        if (acc.type == MEMORY_READ) {
            thiz->logbuf << "   mem[r]:0x" << std::hex << acc.accessAddress << " size:" << acc.size
                         << " value:0x" << acc.value;
        } else if (acc.type == MEMORY_WRITE) {
            thiz->logbuf << "   mem[w]:0x" << std::hex << acc.accessAddress << " size:" << acc.size
                         << " value:0x" << acc.value;
        } else {
            thiz->logbuf << "   mem[rw]:0x" << std::hex << acc.accessAddress << " size:" << acc.size
                         << " value:0x" << acc.value;
        }
    }
    thiz->logbuf << std::endl << std::endl;
    return QBDI::VMAction::CONTINUE;
}

// 初始化虚拟机，并设置代码和内存回调
QBDI::VM vm::init(void *address) {
    uint32_t cid;
    QBDI::GPRState *state;
    QBDI::VM qvm{};

    loadMemoryRanges();//解析一次maps

    // 获取虚拟机的通用寄存器状态
    state = qvm.getGPRState();

    // 设置虚拟机选项，禁用本地监视器，绕过PAUTH（指针认证），启用BTI（分支目标指示）
    qvm.setOptions(QBDI::OPT_DISABLE_LOCAL_MONITOR | QBDI::OPT_BYPASS_PAUTH | QBDI::OPT_ENABLE_BTI);
    assert(state != nullptr);

    // 设置记录内存访问的模式
    qvm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE);

    // 添加指令执行前的回调
    cid = qvm.addCodeCB(QBDI::PREINST, showPreInstruction, this);
    assert(cid != QBDI::INVALID_EVENTID);

    // 添加指令执行后的回调
    cid = qvm.addCodeCB(QBDI::POSTINST, showPostInstruction, this);
    assert(cid != QBDI::INVALID_EVENTID);

    // 添加内存访问回调
    cid = qvm.addMemAccessCB(MEMORY_READ_WRITE, showMemoryAccess, this);
    assert(cid != QBDI::INVALID_EVENTID);

    // 根据传入地址对模块添加插装，确保指令回调和内存回调生效
    bool ret = qvm.addInstrumentedModuleFromAddr(reinterpret_cast<QBDI::rword>(address));
    assert(ret == true);

    return qvm;
}

// 同步寄存器状态，将Dobby上下文寄存器值同步到虚拟机状态
void syn_regs(DobbyRegisterContext *ctx, QBDI::GPRState *state) {
    for (int i = 0; i < 29; i++) {
        QBDI_GPR_SET(state, i, ctx->general.x[i]); // 设置通用寄存器的值
    }
    // 同步栈指针、帧指针和链接寄存器的值
    state->lr = ctx->lr;
    state->x29 = ctx->fp;
    state->sp = ctx->sp;
}
