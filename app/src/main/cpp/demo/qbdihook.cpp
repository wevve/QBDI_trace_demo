//
// Created by Mrack on 2024/4/20.
//

#include "qbdihook.h"
#include <jni.h>
#include <cstring>
#include <cstdio>

#include <fstream>
#include <asm-generic/mman-common.h>
#include <sys/mman.h>
#include <__fwd/string.h>
#include "vm.h"
#include "utils.h"
#include "md5.h"
#include "sha1.hpp"

uint64_t get_tick_count64() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC,&ts);
    return (ts.tv_sec*1000 + ts.tv_nsec/(1000*1000));
}



// 获取当前时间戳的函数
uint64_t get_tick_count64();


//void vm_handle_add(void *address, DobbyRegisterContext *ctx) {
//    uint64_t now = get_tick_count64();
//    size_t number = 1;
//
//    LOGT("vm address %p ", address);
//    // 销毁拦截（或钩子）以避免重复触发
//    DobbyDestroy(address);
//    // 创建虚拟机实例
//    auto vm_ = new vm();
//    // 初始化虚拟机，并将目标地址传递给虚拟机
//    auto qvm = vm_->init(address);
//    // 获取虚拟机的通用寄存器状态
//    auto state = qvm.getGPRState();
//    // 将 Dobby 的寄存器上下文同步到虚拟机的状态
//    syn_regs(ctx, state);
//    // 分配虚拟堆栈，大小为 0x800000 字节（8MB），为虚拟机的运行提供栈空间
//    uint8_t *fakestack;
//    QBDI::allocateVirtualStack(state, 0x800000, &fakestack);
//    // 调用虚拟机执行目标函数，传入目标函数地址
//    qvm.call(nullptr, (uint64_t) address);
//    // 释放之前分配的虚拟堆栈内存
//    QBDI::alignedFree(fakestack);
//
//    // 将虚拟机的日志数据写入文件
//    std::ofstream out;
//    std::string data = get_data_path(gContext); // 获取日志文件的路径
//    out.open(data + "/trace_log.txt", std::ios::out); // 打开或创建日志文件
//    out << vm_->logbuf.str(); // 将虚拟机日志缓冲区的内容写入文件
//    out.close(); // 关闭文件
//
//    // 记录并输出函数执行时间
//    LOGT("Read %ld times cost = %lfs\n", number, (double)(get_tick_count64() - now) / 1000);
//}

void vm_handle_add(void *address, DobbyRegisterContext *ctx) {
    uint64_t now = get_tick_count64();
    size_t number = 1;

    LOGT("vm address %p ", address);
    // 销毁拦截（或钩子）以避免重复触发
    DobbyDestroy(address);
    // 创建虚拟机实例
    auto vm_ = new vm();
    // 初始化虚拟机，并将目标地址传递给虚拟机
    auto qvm = vm_->init(address);
    // 获取虚拟机的通用寄存器状态
    auto state = qvm.getGPRState();
    // 将 Dobby 的寄存器上下文同步到虚拟机的状态
    syn_regs(ctx, state);
    // 分配虚拟堆栈，大小为 0x800000 字节（8MB），为虚拟机的运行提供栈空间
    uint8_t *fakestack;
    // Allocate virtual stack
    //改为分配0x100000内存为1mb后成功了
    //如果需要更大可以考虑
    /**
     * 方法 1：分块分配多个 1MB 的小栈
     * 方法 2：基于 mmap 的手动栈分配
     * 方法 3：通过优化栈使用来减少栈需求
     * 方法 4：确认是否存在系统限制
     */
    //内存不足：堆栈大小为 8MB，设备可能没有足够的连续内存来满足分配请求。
    long mem_size = 0x100000 * 1 * 1 ;
    if (QBDI::allocateVirtualStack(state, mem_size, &fakestack)) {
        LOGT("Failed to allocate virtual stack");
    }

    // Set memory protection to PROT_READ | PROT_WRITE
    if (mprotect(fakestack, mem_size, PROT_READ | PROT_WRITE) != 0) {
        perror("mprotect failed");
        QBDI::alignedFree(fakestack);
    }

    double mem_size_mb = mem_size / (1024.0 * 1024.0);
    LOGT("Virtual stack allocated at %p with size %.2f MB and permissions PROT_READ | PROT_WRITE", fakestack, mem_size_mb);
    // 调用虚拟机执行目标函数，传入目标函数地址
    qvm.call(nullptr, (uint64_t) address);
    // 释放之前分配的虚拟堆栈内存
    QBDI::alignedFree(fakestack);

    // 将虚拟机的日志数据写入文件
    std::ofstream out;
    std::string data = get_data_path(gContext); // 获取日志文件的路径
    out.open(data + "/trace_log.txt", std::ios::out); // 打开或创建日志文件
    out << vm_->logbuf.str(); // 将虚拟机日志缓冲区的内容写入文件
    out.close(); // 关闭文件

    // 记录并输出函数执行时间
    LOGT("Read %ld times cost = %lfs\n", number, (double)(get_tick_count64() - now) / 1000);
}


const char* tracedemo(){
    const char *tuzi = "tuzi";

    return tuzi;
}

void test_QBDI() {
//    DobbyInstrument((void *) (Java_cn_mrack_xposed_nhook_NHook_sign1), vm_handle_add);
    DobbyInstrument((void *) (Java_cn_mrack_xposed_nhook_NHook_sign1), vm_handle_add);
//    DobbyInstrument((void *) (tracedemo), vm_handle_add);
    tracedemo();

}


unsigned char s[256];
unsigned char t[256];


void swap(unsigned char *p1, unsigned char *p2) {
    unsigned char t = *p1;
    *p1 = *p2;
    *p2 = t;
}

void rc4_init(unsigned char *key, int key_len) {
    int i, j = 0;

    //Initial values of both vectors
    for (i = 0; i < 256; i++) {
        s[i] = i;
        t[i] = key[i % key_len];
    }
    //Initial permutation
    for (i = 0; i < 256; i++) {
        j = (j + s[i] + t[i]) % 256;
        swap(&s[i], &s[j]);
    }
}

void rc4(unsigned char *key, int key_len, char *buff, int len) {
    int i = 0;
    unsigned long t1, t2;
    unsigned char val;
    unsigned char out;
    t1 = 0;
    t2 = 0;
    rc4_init(key, key_len);

    //process one byte at a time
    for (i = 0; i < len; i++) {
        t1 = (t1 + 1) % 256;
        t2 = (t2 + s[t1]) % 256;
        swap(&s[t1], &s[t2]);
        val = (s[t1] + s[t2]) % 256;
        out = *buff ^ val;
        *buff = out;
        buff++;
    }
}

void sha1(){
    const std::string input = "abc";

    SHA1 checksum;
    checksum.update(input);
    const std::string hash = checksum.final();
    LOGE("The SHA-1 of %s input %s",input.c_str(),hash.c_str());
}


extern "C" JNIEXPORT jstring JNICALL
Java_cn_mrack_xposed_nhook_NHook_sign1(JNIEnv *env, jclass thiz, jstring sign) {


    const char *sign_ = env->GetStringUTFChars(sign, 0);
    const char *tuzi = "tuzi";


    sha1();
    MD5_CTX mdContext;
    MD5Init(&mdContext);
    MD5Update(&mdContext, (unsigned char *) "kanxue", strlen("kanxue"));
    MD5Update(&mdContext, (unsigned char *) "imyang", strlen("imyang"));
    MD5Update(&mdContext, (unsigned char *) "ollvm_md5", strlen("ollvm_md5"));
    MD5Update(&mdContext, (unsigned char *) "bulNalvWmXgeYrQbvQiiFeLoD", strlen("bulNalvWmXgeYrQbvQiiFeLoD"));
    unsigned char digest[16] = {0};
    MD5Final(digest, &mdContext);

    // 创建一个字符串流用于构建十六进制字符串
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    // 将每个字节转换为两位十六进制数
    for(int i = 0; i < 16; ++i) {
        ss << std::setw(2) << static_cast<int>(digest[i]);
    }

    // 获取最终的十六进制字符串
    std::string md5String = ss.str();

    // 打印 MD5 摘要
    LOGE("MD5: %s", md5String.c_str());



    LOGE("sign_ : %s : %s",sign_,tuzi);

    char *res_chars = new char[strlen(sign_)];
    strcpy(res_chars, sign_);
    auto *key = (u_char *) "\x01\x02\x03\x04\x05";
//    for (int i = 0; i < 10; ++i) {
//        rc4(key, sizeof(key), res_chars, strlen(sign_));
//    }
    rc4(key, sizeof(key), res_chars, strlen(sign_));
    LOGE("res_chars : %s",res_chars);

    char *hex = new char[strlen(sign_) * 2 + 1];
    for (int i = 0; i < strlen(sign_); i++) {
        sprintf(hex + i * 2, "%02x", res_chars[i]);
    }
    LOGE("hex : %s",hex);

    env->ReleaseStringUTFChars(sign, sign_);
    return env->NewStringUTF("hex");
}

