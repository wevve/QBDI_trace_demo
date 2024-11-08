//
// Created by Mrack on 2024/4/20.
//

#include "qbdihook.h"
#include <jni.h>
#include <cstring>
#include <cstdio>

#include <fstream>
#include "vm.h"
#include "utils.h"

uint64_t get_tick_count64() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC,&ts);
    return (ts.tv_sec*1000 + ts.tv_nsec/(1000*1000));
}

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
    QBDI::allocateVirtualStack(state, 0x800000, &fakestack);
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



extern "C" JNIEXPORT jstring JNICALL
Java_cn_mrack_xposed_nhook_NHook_sign1(JNIEnv *env, jclass thiz, jstring sign) {


    const char *sign_ = env->GetStringUTFChars(sign, 0);
    const char *tuzi = "tuzi";

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
    return env->NewStringUTF(hex);
}

