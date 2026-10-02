#include <cuda_runtime.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

namespace {

__device__ __forceinline__ uint32_t rotr(uint32_t value, uint32_t count) {
    return __funnelshift_r(value, value, count);
}

__device__ __forceinline__ uint32_t load_be32(const uint8_t *p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

__device__ __forceinline__ void store_be32(uint8_t *p, uint32_t value) {
    p[0] = uint8_t(value >> 24);
    p[1] = uint8_t(value >> 16);
    p[2] = uint8_t(value >> 8);
    p[3] = uint8_t(value);
}

#define SHA256_S0(x) (rotr((x),2)^rotr((x),13)^rotr((x),22))
#define SHA256_S1(x) (rotr((x),6)^rotr((x),11)^rotr((x),25))
#define SHA256_s0(x) (rotr((x),7)^rotr((x),18)^((x)>>3))
#define SHA256_s1(x) (rotr((x),17)^rotr((x),19)^((x)>>10))
#define SHA256_CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define SHA256_MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define SHA256_EXPAND(x,y,z,w) (SHA256_s1(x)+(y)+SHA256_s0(z)+(w))
#define SHA256_STEP(a,b,c,d,e,f,g,h,w,k) do { \
    (h)+=SHA256_S1(e)+SHA256_CH(e,f,g)+(k)+(w); \
    (d)+=(h); \
    (h)+=SHA256_S0(a)+SHA256_MAJ(a,b,c); \
} while(0)

// Fixed-register, fully unrolled schedule adapted from Hashcat's MIT-licensed
// inc_hash_sha256.cl and mode-33700 loop kernel.
__device__ __forceinline__ void sha256_compress_unrolled(uint32_t state[8], const uint8_t block[64]) {
    uint32_t a=state[0],b=state[1],c=state[2],d=state[3];
    uint32_t e=state[4],f=state[5],g=state[6],h=state[7];
    uint32_t
        w0=load_be32(block+0),
        w1=load_be32(block+4),
        w2=load_be32(block+8),
        w3=load_be32(block+12),
        w4=load_be32(block+16),
        w5=load_be32(block+20),
        w6=load_be32(block+24),
        w7=load_be32(block+28),
        w8=load_be32(block+32),
        w9=load_be32(block+36),
        wa=load_be32(block+40),
        wb=load_be32(block+44),
        wc=load_be32(block+48),
        wd=load_be32(block+52),
        we=load_be32(block+56),
        wf=load_be32(block+60);
    SHA256_STEP(a,b,c,d,e,f,g,h,w0,0x428a2f98u);
    SHA256_STEP(h,a,b,c,d,e,f,g,w1,0x71374491u);
    SHA256_STEP(g,h,a,b,c,d,e,f,w2,0xb5c0fbcfu);
    SHA256_STEP(f,g,h,a,b,c,d,e,w3,0xe9b5dba5u);
    SHA256_STEP(e,f,g,h,a,b,c,d,w4,0x3956c25bu);
    SHA256_STEP(d,e,f,g,h,a,b,c,w5,0x59f111f1u);
    SHA256_STEP(c,d,e,f,g,h,a,b,w6,0x923f82a4u);
    SHA256_STEP(b,c,d,e,f,g,h,a,w7,0xab1c5ed5u);
    SHA256_STEP(a,b,c,d,e,f,g,h,w8,0xd807aa98u);
    SHA256_STEP(h,a,b,c,d,e,f,g,w9,0x12835b01u);
    SHA256_STEP(g,h,a,b,c,d,e,f,wa,0x243185beu);
    SHA256_STEP(f,g,h,a,b,c,d,e,wb,0x550c7dc3u);
    SHA256_STEP(e,f,g,h,a,b,c,d,wc,0x72be5d74u);
    SHA256_STEP(d,e,f,g,h,a,b,c,wd,0x80deb1feu);
    SHA256_STEP(c,d,e,f,g,h,a,b,we,0x9bdc06a7u);
    SHA256_STEP(b,c,d,e,f,g,h,a,wf,0xc19bf174u);
    w0=SHA256_EXPAND(we,w9,w1,w0);
    SHA256_STEP(a,b,c,d,e,f,g,h,w0,0xe49b69c1u);
    w1=SHA256_EXPAND(wf,wa,w2,w1);
    SHA256_STEP(h,a,b,c,d,e,f,g,w1,0xefbe4786u);
    w2=SHA256_EXPAND(w0,wb,w3,w2);
    SHA256_STEP(g,h,a,b,c,d,e,f,w2,0x0fc19dc6u);
    w3=SHA256_EXPAND(w1,wc,w4,w3);
    SHA256_STEP(f,g,h,a,b,c,d,e,w3,0x240ca1ccu);
    w4=SHA256_EXPAND(w2,wd,w5,w4);
    SHA256_STEP(e,f,g,h,a,b,c,d,w4,0x2de92c6fu);
    w5=SHA256_EXPAND(w3,we,w6,w5);
    SHA256_STEP(d,e,f,g,h,a,b,c,w5,0x4a7484aau);
    w6=SHA256_EXPAND(w4,wf,w7,w6);
    SHA256_STEP(c,d,e,f,g,h,a,b,w6,0x5cb0a9dcu);
    w7=SHA256_EXPAND(w5,w0,w8,w7);
    SHA256_STEP(b,c,d,e,f,g,h,a,w7,0x76f988dau);
    w8=SHA256_EXPAND(w6,w1,w9,w8);
    SHA256_STEP(a,b,c,d,e,f,g,h,w8,0x983e5152u);
    w9=SHA256_EXPAND(w7,w2,wa,w9);
    SHA256_STEP(h,a,b,c,d,e,f,g,w9,0xa831c66du);
    wa=SHA256_EXPAND(w8,w3,wb,wa);
    SHA256_STEP(g,h,a,b,c,d,e,f,wa,0xb00327c8u);
    wb=SHA256_EXPAND(w9,w4,wc,wb);
    SHA256_STEP(f,g,h,a,b,c,d,e,wb,0xbf597fc7u);
    wc=SHA256_EXPAND(wa,w5,wd,wc);
    SHA256_STEP(e,f,g,h,a,b,c,d,wc,0xc6e00bf3u);
    wd=SHA256_EXPAND(wb,w6,we,wd);
    SHA256_STEP(d,e,f,g,h,a,b,c,wd,0xd5a79147u);
    we=SHA256_EXPAND(wc,w7,wf,we);
    SHA256_STEP(c,d,e,f,g,h,a,b,we,0x06ca6351u);
    wf=SHA256_EXPAND(wd,w8,w0,wf);
    SHA256_STEP(b,c,d,e,f,g,h,a,wf,0x14292967u);
    w0=SHA256_EXPAND(we,w9,w1,w0);
    SHA256_STEP(a,b,c,d,e,f,g,h,w0,0x27b70a85u);
    w1=SHA256_EXPAND(wf,wa,w2,w1);
    SHA256_STEP(h,a,b,c,d,e,f,g,w1,0x2e1b2138u);
    w2=SHA256_EXPAND(w0,wb,w3,w2);
    SHA256_STEP(g,h,a,b,c,d,e,f,w2,0x4d2c6dfcu);
    w3=SHA256_EXPAND(w1,wc,w4,w3);
    SHA256_STEP(f,g,h,a,b,c,d,e,w3,0x53380d13u);
    w4=SHA256_EXPAND(w2,wd,w5,w4);
    SHA256_STEP(e,f,g,h,a,b,c,d,w4,0x650a7354u);
    w5=SHA256_EXPAND(w3,we,w6,w5);
    SHA256_STEP(d,e,f,g,h,a,b,c,w5,0x766a0abbu);
    w6=SHA256_EXPAND(w4,wf,w7,w6);
    SHA256_STEP(c,d,e,f,g,h,a,b,w6,0x81c2c92eu);
    w7=SHA256_EXPAND(w5,w0,w8,w7);
    SHA256_STEP(b,c,d,e,f,g,h,a,w7,0x92722c85u);
    w8=SHA256_EXPAND(w6,w1,w9,w8);
    SHA256_STEP(a,b,c,d,e,f,g,h,w8,0xa2bfe8a1u);
    w9=SHA256_EXPAND(w7,w2,wa,w9);
    SHA256_STEP(h,a,b,c,d,e,f,g,w9,0xa81a664bu);
    wa=SHA256_EXPAND(w8,w3,wb,wa);
    SHA256_STEP(g,h,a,b,c,d,e,f,wa,0xc24b8b70u);
    wb=SHA256_EXPAND(w9,w4,wc,wb);
    SHA256_STEP(f,g,h,a,b,c,d,e,wb,0xc76c51a3u);
    wc=SHA256_EXPAND(wa,w5,wd,wc);
    SHA256_STEP(e,f,g,h,a,b,c,d,wc,0xd192e819u);
    wd=SHA256_EXPAND(wb,w6,we,wd);
    SHA256_STEP(d,e,f,g,h,a,b,c,wd,0xd6990624u);
    we=SHA256_EXPAND(wc,w7,wf,we);
    SHA256_STEP(c,d,e,f,g,h,a,b,we,0xf40e3585u);
    wf=SHA256_EXPAND(wd,w8,w0,wf);
    SHA256_STEP(b,c,d,e,f,g,h,a,wf,0x106aa070u);
    w0=SHA256_EXPAND(we,w9,w1,w0);
    SHA256_STEP(a,b,c,d,e,f,g,h,w0,0x19a4c116u);
    w1=SHA256_EXPAND(wf,wa,w2,w1);
    SHA256_STEP(h,a,b,c,d,e,f,g,w1,0x1e376c08u);
    w2=SHA256_EXPAND(w0,wb,w3,w2);
    SHA256_STEP(g,h,a,b,c,d,e,f,w2,0x2748774cu);
    w3=SHA256_EXPAND(w1,wc,w4,w3);
    SHA256_STEP(f,g,h,a,b,c,d,e,w3,0x34b0bcb5u);
    w4=SHA256_EXPAND(w2,wd,w5,w4);
    SHA256_STEP(e,f,g,h,a,b,c,d,w4,0x391c0cb3u);
    w5=SHA256_EXPAND(w3,we,w6,w5);
    SHA256_STEP(d,e,f,g,h,a,b,c,w5,0x4ed8aa4au);
    w6=SHA256_EXPAND(w4,wf,w7,w6);
    SHA256_STEP(c,d,e,f,g,h,a,b,w6,0x5b9cca4fu);
    w7=SHA256_EXPAND(w5,w0,w8,w7);
    SHA256_STEP(b,c,d,e,f,g,h,a,w7,0x682e6ff3u);
    w8=SHA256_EXPAND(w6,w1,w9,w8);
    SHA256_STEP(a,b,c,d,e,f,g,h,w8,0x748f82eeu);
    w9=SHA256_EXPAND(w7,w2,wa,w9);
    SHA256_STEP(h,a,b,c,d,e,f,g,w9,0x78a5636fu);
    wa=SHA256_EXPAND(w8,w3,wb,wa);
    SHA256_STEP(g,h,a,b,c,d,e,f,wa,0x84c87814u);
    wb=SHA256_EXPAND(w9,w4,wc,wb);
    SHA256_STEP(f,g,h,a,b,c,d,e,wb,0x8cc70208u);
    wc=SHA256_EXPAND(wa,w5,wd,wc);
    SHA256_STEP(e,f,g,h,a,b,c,d,wc,0x90befffau);
    wd=SHA256_EXPAND(wb,w6,we,wd);
    SHA256_STEP(d,e,f,g,h,a,b,c,wd,0xa4506cebu);
    we=SHA256_EXPAND(wc,w7,wf,we);
    SHA256_STEP(c,d,e,f,g,h,a,b,we,0xbef9a3f7u);
    wf=SHA256_EXPAND(wd,w8,w0,wf);
    SHA256_STEP(b,c,d,e,f,g,h,a,wf,0xc67178f2u);
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}


__device__ void sha256_init(uint32_t state[8]) {
    state[0]=0x6a09e667; state[1]=0xbb67ae85; state[2]=0x3c6ef372; state[3]=0xa54ff53a;
    state[4]=0x510e527f; state[5]=0x9b05688c; state[6]=0x1f83d9ab; state[7]=0x5be0cd19;
}

__device__ void hmac_init(const uint8_t key[64], uint32_t inner[8], uint32_t outer[8]) {
    uint8_t block[64];
    #pragma unroll
    for (int i=0;i<64;++i) block[i]=key[i]^0x36;
    sha256_init(inner); sha256_compress_unrolled(inner, block);
    #pragma unroll
    for (int i=0;i<64;++i) block[i]=key[i]^0x5c;
    sha256_init(outer); sha256_compress_unrolled(outer, block);
}

// HMAC-SHA256 where the 64-byte key block has already been compressed and the
// remaining message is either 4 bytes (PBKDF2 U1) or 32 bytes (later U values).
__device__ void hmac_sha256(const uint32_t inner_base[8], const uint32_t outer_base[8],
                            const uint8_t *message, int message_len, uint8_t output[32]) {
    uint8_t block[64];
    uint32_t inner[8], outer[8];
    #pragma unroll
    for (int i=0;i<8;++i) { inner[i]=inner_base[i]; outer[i]=outer_base[i]; }
    #pragma unroll
    for (int i=0;i<64;++i) block[i]=0;
    for (int i=0;i<message_len;++i) block[i]=message[i];
    block[message_len]=0x80;
    uint64_t inner_bits=uint64_t(64+message_len)*8;
    for (int i=0;i<8;++i) block[63-i]=uint8_t(inner_bits>>(i*8));
    sha256_compress_unrolled(inner, block);

    #pragma unroll
    for (int i=0;i<64;++i) block[i]=0;
    #pragma unroll
    for (int i=0;i<8;++i) store_be32(block+i*4, inner[i]);
    block[32]=0x80;
    const uint64_t outer_bits=(64+32)*8;
    for (int i=0;i<8;++i) block[63-i]=uint8_t(outer_bits>>(i*8));
    sha256_compress_unrolled(outer, block);
    #pragma unroll
    for (int i=0;i<8;++i) store_be32(output+i*4, outer[i]);
}

__global__ void pbkdf2_kernel(const uint8_t *keys, uint32_t iterations,
                              uint8_t *outputs, uint64_t count) {
    uint64_t index=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if (index>=count) return;
    const uint8_t *key=keys+index*64;
    uint8_t u[32], result[32];
    uint32_t inner_base[8], outer_base[8];
    hmac_init(key,inner_base,outer_base);
    const uint8_t block_index[4]={0,0,0,1};
    hmac_sha256(inner_base,outer_base,block_index,4,u);
    #pragma unroll
    for (int i=0;i<32;++i) result[i]=u[i];
    for (uint32_t round=1;round<iterations;++round) {
        hmac_sha256(inner_base,outer_base,u,32,u);
        #pragma unroll
        for (int i=0;i<32;++i) result[i]^=u[i];
    }
    #pragma unroll
    for (int i=0;i<32;++i) outputs[index*32+i]=result[i];
}

void set_error(char *error, size_t error_len, const char *operation, cudaError_t code) {
    if (error && error_len) snprintf(error,error_len,"%s: %s",operation,cudaGetErrorString(code));
}

} // namespace

extern "C" int preimage_cuda_device_count(int *count, char *error, size_t error_len) {
    cudaError_t code=cudaGetDeviceCount(count);
    if (code!=cudaSuccess) { set_error(error,error_len,"cudaGetDeviceCount",code); return int(code); }
    return 0;
}

extern "C" int preimage_cloudap_pbkdf2(const uint8_t *keys, uint64_t count,
                                         uint32_t iterations, int device,
                                         uint8_t *outputs, char *error,
                                         size_t error_len) {
    if (!keys || !outputs || !count || !iterations || device < 0) {
        if (error && error_len) snprintf(error,error_len,"invalid CUDA PBKDF2 arguments");
        return -1;
    }
    cudaError_t code=cudaSetDevice(device);
    if (code!=cudaSuccess) { set_error(error,error_len,"cudaSetDevice",code); return int(code); }

    uint8_t *device_keys=nullptr,*device_outputs=nullptr;
    size_t key_bytes=size_t(count)*64, output_bytes=size_t(count)*32;
    code=cudaMalloc(reinterpret_cast<void **>(&device_keys),key_bytes);
    if (code!=cudaSuccess) { set_error(error,error_len,"cudaMalloc(keys)",code); return int(code); }
    code=cudaMalloc(reinterpret_cast<void **>(&device_outputs),output_bytes);
    if (code!=cudaSuccess) { set_error(error,error_len,"cudaMalloc(outputs)",code); cudaFree(device_keys); return int(code); }
    code=cudaMemcpy(device_keys,keys,key_bytes,cudaMemcpyHostToDevice);
    if (code==cudaSuccess) {
        const int threads=128;
        const unsigned blocks=unsigned((count+threads-1)/threads);
        pbkdf2_kernel<<<blocks,threads>>>(device_keys,iterations,device_outputs,count);
        code=cudaGetLastError();
    }
    if (code==cudaSuccess) code=cudaMemcpy(outputs,device_outputs,output_bytes,cudaMemcpyDeviceToHost);
    cudaFree(device_outputs); cudaFree(device_keys);
    if (code!=cudaSuccess) { set_error(error,error_len,"CloudAP CUDA kernel",code); return int(code); }
    return 0;
}
