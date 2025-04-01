#include "types.h"
#include "gdb_stub.h"
#include "uart.h"
#include "tsc.h"
#include "memmap.h"
#include "utils.h"
#include "string.h"

static void delay(uint64_t microseconds)
{
    uint64_t start = rdtsc();
    uint64_t delay = microseconds * TSC_FREQ_HZ / 1000000;
    while(rdtsc() - start < delay);
}

static uint8_t packet[4096];

static inline int hex2int(char c)
{
    if(c >= 'a' && c <= 'z')
        return c - 'a' + 10;
    else if(c >= 'A' && c <= 'Z')
        return c - 'A' + 10;
    else
        return c - '0';
}

static inline char int2hex(int c)
{
    if(c < 10)
        return c + '0';
    else
        return c - 10 + 'a';
}

static uint64_t read_packet(void)
{
    for(;;)
    {
        while(getchar() != '$');
        size_t i = 0;
        uint8_t checksum = 0;
        while(i < sizeof(packet) && (packet[i] = getchar()) != '#')
            checksum += packet[i++];
        if(i == sizeof(packet) && getchar() != '#')
        {
            while(getchar() != '#');
            getchar();
            getchar();
            continue;
        }
        uint8_t a = hex2int(getchar());
        uint8_t b = hex2int(getchar());
        if(checksum == 16 * a + b)
        {
            putchar('+');
            return i;
        }
    }
}

static void write_packet(size_t sz)
{
    for(;;)
    {
        uint8_t checksum = 0;
        putchar('$');
        for(size_t i = 0; i < sz; i++)
        {
            checksum += packet[i];
            putchar(packet[i]);
        }
        putchar('#');
        putchar(int2hex(checksum / 16));
        putchar(int2hex(checksum % 16));
        int c;
        while((c = getchar_nonblocking()) >= 0)
            if(c == '+')
                return;
        if(getchar() == '+')
            return;
        delay(1000000);
    }
}

static void pkt_putstr(size_t* sz, const char* s)
{
    size_t off = *sz;
    while(off < sizeof(packet) && *s)
        packet[off++] = *s++;
    *sz = off;
}

static void pkt_puthex(size_t* sz, uint64_t value)
{
    size_t off = *sz;
    for(int i = 60; i >= 0 && off < sizeof(packet); i -= 4)
        packet[off++] = int2hex((value >> i) & 15);
    *sz = off;
}

static void pkt_putrevhex(size_t* sz, uint64_t value, int bits)
{
    size_t off = *sz;
    for(int i = 0; i < bits && off < sizeof(packet); i += 4)
        packet[off++] = int2hex((value >> (i ^ 4)) & 15);
    *sz = off;
}

static int memcmp(const char* a, const char* b, size_t sz)
{
    for(size_t i = 0; i < sz; i++)
        if(a[i] != b[i])
            return a[i] - b[i];
    return 0;
}

static int mutex = 0;

uint64_t pkt_getrevhex(size_t* pos, size_t size, int bits)
{
    size_t off = *pos;
    uint64_t value = 0;
    for(int i = 0; i < bits && off < size; i += 4)
        value |= (uint64_t)hex2int(packet[off++]) << (i ^ 4);
    *pos = off;
    return value;
}

struct
{
    int dangerous_read;
} gdb_magic;

static void do_gdb_stub(uint64_t* regs, uint64_t* trap_frame)
{
    for(;;)
    {
        size_t sz = read_packet();
        size_t wsz = 0;
        if(sz == 1 && packet[0] == '?')
        {
            pkt_putstr(&wsz, "T05");
            write_packet(wsz);
        }
        else if(sz == 8 && !memcmp(packet, "qOffsets", 8))
        {
            pkt_putstr(&wsz, "TextSeg=");
            pkt_puthex(&wsz, FAKEXEN_START);
        }
        else if(sz == 1 && packet[0] == 'g')
        {
            pkt_putrevhex(&wsz, regs[0], 64);
            pkt_putrevhex(&wsz, regs[3], 64);
            pkt_putrevhex(&wsz, regs[1], 64);
            pkt_putrevhex(&wsz, regs[2], 64);
            pkt_putrevhex(&wsz, regs[6], 64);
            pkt_putrevhex(&wsz, regs[7], 64);
            pkt_putrevhex(&wsz, regs[5], 64);
            pkt_putrevhex(&wsz, trap_frame[3], 64);
            for(size_t i = 8; i < 16; i++)
                pkt_putrevhex(&wsz, regs[i], 64);
            pkt_putrevhex(&wsz, trap_frame[0], 64);
            pkt_putrevhex(&wsz, trap_frame[2], 32);
            pkt_putrevhex(&wsz, trap_frame[1], 32);
            pkt_putrevhex(&wsz, trap_frame[4], 32);
            pkt_putrevhex(&wsz, 0, 64);
            pkt_putrevhex(&wsz, 0, 64);
            while(wsz < 1120)
                packet[wsz++] = 'x';
        }
        else if(sz && packet[0] == 'm')
        {
            uint64_t addr = 0;
            size_t pos = 1;
            while(pos < sz && packet[pos] != ',')
                addr = 16 * addr + hex2int(packet[pos++]);
            pos++;
            uint64_t size = 0;
            while(pos < sz)
                size = 16 * size + hex2int(packet[pos++]);
            char buf[64] = {};
            while(size)
            {
                size_t chk = size;
                if(chk > sizeof(buf))
                    chk = sizeof(buf);
                if(addr >= FAKEXEN_END && addr < new_kdata_base)
                    break;
                if(copy_from_kernel(GUEST_STATE.cr3 ?: initial_cr3, buf, addr, chk))
                    break;
                if(gdb_magic.dangerous_read)
                    memcpy(buf, (void*)addr, chk);
                for(size_t i = 0; i < chk; i++)
                    pkt_putrevhex(&wsz, buf[i], 8);
                addr += chk;
                size -= chk;
            }
        }
        else if(sz && packet[0] == 'G')
        {
            size_t pos = 1;
            regs[0] = pkt_getrevhex(&pos, sz, 64);
            regs[3] = pkt_getrevhex(&pos, sz, 64);
            regs[1] = pkt_getrevhex(&pos, sz, 64);
            regs[2] = pkt_getrevhex(&pos, sz, 64);
            regs[6] = pkt_getrevhex(&pos, sz, 64);
            regs[7] = pkt_getrevhex(&pos, sz, 64);
            regs[5] = pkt_getrevhex(&pos, sz, 64);
            trap_frame[3] = regs[4] = pkt_getrevhex(&pos, sz, 64);
            for(size_t i = 8; i < 16; i++)
                regs[i] = pkt_getrevhex(&pos, sz, 64);
            trap_frame[0] = pkt_getrevhex(&pos, sz, 64);
            trap_frame[2] = pkt_getrevhex(&pos, sz, 32);
            pkt_putstr(&wsz, "OK");
        }
        else if(sz && packet[0] == 'M')
        {
            uint64_t addr = 0;
            size_t pos = 1;
            while(pos < sz && packet[pos] != ',')
                addr = 16 * addr + hex2int(packet[pos++]);
            pos++;
            uint64_t size = 0;
            while(pos < sz && packet[pos] != ':')
                size = 16 * size + hex2int(packet[pos++]);
            pos++;
            pkt_putstr(&wsz, "OK");
            char buf[64] = {};
            while(size)
            {
                size_t chk = size;
                if(chk > sizeof(buf))
                    chk = sizeof(buf);
                for(size_t i = 0; i < chk; i++)
                {
                    uint8_t a = pos < sz ? hex2int(packet[pos++]) : 0;
                    uint8_t b = pos < sz ? hex2int(packet[pos++]) : 0;
                    buf[i] = 16 * a + b;
                }
                if((addr >= FAKEXEN_END && addr < new_kdata_base) || copy_to_kernel(GUEST_STATE.cr3 ?: initial_cr3, addr, buf, chk))
                {
                    wsz = 0;
                    pkt_putstr(&wsz, "E14");
                    break;
                }
                addr += chk;
                size -= chk;
            }
        }
        else if(sz && (packet[0] == 's' || packet[0] == 'c' || packet[0] == 'F'))
        {
            if(packet[0] == 's')
                trap_frame[2] |= 256;
            __atomic_store_n(&mutex, 1, __ATOMIC_SEQ_CST);
            return;
        }
        write_packet(wsz);
    }
}

static inline int gdb_stub_lock(void)
{
    int value = 0;
    int first = 0;
    if(__atomic_compare_exchange_n(&mutex, &value, 1, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
        first = 1;
    value = 1;
    while(!__atomic_compare_exchange_n(&mutex, &value, 2, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
        value = 1;
    return first;
}

void gdb_stub(uint64_t* regs, uint64_t* trap_frame)
{
    int first = gdb_stub_lock();
    trap_frame[2] &= -257;
    if(first)
        putstr("\r\n\r\nGDB stub activated. You can connect with GDB for post-mortem debugging.\r\n\r\n");
    else
    {
        size_t wsz = 0;
        pkt_putstr(&wsz, "T05");
        write_packet(wsz);
    }
    do_gdb_stub(regs, trap_frame);
}

int gdb_stub_active(void)
{
    return !!__atomic_load_n(&mutex, __ATOMIC_SEQ_CST);
}

void gdb_stub_syscall(const char* name, int nargs, uint64_t* args)
{
    gdb_stub_lock();
    uint64_t regs[16] = {};
    uint64_t trap_frame[5] = {};
    size_t wsz = 0;
    pkt_putstr(&wsz, "F");
    pkt_putstr(&wsz, name);
    for(size_t i = 0; i < nargs; i++)
    {
        pkt_putstr(&wsz, ",");
        pkt_puthex(&wsz, args[i]);
    }
    write_packet(wsz);
    do_gdb_stub(regs, trap_frame);
}
