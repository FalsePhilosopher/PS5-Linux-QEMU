#include <sstream>
#include <unordered_map>
#include <libboot/vm.hpp>
#include <libboot/hook.hpp>
#include <liblog/logging.hpp>
#include <libsmp/global_lock.hpp>
#include <libsmp/acpi.hpp>
extern "C"
{
    #include <fs.h>
    #include <elf_struct.h>
    #include <sysregs.h>
    extern char fakekernel_start[];
    extern char fakekernel_end[];
    extern char trampoline_start[];
    extern char trampoline_end[];
}

static inline uint64_t virt2phys(void* ptr)
{
    return ((uint64_t*)PML1_MOD_BASE)[((uint64_t)ptr) >> 12] & PG_ADDR_MASK_4KB;
}

int main(const char* cmdline)
{
    std::istringstream params(cmdline);
    std::string fakexen_path;
    params >> fakexen_path;
    std::string linux_path;
    params >> linux_path;
    struct ehdr eh = {0};
    FILE* f1 = open(fakexen_path.c_str(), O_RDONLY);
    FILE* f2 = open(linux_path.c_str(), O_RDONLY);
    pread(f1, &eh, sizeof(eh), 0);
    uint64_t max_addr = 0;
    for(size_t i = 0; i < eh.e_phnum; i++)
    {
        struct phdr ph = {0};
        pread(f1, &ph, sizeof(ph), eh.e_phoff + 56 * i);
        max_addr = std::max(max_addr, ph.p_vaddr + ph.p_memsz);
    }
    max_addr = ((max_addr - 1) | 4095) + 1;
    uint64_t linux_offset = max_addr;
    size_t linux_size = lseek(f2, 0, SEEK_END);
    size_t size = linux_offset + linux_size;
    char* mapping = (char*)mmap(0, size, PROT_READ|PROT_WRITE|PROT_NOEXEC, MAP_ANON);
    uint64_t dynamic_start = 0, dynamic_end = 0;
    for(size_t i = 0; i < eh.e_phnum; i++)
    {
        struct phdr ph = {0};
        pread(f1, &ph, sizeof(ph), eh.e_phoff + 56 * i);
        if(ph.p_type == PT_LOAD)
        {
            pread(f1, mapping + ph.p_vaddr, ph.p_filesz, ph.p_offset);
            memset(mapping + ph.p_filesz, 0, ph.p_memsz - ph.p_filesz);
        }
        else if(ph.p_type == PT_DYNAMIC)
        {
            dynamic_start = ph.p_vaddr;
            dynamic_end = ph.p_vaddr + ph.p_memsz;
        }
    }
    pread(f2, mapping + linux_offset, linux_size, 0);
    close(f1);
    close(f2);
    char* strtab = 0;
    char* symtab = 0;
    char* rela = 0;
    size_t relasz = 0;
    for(uint64_t q = dynamic_start; q < dynamic_end; q += 16)
    {
        uint64_t* kv = (uint64_t*)(mapping + q);
        if(kv[0] == 5)
            strtab = mapping + kv[1];
        else if(kv[0] == 6)
            symtab = mapping + kv[1];
        else if(kv[0] == 7)
            rela = mapping + kv[1];
        else if(kv[0] == 8)
            relasz = kv[1];
    }
    auto alloc_page = []()
    {
        uint64_t* page = (uint64_t*)mmap(0, 4096, PROT_READ|PROT_WRITE|PROT_NOEXEC, MAP_ANON);
        for(size_t i = 0; i < 512; i++)
            page[i] = 0;
        return page;
    };
    uint64_t* cr3 = alloc_page();
    uint64_t* physmap1 = alloc_page();
    cr3[0] = virt2phys(physmap1) | 7;
    for(size_t i = 0; i < 512; i++)
        physmap1[i] = (i << 30) | 135;
    uint64_t* physmap2 = alloc_page();
    cr3[1] = virt2phys(physmap2) | 31;
    for(size_t i = 0; i < 512; i++)
        physmap2[i] = (i << 30) | 159;
    uint64_t* pml4 = cr3 + 2;
    for(size_t i = 0; i < size; i += (1ul << 39))
    {
        uint64_t* pml3 = alloc_page();
        *pml4++ = virt2phys(pml3) | 7;
        for(size_t j = i; j < std::min(size, i + (1ul << 39)); j += (1ul << 30))
        {
            uint64_t* pml2 = alloc_page();
            *pml3++ = virt2phys(pml2) | 7;
            for(size_t k = j; k < std::min(size, j + (1ul << 30)); k += (1ul << 21))
            {
                uint64_t* pml1 = alloc_page();
                *pml2++ = virt2phys(pml1) | 7;
                for(size_t l = k; l < std::min(size, k + (1ul << 21)); l += (1ul << 12))
                    *pml1++ = virt2phys(mapping+l) | 7;
            }
        }
    }
    uint64_t* pml3_kernel = alloc_page();
    cr3[511] = virt2phys(pml3_kernel) | 3;
    uint64_t* pml2_kernel = alloc_page();
    pml3_kernel[508] = virt2phys(pml2_kernel) | 3;
    pml2_kernel[0] = 0x10000081;
    pml2_kernel[1] = 0x10200083;
    hooks::createVCPUInitHook([=]() mutable
    {
        smp::global_lock.lock();
        static bool ran = false;
        if(!ran)
        {
            ran = true;
            std::unordered_map<std::string, size_t> kernel_symbols;
            char* q = fakekernel_start;
            while(*q)
            {
                std::string name = q;
                q += name.size() + 1;
                uint64_t value;
                memcpy(&value, q, sizeof(value));
                q += sizeof(value);
                kernel_symbols[name] = value;
            }
            q++;
            size_t kdata_base = kernel_symbols["kdata_base"];
            size_t offset = 0x200000 - kdata_base % 0x200000;
            size_t gdt_array = kernel_symbols["gdt_array"] + offset;
            for(auto& i : kernel_symbols)
                i.second += 0xffffffff00200000 - kdata_base;
            size_t tss_array = kernel_symbols["tss_array"];
            char* fakekernel = (char*)mmap(0, fakekernel_end-fakekernel_start+offset, PROT_READ|PROT_WRITE|PROT_NOEXEC, 0x10000000);
            memcpy(fakekernel+offset, fakekernel_start, fakekernel_end-fakekernel_start);
            for(size_t i = 0; i < 16; i++)
            {
                uint64_t addr = tss_array + 0x68 * i;
                char* p = (char*)&addr;
                char* gdt = fakekernel+gdt_array+0x68*i;
                memcpy(gdt+0x48+2, p, 3);
                memcpy(gdt+0x48+7, p+3, 5);
            }
            munmap(fakekernel, fakekernel_end-fakekernel_start+offset);
            vm::VM* vcpu = boot::curVCPU();
            char* dos_mem = (char*)mmap(0, 1048576, PROT_READ|PROT_WRITE|PROT_NOEXEC, 0);
            uint64_t e820_map = vcpu->get_reg(vm::Register::RSI) + 0x2d0;
            uint64_t e820_map_end = e820_map + dos_mem[vcpu->get_reg(vm::Register::RSI) + 0x1e8] * 20;
            void* e820_map_copy = (void*)mmap(0, 4096, PROT_READ|PROT_WRITE|PROT_NOEXEC, MAP_ANON);
            memcpy(e820_map_copy, dos_mem+e820_map, e820_map_end - e820_map);
            uint64_t e820_map_phys = virt2phys(e820_map_copy);
            e820_map_end += e820_map_phys - e820_map;
            e820_map = e820_map_phys;
            kernel_symbols["image_start"] = 0xffff810000000000;
            kernel_symbols["linux_start"] = 0xffff810000000000 + linux_offset;
            kernel_symbols["linux_end"] = 0xffff810000000000 + size;
            kernel_symbols["image_end"] = 0xffff810000000000 + size;
            kernel_symbols["e820_start"] = e820_map;
            kernel_symbols["e820_end"] = e820_map_end;
            kernel_symbols["acpi_rsdp"] = smp::get_rsdp();
            for(size_t i = 0; i < relasz; i += 24)
            {
                uint64_t* oia = (uint64_t*)(rela + i);
                if((uint32_t)oia[1] == 1 || (uint32_t)oia[1] == 6)
                {
                    uint64_t* sym = (uint64_t*)(symtab + 24 * (oia[1] >> 32));
                    const char* name = strtab + (uint32_t)sym[0];
                    uint64_t value = sym[1];
                    if(!value)
                    {
                        value = kernel_symbols[name];
                        if(!value)
                            logging::log << name << " not found!" << std::endl;
                    }
                    value += oia[2];
                    memcpy(mapping + oia[0], &value, sizeof(value));
                }
                else if((uint64_t)oia[1] == 8)
                {
                    uint64_t value = 0xffff810000000000 + oia[2];
                    memcpy(mapping + oia[0], &value, sizeof(value));
                }
                else
                    logging::log << "Unknown relocation type " << (uint32_t)oia[1] << std::endl;
            }
            memcpy(dos_mem+0x8000, trampoline_start, trampoline_end-trampoline_start);
            munmap(dos_mem, 1048576);
            uint64_t cr3_phys = virt2phys(cr3);
            vcpu->set_reg(vm::Register::CR0, vcpu->get_reg(vm::Register::CR0) | 0x80000001);
            vcpu->set_reg(vm::Register::CR4, vcpu->get_reg(vm::Register::CR4) | 32);
            vcpu->set_reg(vm::Register::CR3, cr3_phys);
            vcpu->wrmsr(IA32_EFER, vcpu->rdmsr(IA32_EFER) | 0x500);
            vm::GDTEntry cs64, ds32;
            memset(cs64.data, 0, 16);
            memset(ds32.data, 0, 16);
            memcpy(cs64.data, "\xff\xff\x00\x00\x00\x9b\xaf\x00", 8);
            memcpy(ds32.data, "\xff\xff\x00\x00\x00\x93\xcf\x00", 8);
            vcpu->set_segment(vm::Register::CS, 8, cs64);
            vcpu->set_segment(vm::Register::DS, 0, ds32);
            vcpu->set_segment(vm::Register::ES, 0, ds32);
            vcpu->set_segment(vm::Register::SS, 0, ds32);
            vcpu->set_segment(vm::Register::FS, 0, ds32);
            vcpu->set_segment(vm::Register::GS, 0, ds32);
            vcpu->set_reg(vm::Register::RDI, cr3_phys);
            vcpu->set_reg(vm::Register::RSI, 0x10000000000 + eh.e_entry);
            vcpu->set_reg(vm::Register::RDX, kernel_symbols["gdt_array"]);
            vcpu->set_reg(vm::Register::RCX, kernel_symbols["idt"]);
            vcpu->set_reg(vm::Register::R8, kernel_symbols["loader_retpoline"]);
            vcpu->set_reg(vm::Register::RIP, 0x8000);
            vcpu->set_reg(vm::Register::RFLAGS, 2);
        }
        smp::global_lock.unlock();
        return true;
    });
    return 0;
}
