// Source - https://stackoverflow.com/a/78647285
// Posted by Marco Bonelli, modified by community. See post 'Timeline' for change history
// Retrieved 2026-03-26, License - CC BY-SA 4.0

// SPDX-License-Identifier: GPL-3.0
#include <linux/init.h>     // module_{init,exit}()
#include <linux/module.h>   // THIS_MODULE, MODULE_VERSION, ...
#include <linux/kernel.h>   // printk(), pr_*()
#include <linux/kallsyms.h> // kallsyms_lookup_name()
#include <asm/syscall.h>    // syscall_fn_t, __NR_*
#include <asm/ptrace.h>     // struct pt_regs
#include <asm/tlbflush.h>   // flush_tlb_kernel_range()
#include <asm/pgtable.h>    // {clear,set}_pte_bit(), set_pte()
#include <linux/vmalloc.h>  // vm_unmap_aliases()
#include <linux/mm.h>       // struct mm_struct, apply_to_page_range()
#include <linux/kprobes.h>  // register_kprobe(), unregister_kprobe()


#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

typedef unsigned long (*kallsyms_lookup_name_t)(const char *);

static struct mm_struct *init_mm_ptr;
static syscall_fn_t *syscall_table;
static syscall_fn_t original_read;

/***** HELPERS ****************************************************************/

/**
 * This is an enhanced implementation of __apply_to_page_range() that is also
 * capable of handling huge PMD mappings (pmd_leaf()). The original
 * implementation of __apply_to_page_range() only handles last-level PTEs, and
 * fails with -EINVAL for PMD mappings. This implementation takes 2 function
 * pointers instead of a single one:
 *
 *   - pte_fn_t fn_pte: function to apply changes to a leaf PTE
 *   - pmd_fn_t fn_pmd: function to apply changes to a leaf PMD
 */

// pte_fn_t already present in <linux/mm.h>
typedef int (*pmd_fn_t)(pmd_t *pmd, unsigned long addr, void *data);

// From arch/arm64/mm/hugetlbpage.c
int pmd_huge(pmd_t pmd)
{
    return pmd_val(pmd) && !(pmd_val(pmd) & PMD_TABLE_BIT);
}

// Adapted from arch/arm64/mm/hugetlbpage.c
int pud_huge(pud_t pud)
{
#if CONFIG_PGTABLE_LEVELS == 2
    return 0;
#else
    return pud_val(pud) && !(pud_val(pud) & PUD_TABLE_BIT);
#endif
}

// From arch/arm64/mm/pageattr.c.
struct page_change_data {
    pgprot_t set_mask;
    pgprot_t clear_mask;
};

// From arch/arm64/mm/pageattr.c.
static int change_page_range(pte_t *ptep, unsigned long addr, void *data)
{
    struct page_change_data *cdata = data;
    pte_t pte = READ_ONCE(*ptep);

    pte = clear_pte_bit(pte, cdata->clear_mask);
    pte = set_pte_bit(pte, cdata->set_mask);

    set_pte(ptep, pte);
    return 0;
}

static int change_pmd_range(pmd_t *pmdp, unsigned long addr, void *data)
{
    struct page_change_data *cdata = data;
    pmd_t pmd = READ_ONCE(*pmdp);

    pmd = clear_pmd_bit(pmd, cdata->clear_mask);
    pmd = set_pmd_bit(pmd, cdata->set_mask);

    set_pmd(pmdp, pmd);
    return 0;
}


// Adapted from mm/memory.c
static int apply_to_pte_range(struct mm_struct *mm, pmd_t *pmd,
                     unsigned long addr, unsigned long end,
                     pte_fn_t fn, void *data,
                     pgtbl_mod_mask *mask)
{
    pte_t *pte, *mapped_pte;
    int err = 0;
    spinlock_t *ptl;


    mapped_pte = pte = (mm == init_mm_ptr) ? pte_offset_kernel(pmd, addr) :
        pte_offset_map_lock(mm, pmd, addr, &ptl);

    BUG_ON(pmd_huge(*pmd));
    arch_enter_lazy_mmu_mode();

    if (fn) {
        do {
            if (!pte_none(*pte)) {
                err = fn(pte++, addr, data);
                if (err)
                    break;
            }
        } while (addr += PAGE_SIZE, addr != end);
    }
    *mask |= PGTBL_PTE_MODIFIED;

    arch_leave_lazy_mmu_mode();

    if (mm != init_mm_ptr)
        pte_unmap_unlock(mapped_pte, ptl);
    return err;
}

// Adapted from mm/memory.c
static int apply_to_pmd_range(struct mm_struct *mm, pud_t *pud,
                unsigned long addr, unsigned long end,
                pte_fn_t fn_pte, pmd_fn_t fn_pmd,
                void *data, pgtbl_mod_mask *mask)
{
    pmd_t *pmd;
    unsigned long next;
    int err = 0;

    BUG_ON(pud_huge(*pud));

    pmd = pmd_offset(pud, addr);
    do {
        next = pmd_addr_end(addr, end);
        if (pmd_none(*pmd))
            continue;

        if (pmd_leaf(*pmd)) {
            if (!fn_pmd || pmd_none(*pmd))
                continue;

            err = fn_pmd(pmd, addr, data);
            if (err)
                break;
        } else {
            if (!pmd_none(*pmd) && WARN_ON_ONCE(pmd_bad(*pmd)))
                continue;

            err = apply_to_pte_range(mm, pmd, addr, next, fn_pte,
                data, mask);
            if (err)
                break;
        }
    } while (pmd++, addr = next, addr != end);

    return err;
}

// Adapted from mm/memory.c
static int apply_to_pud_range(struct mm_struct *mm, p4d_t *p4d,
                unsigned long addr, unsigned long end,
                pte_fn_t fn_pte, pmd_fn_t fn_pmd,
                void *data, pgtbl_mod_mask *mask)
{
    pud_t *pud;
    unsigned long next;
    int err = 0;

    pud = pud_offset(p4d, addr);
    do {
        next = pud_addr_end(addr, end);
        if (pud_none(*pud))
            continue;
        if (WARN_ON_ONCE(pud_leaf(*pud)))
            return -EINVAL;
        if (!pud_none(*pud) && WARN_ON_ONCE(pud_bad(*pud)))
            continue;
        err = apply_to_pmd_range(mm, pud, addr, next, fn_pte,
            fn_pmd, data, mask);
        if (err)
            break;
    } while (pud++, addr = next, addr != end);

    return err;
}

// Adapted from mm/memory.c
static int apply_to_p4d_range(struct mm_struct *mm, pgd_t *pgd,
                unsigned long addr, unsigned long end,
                pte_fn_t fn_pte, pmd_fn_t fn_pmd,
                void *data, pgtbl_mod_mask *mask)
{
    p4d_t *p4d;
    unsigned long next;
    int err = 0;

    p4d = p4d_offset(pgd, addr);
    do {
        next = p4d_addr_end(addr, end);
        if (p4d_none(*p4d))
            continue;
        if (WARN_ON_ONCE(p4d_leaf(*p4d)))
            return -EINVAL;
        if (!p4d_none(*p4d) && WARN_ON_ONCE(p4d_bad(*p4d)))
            continue;
        err = apply_to_pud_range(mm, p4d, addr, next, fn_pte, fn_pmd,
            data, mask);
        if (err)
            break;
    } while (p4d++, addr = next, addr != end);

    return err;
}

// Adapted from mm/memory.c
static int __apply_to_page_range(struct mm_struct *mm, unsigned long addr,
                 unsigned long size,
                 pte_fn_t fn_pte, pmd_fn_t fn_pmd,
                 void *data)
{
    pgd_t *pgd;
    unsigned long start = addr, next;
    unsigned long end = addr + size;
    pgtbl_mod_mask mask = 0;
    int err = 0;

    if (WARN_ON(addr >= end))
        return -EINVAL;

    pgd = pgd_offset(mm, addr);
    do {
        next = pgd_addr_end(addr, end);
        if (pgd_none(*pgd))
            continue;
        if (WARN_ON_ONCE(pgd_leaf(*pgd)))
            return -EINVAL;
        if (!pgd_none(*pgd) && WARN_ON_ONCE(pgd_bad(*pgd)))
            continue;
        err = apply_to_p4d_range(mm, pgd, addr, next, fn_pte, fn_pmd,
            data, &mask);
        if (err)
            break;
    } while (pgd++, addr = next, addr != end);

    if (mask & ARCH_PAGE_TABLE_SYNC_MASK)
        arch_sync_kernel_mappings(start, start + size);

    return err;
}

// Adapted from arch/arm64/mm/pageattr.c.
static int __change_memory_common(unsigned long start, unsigned long size,
                  pgprot_t set_mask, pgprot_t clear_mask)
{
    struct page_change_data data;
    int ret;

    data.set_mask = set_mask;
    data.clear_mask = clear_mask;

    ret = __apply_to_page_range(init_mm_ptr, start, size,
        &change_page_range, &change_pmd_range, &data);
    if (ret)
        pr_info("__apply_to_page_range() failed: %d\n", ret);

    flush_tlb_kernel_range(start, start + size);
    return ret;
}

// Simplified version of set_memory_rw() from arch/arm64/mm/pageattr.c.
static int set_page_rw(unsigned long addr)
{
    vm_unmap_aliases();
    return __change_memory_common(addr, PAGE_SIZE, __pgprot(PTE_WRITE), __pgprot(PTE_RDONLY));
}

// Simplified version of set_memory_ro() from arch/arm64/mm/pageattr.c.
static int set_page_ro(unsigned long addr)
{
    vm_unmap_aliases();
    return __change_memory_common(addr, PAGE_SIZE, __pgprot(PTE_RDONLY), __pgprot(PTE_WRITE));
}

/***** ACTUAL MODULE **********************************************************/

static long myread(const struct pt_regs *regs)
{
    pr_info("read() called\n");
    return original_read(regs);
}

static int __init modinit(void)
{
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    kallsyms_lookup_name_t kallsyms_lookup_name;
    int res;

    pr_info("init\n");

    // Workaround for kallsyms_lookup_name() not being exported: find it
    // using kprobes.
    res = register_kprobe(&kp);
    if (res != 0) {
        pr_err("register_kprobe() failed: %d\n", res);
        return res;
    }

    kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    init_mm_ptr = (struct mm_struct *)kallsyms_lookup_name("init_mm");
    if (!init_mm_ptr) {
        pr_err("init_mm not found\n");
        return -ENOSYS;
    }

    syscall_table = (syscall_fn_t *)kallsyms_lookup_name("sys_call_table");
    if (!syscall_table) {
        pr_err("sys_call_table not found\n");
        return -ENOSYS;
    }

    original_read = syscall_table[__NR_read];

    res = set_page_rw((unsigned long)(syscall_table + __NR_read) & PAGE_MASK);
    if (res != 0) {
        pr_err("set_page_rw() failed: %d\n", res);
        return res;
    }

    syscall_table[__NR_read] = myread;

    res = set_page_ro((unsigned long)(syscall_table + __NR_read) & PAGE_MASK);
    if (res != 0) {
        pr_err("set_page_ro() failed: %d\n", res);
        return res;
    }

    pr_info("init done\n");

    return 0;
}

static void __exit modexit(void)
{
    int res;

    pr_info("exit\n");

    res = set_page_rw((unsigned long)(syscall_table + __NR_read) & PAGE_MASK);
    if (res != 0) {
        pr_err("set_page_rw() failed: %d\n", res);
        return;
    }

    syscall_table[__NR_read] = original_read;

    res = set_page_ro((unsigned long)(syscall_table + __NR_read) & PAGE_MASK);
    if (res != 0)
        pr_err("set_page_ro() failed: %d\n", res);

    pr_info("goodbye\n");
}

module_init(modinit);
module_exit(modexit);
MODULE_VERSION("0.1");
MODULE_AUTHOR("Marco Bonelli");
MODULE_DESCRIPTION("Syscall hijack on arm64.");
MODULE_LICENSE("GPL");
