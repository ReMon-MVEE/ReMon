#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/rmap.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/unistd.h>
#include <linux/pid_namespace.h>
#include <linux/mman.h>

#include "PMVEE.h"

#include <asm/tlb.h>


MODULE_LICENSE("GPL"); // todo
MODULE_AUTHOR("Jonas Vinck");
MODULE_DESCRIPTION("PMVEE project kernel module");
MODULE_VERSION("0.1");


#define PMVEE_KERNEL_UNMAP                  0 // always munmap and mmap mappings in NDP
#define PMVEE_KERNEL_NO_UNMAP               1 // use zap and copy_page_range for existing mappings
#define PMVEE_KERNEL_SKIP                   2 // use shorter zap and copy_page_range definitions in module
#define PMVEE_KERNEL_MERGE_PMD_SKIP         3 // use merged zap and copy_page_range definitions in module
#define PMVEE_KERNEL_MERGE_PMD_SHORTER_SKIP 4 // use merged zap and copy_page_range definitions in module
#define PMVEE_KERNEL_MERGE_PTE_SKIP         5 // use merged zap and copy_page_range definitions in module
#define PMVEE_KERNEL_SHORTEST_SKIP          6 // skip those pages that weren't accessed

#define PMVEE_SKIP_LEVEL PMVEE_KERNEL_MERGE_PMD_SHORTER_SKIP


// define DEBUG_ME
#ifdef DEBUG_ME
#define debugk(...) printk(__VA_ARGS__);

static void debug_print_mappings(
        struct mm_struct *from_mm,
        struct mm_struct *to_mm,
        unsigned long from,
        unsigned long size_one,
        unsigned long size_two)
{
    int mp_seen = 0;
    struct vm_area_struct * temptemptemp = from_mm->mmap;
    printk("before:\n");
    while (temptemptemp)
    {
        if (temptemptemp->vm_start >= from && temptemptemp->vm_end <= from + size_one + size_two)
        {
            if (!mp_seen)
            {
                mp_seen = 1;
                printk("mp start >>>>>>>>>>>>>>>>>>>>>");
            }
        }
        else if (mp_seen)
        {
            mp_seen = 0;
            printk("mp end >>>>>>>>>>>>>>>>>>>>>>>");
        }
        printk("   > leader:   [ 0x%lx ; 0x%lx )\n", temptemptemp->vm_start, temptemptemp->vm_end);
        temptemptemp = temptemptemp->vm_next;
    }

    temptemptemp = to_mm->mmap;
    while (temptemptemp)
    {
        if (temptemptemp->vm_start >= from && temptemptemp->vm_end <= from + size_one + size_two)
        {
            if (!mp_seen)
            {
                mp_seen = 1;
                printk("mp start >>>>>>>>>>>>>>>>>>>>>");
            }
        }
        else if (mp_seen)
        {
            mp_seen = 0;
            printk("mp end >>>>>>>>>>>>>>>>>>>>>>>");
        }
            printk("   > follower: [ 0x%lx ; 0x%lx )\n", temptemptemp->vm_start, temptemptemp->vm_end);
        temptemptemp = temptemptemp->vm_next;
    }
    printk("done.\n");
}
#else

#define debugk(...) ; // printk(__VA_ARGS__);

#endif


extern long (*pmvee_switch_stub) (
    pid_t source,
    pid_t destination,
    unsigned long from,
    unsigned long size_one,
    unsigned long size_two,
    unsigned long flags);
extern long (*pmvee_check_stub)  (
    pid_t source,
    pid_t destination,
    unsigned long from,
    unsigned long size_one,
    unsigned long size_two,
    unsigned long flags);
extern unsigned char (*pmvee_should_skip_stub) (struct pt_regs *regs, unsigned long entering);


#include <asm/pgtable.h>
#include <linux/swapops.h>
#include <linux/sched/task.h>
#include <linux/mmu_notifier.h>

/*
requires symbol: __mmu_notifier_invalidate_range_end
requires symbol: pgd_clear_bad
requires symbol: __mmu_notifier_invalidate_range_start
requires symbol: track_pfn_copy
requires symbol: p4d_clear_bad
requires symbol: __pud_alloc
requires symbol: __pmd_alloc
requires symbol: pmd_clear_bad
requires symbol: mmlist_lock
requires symbol: pud_clear_bad
requires symbol: __pte_alloc
requires symbol: sync_mm_rss
requires symbol: copy_huge_pmd
requires symbol: add_swap_count_continuation
requires symbol: swap_duplicate
requires symbol: __p4d_alloc
requires symbol: vm_normal_page
requires symbol: copy_huge_pud
requires symbol: tlb_finish_mmu
requires symbol: tlb_gather_mmu
requires: __mmu_notifier_invalidate_range
requires: tlb_flush_mmu
requires: free_swap_and_cache
requires: __tlb_remove_page_size
requires: page_remove_rmap
ERROR: "untrack_pfn" [/home/jonas/repos/ReMon-private/PMVEE/pmvee_kernel_module.ko] undefined!
ERROR: "uprobe_munmap" [/home/jonas/repos/ReMon-private/PMVEE/pmvee_kernel_module.ko] undefined!
ERROR: "lru_add_drain" [/home/jonas/repos/ReMon-private/PMVEE/pmvee_kernel_module.ko] undefined!
ERROR: "page_rmapping" [/home/jonas/repos/ReMon-private/PMVEE/pmvee_kernel_module.ko] undefined!
*/

static inline bool is_cow_mapping(vm_flags_t flags)
{
	return (flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
}

static inline void add_mm_rss_vec(struct mm_struct *mm, int *rss)
{
	int i;

	if (current->mm == mm)
		sync_mm_rss(mm);
	for (i = 0; i < NR_MM_COUNTERS; i++)
		if (rss[i])
			add_mm_counter(mm, i, rss[i]);
}

static inline void init_rss_vec(int *rss)
{
	memset(rss, 0, sizeof(int) * NR_MM_COUNTERS);
}

static inline bool should_zap_cows(struct zap_details *details)
{
	/* By default, zap all pages */
	if (!details)
		return true;

	/* Or, we zap COWed pages only if the caller wants to */
	return !details->check_mapping;
}

static void flush_tlb_batched_pending(struct mm_struct *mm)
{
	if (mm->tlb_flush_batched) {
		flush_tlb_mm(mm);

		/*
		 * Do not allow the compiler to re-order the clearing of
		 * tlb_flush_batched before the tlb is flushed.
		 */
		barrier();
		mm->tlb_flush_batched = false;
	}
}

static inline unsigned long
pmvee_copy_one_pte(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		pte_t *dst_pte, pte_t *src_pte, struct vm_area_struct *vma,
		unsigned long addr, int *rss)
{
	debugk("copying %llx", addr);
	// printk("[%d] copying %llx\n", current->pid, addr);
	unsigned long vm_flags = vma->vm_flags;
	pte_t pte = *src_pte;
	struct page *page;

	/* pte contains position in swap or file, so copy. */
	if (unlikely(!pte_present(pte))) {
		swp_entry_t entry = pte_to_swp_entry(pte);

		if (likely(!non_swap_entry(entry))) {
			if (swap_duplicate(entry) < 0)
				return entry.val;

			/* make sure dst_mm is on swapoff's mmlist. */
			if (unlikely(list_empty(&dst_mm->mmlist))) {
				spin_lock(&mmlist_lock);
				if (list_empty(&dst_mm->mmlist))
					list_add(&dst_mm->mmlist,
							&src_mm->mmlist);
				spin_unlock(&mmlist_lock);
			}
			rss[MM_SWAPENTS]++;
		} else if (is_migration_entry(entry)) {
			page = migration_entry_to_page(entry);

			rss[mm_counter(page)]++;

			if (is_write_migration_entry(entry) &&
					is_cow_mapping(vm_flags)) {
				/*
				 * COW mappings require pages in both
				 * parent and child to be set to read.
				 */
				make_migration_entry_read(&entry);
				pte = swp_entry_to_pte(entry);
				if (pte_swp_soft_dirty(*src_pte))
					pte = pte_swp_mksoft_dirty(pte);
				set_pte_at(src_mm, addr, src_pte, pte);
			}
		} else if (is_device_private_entry(entry)) {
			page = device_private_entry_to_page(entry);

			/*
			 * Update rss count even for unaddressable pages, as
			 * they should treated just like normal pages in this
			 * respect.
			 *
			 * We will likely want to have some new rss counters
			 * for unaddressable pages, at some point. But for now
			 * keep things as they are.
			 */
			get_page(page);
			rss[mm_counter(page)]++;
			page_dup_rmap(page, false);

			/*
			 * We do not preserve soft-dirty information, because so
			 * far, checkpoint/restore is the only feature that
			 * requires that. And checkpoint/restore does not work
			 * when a device driver is involved (you cannot easily
			 * save and restore device driver state).
			 */
			if (is_write_device_private_entry(entry) &&
			    is_cow_mapping(vm_flags)) {
				make_device_private_entry_read(&entry);
				pte = swp_entry_to_pte(entry);
				set_pte_at(src_mm, addr, src_pte, pte);
			}
		}
		goto out_set_pte;
	}

	/*
	 * If it's a COW mapping, write protect it both
	 * in the parent and the child
	 */
	if (is_cow_mapping(vm_flags) && pte_write(pte)) {
		ptep_set_wrprotect(src_mm, addr, src_pte);
		pte = pte_wrprotect(pte);
	}

	/*
	 * If it's a shared mapping, mark it clean in
	 * the child
	 */
	if (vm_flags & VM_SHARED)
		pte = pte_mkclean(pte);
	pte = pte_mkold(pte);

	page = vm_normal_page(vma, addr, pte);
	if (page) {
		get_page(page);
		page_dup_rmap(page, false);
		rss[mm_counter(page)]++;
	} else if (pte_devmap(pte)) {
		page = pte_page(pte);
	}

out_set_pte:
	set_pte_at(dst_mm, addr, dst_pte, pte);
	return 0;
}

static int pmvee_copy_pte_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		   pmd_t *dst_pmd, pmd_t *src_pmd, struct vm_area_struct *vma,
		   unsigned long addr, unsigned long end)
{
	pte_t *orig_src_pte, *orig_dst_pte;
	pte_t *src_pte, *dst_pte;
	spinlock_t *src_ptl, *dst_ptl;
	int progress = 0;
	int rss[NR_MM_COUNTERS];
	swp_entry_t entry = (swp_entry_t){0};

again:
	init_rss_vec(rss);

	dst_pte = pte_offset_map(dst_pmd, addr);
	src_pte = pte_offset_map(src_pmd, addr);
	src_ptl = pte_lockptr(src_mm, src_pmd);
	dst_ptl = pte_lockptr(dst_mm, dst_pmd);
	spin_lock_nested(src_ptl, SINGLE_DEPTH_NESTING);
	spin_lock_nested(dst_ptl, SINGLE_DEPTH_NESTING);
	orig_src_pte = src_pte;
	orig_dst_pte = dst_pte;
	arch_enter_lazy_mmu_mode();

	do {
		/*
		 * We are holding two locks at this point - either of them
		 * could generate latencies in another task on another CPU.
		 */
		if (progress >= 32) {
			progress = 0;
			if (need_resched() ||
			    spin_needbreak(src_ptl) || spin_needbreak(dst_ptl))
				break;
		}
		if (pte_none(*src_pte)) {
			progress++;
			continue;
		}

		#if PMVEE_SKIP_LEVEL >= PMVEE_KERNEL_MERGE_PMD_SHORTER_SKIP
		if (pte_pfn(*src_pte) == pte_pfn(*dst_pte)) {
			debugk(" > skipping copy\n");
			progress++;
			continue;
		}
		else
		{
			debugk(" > copy: %llx - %llx\n", pte_pfn(*dst_pte), pte_pfn(*src_pte));
		}
		#endif

		entry.val = pmvee_copy_one_pte(dst_mm, src_mm, dst_pte, src_pte, vma, addr, rss);
		debugk(" > after copy: %llx - %llx\n", pte_pfn(*dst_pte), pte_pfn(*src_pte));
		if (entry.val)
			break;
		progress += 8;
	} while (dst_pte++, src_pte++, addr += PAGE_SIZE, addr != end);

	arch_leave_lazy_mmu_mode();
	spin_unlock(src_ptl);
	pte_unmap(orig_src_pte);
	add_mm_rss_vec(dst_mm, rss);
	pte_unmap_unlock(orig_dst_pte, dst_ptl);
	cond_resched();

	if (entry.val) {
		printk("> weird\n");
		if (add_swap_count_continuation(entry, GFP_KERNEL) < 0)
			return -ENOMEM;
		progress = 0;
	}
	if (addr != end)
		goto again;
	return 0;
}

static inline int pmvee_copy_pmd_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		pud_t *dst_pud, pud_t *src_pud, struct vm_area_struct *vma,
		unsigned long addr, unsigned long end)
{
	pmd_t *src_pmd, *dst_pmd;
	unsigned long next;

	dst_pmd = pmd_offset(dst_pud, addr);
	if (!dst_pmd)
		return -ENOMEM;
	src_pmd = pmd_offset(src_pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (is_swap_pmd(*src_pmd) || pmd_trans_huge(*src_pmd)
			|| pmd_devmap(*src_pmd)) {
            printk("Not supporting this right now.\n");
            continue;
			// int err;
			// VM_BUG_ON_VMA(next-addr != HPAGE_PMD_SIZE, vma);
			// err = copy_huge_pmd(dst_mm, src_mm,
			// 		    dst_pmd, src_pmd, addr, vma);
			// if (err == -ENOMEM)
			// 	return -ENOMEM;
			// if (!err)
			// 	continue;
			/* fall through */
		}
		if (pmd_none_or_clear_bad(src_pmd))
			continue;
		if (pmvee_copy_pte_range(dst_mm, src_mm, dst_pmd, src_pmd,
						vma, addr, next))
			return -ENOMEM;
	} while (dst_pmd++, src_pmd++, addr = next, addr != end);
	return 0;
}

static inline int pmvee_copy_pud_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		p4d_t *dst_p4d, p4d_t *src_p4d, struct vm_area_struct *vma,
		unsigned long addr, unsigned long end)
{
	pud_t *src_pud, *dst_pud;
	unsigned long next;

	dst_pud = pud_offset(dst_p4d, addr);
	if (!dst_pud)
		return -ENOMEM;
	src_pud = pud_offset(src_p4d, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_trans_huge(*src_pud) || pud_devmap(*src_pud)) {
            printk("No supporting this right now.\n");
            continue;
			// int err;
// 
			// VM_BUG_ON_VMA(next-addr != HPAGE_PUD_SIZE, vma);
			// err = copy_huge_pud(dst_mm, src_mm,
			// 		    dst_pud, src_pud, addr, vma);
			// if (err == -ENOMEM)
			// 	return -ENOMEM;
			// if (!err)
			// 	continue;
			/* fall through */
		}
		if (pud_none_or_clear_bad(src_pud))
			continue;
		if (pmvee_copy_pmd_range(dst_mm, src_mm, dst_pud, src_pud,
						vma, addr, next))
			return -ENOMEM;
	} while (dst_pud++, src_pud++, addr = next, addr != end);
	return 0;
}

static inline int pmvee_copy_p4d_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		pgd_t *dst_pgd, pgd_t *src_pgd, struct vm_area_struct *vma,
		unsigned long addr, unsigned long end)
{
	p4d_t *src_p4d, *dst_p4d;
	unsigned long next;

	dst_p4d = p4d_offset(dst_pgd, addr);
	if (!dst_p4d)
		return -ENOMEM;
	src_p4d = p4d_offset(src_pgd, addr);
	do {
		next = p4d_addr_end(addr, end);
		if (p4d_none_or_clear_bad(src_p4d))
			continue;
		if (pmvee_copy_pud_range(dst_mm, src_mm, dst_p4d, src_p4d,
						vma, addr, next))
			return -ENOMEM;
	} while (dst_p4d++, src_p4d++, addr = next, addr != end);
	return 0;
}

int pmvee_copy_page_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		struct vm_area_struct *vma)
{
	pgd_t *src_pgd, *dst_pgd;
	unsigned long next;
	unsigned long addr = vma->vm_start;
	unsigned long end = vma->vm_end;
	struct mmu_notifier_range range;
	bool is_cow;
	int ret;

	/*
	 * Don't copy ptes where a page fault will fill them correctly.
	 * Fork becomes much lighter when there are big shared or private
	 * readonly mappings. The tradeoff is that copy_page_range is more
	 * efficient than faulting.
	 */
	if (!(vma->vm_flags & (VM_HUGETLB | VM_PFNMAP | VM_MIXEDMAP)) &&
			!vma->anon_vma)
		return 0;

	if (is_vm_hugetlb_page(vma))
    {
        printk("No supporting this right now.\n");
        return -ENOMEM;
		// return copy_hugetlb_page_range(dst_mm, src_mm, vma);
    }

	if (unlikely(vma->vm_flags & VM_PFNMAP)) {
		/*
		 * We do not free on error cases below as remove_vma
		 * gets called on error from higher level routine
		 */
		ret = track_pfn_copy(vma);
		if (ret)
			return ret;
	}

	/*
	 * We need to invalidate the secondary MMU mappings only when
	 * there could be a permission downgrade on the ptes of the
	 * parent mm. And a permission downgrade will only happen if
	 * is_cow_mapping() returns true.
	 */
	is_cow = is_cow_mapping(vma->vm_flags);

	if (is_cow) {
		mmu_notifier_range_init(&range, MMU_NOTIFY_PROTECTION_PAGE,
					0, vma, src_mm, addr, end);
		mmu_notifier_invalidate_range_start(&range);
	}

	ret = 0;
	dst_pgd = pgd_offset(dst_mm, addr);
	src_pgd = pgd_offset(src_mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(src_pgd))
			continue;
		if (unlikely(pmvee_copy_p4d_range(dst_mm, src_mm, dst_pgd, src_pgd,
					    vma, addr, next))) {
			ret = -ENOMEM;
			break;
		}
	} while (dst_pgd++, src_pgd++, addr = next, addr != end);

	if (is_cow)
		mmu_notifier_invalidate_range_end(&range);
	return ret;
}


static unsigned long pmvee_zap_one_pte(struct mmu_gather *tlb,
		struct mm_struct *dst_mm, struct vm_area_struct *dst_vma, pte_t *dst_pte,
		unsigned long *addr, int *rss, struct zap_details *details)
{
	swp_entry_t entry;

	if (pte_present(*dst_pte)) {
		unsigned long ret = 0;
		struct page *page;
		pte_t dst_ptent;

		page = vm_normal_page(dst_vma, (*addr), *dst_pte);
		if (unlikely(details) && page) {
			/*
				* unmap_shared_mapping_pages() wants to
				* invalidate cache without truncating:
				* unmap shared but keep private pages.
				*/
			if (details->check_mapping &&
				details->check_mapping != page_rmapping(page))
			{
				printk(" > I should never be seen.\n");
				return 0;
			}
		}
		dst_ptent = ptep_get_and_clear_full(dst_mm, (*addr), dst_pte,
						tlb->fullmm);
		tlb_remove_tlb_entry(tlb, dst_pte, (*addr));
		if (unlikely(!page))
		{
			debugk("not page\n");
			return 0;
		}

		if (!PageAnon(page)) {
			if (pte_dirty(dst_ptent)) {
				ret = 1;
				set_page_dirty(page);
			}
			if (pte_young(dst_ptent) &&
				likely(!(dst_vma->vm_flags & VM_SEQ_READ)))
				mark_page_accessed(page);
		}
		rss[mm_counter(page)]--;
		page_remove_rmap(page, false);
		if (unlikely(page_mapcount(page) < 0))
			printk(" > bad pte?\n");
		if (unlikely(__tlb_remove_page(tlb, page))) {
			ret = 1;
			(*addr) += PAGE_SIZE;
			debugk("added to addr\n");
			return 1;
		}
		return ret;
	}

	entry = pte_to_swp_entry(*dst_pte);
	if (non_swap_entry(entry) && is_device_private_entry(entry)) {
		struct page *page = device_private_entry_to_page(entry);

		if (unlikely(details && details->check_mapping)) {
			/*
				* unmap_shared_mapping_pages() wants to
				* invalidate cache without truncating:
				* unmap shared but keep private pages.
				*/
			if (details->check_mapping !=
				page_rmapping(page))
				return 0;
		}

		pte_clear_not_present_full(dst_mm, (*addr), dst_pte, tlb->fullmm);
		rss[mm_counter(page)]--;
		page_remove_rmap(page, false);
		put_page(page);
		return 0;
	}

	if (!non_swap_entry(entry)) {
		/* Genuine swap entry, hence a private anon page */
		if (!should_zap_cows(details))
			return 0;
		rss[MM_SWAPENTS]--;
	} else if (is_migration_entry(entry)) {
		struct page *page;

		page = migration_entry_to_page(entry);
		if (details && details->check_mapping &&
			details->check_mapping != page_rmapping(page))
			return 0;
		rss[mm_counter(page)]--;
	}
	if (unlikely(!free_swap_and_cache(entry)))
		printk(" > bad pte?\n");
	pte_clear_not_present_full(dst_mm, (*addr), dst_pte, tlb->fullmm);
	return 0;
}

static unsigned long pmvee_zap_pte_range(struct mmu_gather *tlb,
				struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma, pmd_t *dst_pmd, pmd_t *src_pmd,
				unsigned long addr, unsigned long end,
				struct zap_details *details)
{
	struct mm_struct *dst_mm = tlb->mm;
	struct mm_struct *src_mm = src_vma->vm_mm;
	int force_flush = 0;
	int rss[NR_MM_COUNTERS];
	spinlock_t *dst_ptl, *src_ptl;
	pte_t *dst_start_pte, *src_start_pte;
	pte_t *dst_pte, *src_pte;

	tlb_change_page_size(tlb, PAGE_SIZE);
again:
	init_rss_vec(rss);
	dst_start_pte = pte_offset_map_lock(dst_mm, dst_pmd, addr, &dst_ptl);
	src_start_pte = pte_offset_map_lock(src_mm, src_pmd, addr, &src_ptl);
	dst_pte = dst_start_pte;
	src_pte = src_start_pte;
	flush_tlb_batched_pending(dst_mm);
	arch_enter_lazy_mmu_mode();
	do {
		if (pte_none(*dst_pte))
			continue;

		#if PMVEE_SKIP_LEVEL == PMVEE_KERNEL_SHORTEST_SKIP || PMVEE_SKIP_LEVEL == PMVEE_KERNEL_MERGE_PMD_SHORTER_SKIP
		if (pte_pfn(*dst_pte) == pte_pfn(*src_pte))
		{
			debugk(" > skipping zap\n");
			continue;
		}
		else
		{
			debugk(" > zap: %llx - %llx\n", pte_pfn(*dst_pte), pte_pfn(*src_pte));
		}
		#endif

		if (need_resched())
			break;

		force_flush = pmvee_zap_one_pte(tlb, dst_mm, dst_vma, dst_pte, &addr, rss, details);
		#if PMVEE_SKIP_LEVEL >= PMVEE_KERNEL_MERGE_PTE_SKIP
		pmvee_copy_one_pte(dst_mm, src_mm, dst_pte, src_pte, src_vma, addr, rss);
		#endif

		if (force_flush)
			break;
	} while (dst_pte++, src_pte++, addr += PAGE_SIZE, addr != end);

	add_mm_rss_vec(dst_mm, rss);
	arch_leave_lazy_mmu_mode();

	/* Do the actual TLB flush before dropping ptl */
	if (force_flush)
		tlb_flush_mmu_tlbonly(tlb);
	pte_unmap_unlock(dst_start_pte, dst_ptl);
	pte_unmap_unlock(src_start_pte, src_ptl);

	/*
	 * If we forced a TLB flush (either due to running out of
	 * batch buffers or because we needed to flush dirty TLB
	 * entries before releasing the ptl), free the batched
	 * memory too. Restart if we didn't do everything.
	 */
	if (force_flush) {
		force_flush = 0;
		tlb_flush_mmu(tlb);
	}

	if (addr != end) {
		cond_resched();
		goto again;
	}

	return addr;
}

static inline unsigned long pmvee_zap_pmd_range(struct mmu_gather *tlb,
				struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma, pud_t *dst_pud, pud_t *src_pud,
				unsigned long addr, unsigned long end,
				struct zap_details *details)
{
	pmd_t *dst_pmd, *src_pmd;
	unsigned long next;

	dst_pmd = pmd_offset(dst_pud, addr);
	src_pmd = pmd_offset(src_pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (is_swap_pmd(*dst_pmd) || pmd_trans_huge(*dst_pmd) || pmd_devmap(*dst_pmd)) {
            printk(" > not supporting this right now.\n");
            continue;
			// if (next - addr != HPAGE_PMD_SIZE)
			// 	__split_huge_pmd(vma, pmd, addr, false, NULL);
			// else if (zap_huge_pmd(tlb, vma, pmd, addr))
			// 	goto next;
			// /* fall through */
		} else if (details && details->single_page &&
			   PageTransCompound(details->single_page) &&
			   next - addr == HPAGE_PMD_SIZE && pmd_none(*dst_pmd)) {
            printk(" > should never be hit.\n");
            continue;
			// spinlock_t *ptl = pmd_lock(tlb->mm, pmd);
			// /*
			//  * Take and drop THP pmd lock so that we cannot return
			//  * prematurely, while zap_huge_pmd() has cleared *pmd,
			//  * but not yet decremented compound_mapcount().
			//  */
			// spin_unlock(ptl);
		}

		/*
		 * Here there can be other concurrent MADV_DONTNEED or
		 * trans huge page faults running, and if the pmd is
		 * none or trans huge it can change under us. This is
		 * because MADV_DONTNEED holds the mmap_sem in read
		 * mode.
		 */
		if (pmd_none_or_trans_huge_or_clear_bad(dst_pmd))
			goto next;
		next = pmvee_zap_pte_range(tlb, dst_vma, src_vma, dst_pmd, src_pmd, addr, next, details);
		#if PMVEE_SKIP_LEVEL >= PMVEE_KERNEL_MERGE_PMD_SKIP && PMVEE_SKIP_LEVEL <= PMVEE_KERNEL_MERGE_PMD_SHORTER_SKIP
		pmvee_copy_pte_range(dst_vma->vm_mm, src_vma->vm_mm, dst_pmd, src_pmd, src_vma, addr, next);
		#endif
next:
		cond_resched();
	} while (dst_pmd++, src_pmd++, addr = next, addr != end);

	return addr;
}

static inline unsigned long pmvee_zap_pud_range(struct mmu_gather *tlb,
				struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma, p4d_t *dst_p4d, p4d_t *src_p4d,
				unsigned long addr, unsigned long end,
				struct zap_details *details)
{
	pud_t *dst_pud, *src_pud;
	unsigned long next;

	dst_pud = pud_offset(dst_p4d, addr);
	src_pud = pud_offset(src_p4d, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_trans_huge(*dst_pud) || pud_devmap(*dst_pud)) {
            printk(" > not supporting this right now.\n");
            continue;
			// if (next - addr != HPAGE_PUD_SIZE) {
			// 	VM_BUG_ON_VMA(!rwsem_is_locked(&tlb->mm->mmap_sem), vma);
			// 	split_huge_pud(vma, pud, addr);
			// } else if (zap_huge_pud(tlb, vma, pud, addr))
			// 	goto next;
			// /* fall through */
		}
		if (pud_none_or_clear_bad(dst_pud))
			continue;
		next = pmvee_zap_pmd_range(tlb, dst_vma, src_vma, dst_pud, src_pud, addr, next, details);
// next:
		cond_resched();
	} while (dst_pud++, src_pud++, addr = next, addr != end);

	return addr;
}

static inline unsigned long pmvee_zap_p4d_range(struct mmu_gather *tlb,
				struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma, pgd_t *dst_pgd, pgd_t *src_pgd,
				unsigned long addr, unsigned long end,
				struct zap_details *details)
{
	p4d_t *dst_p4d, *src_p4d;
	unsigned long next;

	dst_p4d = p4d_offset(dst_pgd, addr);
	src_p4d = p4d_offset(src_pgd, addr);
	do {
		next = p4d_addr_end(addr, end);
		if (p4d_none_or_clear_bad(dst_p4d))
			continue;
		next = pmvee_zap_pud_range(tlb, dst_vma, src_vma, dst_p4d, src_p4d, addr, next, details);
	} while (dst_p4d++, src_p4d++, addr = next, addr != end);

	return addr;
}

void pmvee_unmap_page_range(struct mmu_gather *tlb,
			     struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma,
			     unsigned long addr, unsigned long end,
			     struct zap_details *details)
{
	pgd_t *dst_pgd, *src_pgd;
	unsigned long next;

	BUG_ON(addr >= end);
	tlb_start_vma(tlb, vma);
	dst_pgd = pgd_offset(dst_vma->vm_mm, addr);
	src_pgd = pgd_offset(src_vma->vm_mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(dst_pgd))
			continue;
		next = pmvee_zap_p4d_range(tlb, dst_vma, src_vma, dst_pgd, src_pgd, addr, next, details);
	} while (dst_pgd++, src_pgd++, addr = next, addr != end);
	tlb_end_vma(tlb, vma);
}


static void pmvee_unmap_single_vma(struct mmu_gather *tlb,
		struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma, unsigned long start_addr,
		unsigned long end_addr,
		struct zap_details *details)
{
	unsigned long start = max(dst_vma->vm_start, start_addr);
	unsigned long end;

	if (start >= dst_vma->vm_end)
		return;
	end = min(dst_vma->vm_end, end_addr);
	if (end <= dst_vma->vm_start)
		return;

	if (dst_vma->vm_file)
		uprobe_munmap(dst_vma, start, end);

	if (unlikely(dst_vma->vm_flags & VM_PFNMAP))
		untrack_pfn(dst_vma, 0, 0);

	if (start != end) {
		if (unlikely(is_vm_hugetlb_page(dst_vma))) {
            printk("Not supported right now.\n");
			/*
			 * It is undesirable to test vma->vm_file as it
			 * should be non-null for valid hugetlb area.
			 * However, vm_file will be NULL in the error
			 * cleanup path of mmap_region. When
			 * hugetlbfs ->mmap method fails,
			 * mmap_region() nullifies vma->vm_file
			 * before calling this function to clean up.
			 * Since no pte has actually been setup, it is
			 * safe to do nothing in this case.
			 */
			// if (vma->vm_file) {
			// 	i_mmap_lock_write(vma->vm_file->f_mapping);
			// 	__unmap_hugepage_range_final(tlb, vma, start, end, NULL);
			// 	i_mmap_unlock_write(vma->vm_file->f_mapping);
			// }
		} else
			pmvee_unmap_page_range(tlb, dst_vma, src_vma, start, end, details);
	}
}

/**
 * zap_page_range - remove user pages in a given range
 * @vma: vm_area_struct holding the applicable pages
 * @start: starting address of pages to zap
 * @size: number of bytes to zap
 *
 * Caller must protect the VMA list
 */
void pmvee_zap_page_range(struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma, unsigned long start,
		unsigned long size)
{
	struct mmu_notifier_range range;
	struct mmu_gather tlb;

	lru_add_drain();
	mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, dst_vma, dst_vma->vm_mm,
				start, start + size);
	tlb_gather_mmu(&tlb, dst_vma->vm_mm, start, range.end);
	update_hiwater_rss(dst_vma->vm_mm);
	mmu_notifier_invalidate_range_start(&range);
	for ( ; dst_vma && dst_vma->vm_start < range.end; dst_vma = dst_vma->vm_next)
		pmvee_unmap_single_vma(&tlb, dst_vma, src_vma, start, range.end, NULL);
	mmu_notifier_invalidate_range_end(&range);
	tlb_finish_mmu(&tlb, start, range.end);
}

/*
 * Executable code area - executable, not writable, not stack
 */
static inline bool is_exec_mapping(vm_flags_t flags)
{
	return (flags & (VM_EXEC | VM_WRITE | VM_STACK)) == VM_EXEC;
}

/*
 * Stack area - atomatically grows in one direction
 *
 * VM_GROWSUP / VM_GROWSDOWN VMAs are always private anonymous:
 * do_mmap() forbids all other combinations.
 */
static inline bool is_stack_mapping(vm_flags_t flags)
{
	return (flags & VM_STACK) == VM_STACK;
}

/*
 * Data area - private, writable, not stack
 */
static inline bool is_data_mapping(vm_flags_t flags)
{
	return (flags & (VM_WRITE | VM_SHARED | VM_STACK)) == VM_WRITE;
}


static int find_vma_links(struct mm_struct *mm, unsigned long addr,
		unsigned long end, struct vm_area_struct **pprev,
		struct rb_node ***rb_link, struct rb_node **rb_parent)
{
	struct rb_node **__rb_link, *__rb_parent, *rb_prev;

	__rb_link = &mm->mm_rb.rb_node;
	rb_prev = __rb_parent = NULL;

	while (*__rb_link) {
		struct vm_area_struct *vma_tmp;

		__rb_parent = *__rb_link;
		vma_tmp = rb_entry(__rb_parent, struct vm_area_struct, vm_rb);

		if (vma_tmp->vm_end > addr) {
			/* Fail if an existing vma overlaps the area */
			if (vma_tmp->vm_start < end)
				return -ENOMEM;
			__rb_link = &__rb_parent->rb_left;
		} else {
			rb_prev = __rb_parent;
			__rb_link = &__rb_parent->rb_right;
		}
	}

	*pprev = NULL;
	if (rb_prev)
		*pprev = rb_entry(rb_prev, struct vm_area_struct, vm_rb);
	*rb_link = __rb_link;
	*rb_parent = __rb_parent;
	return 0;
}


static long actual_pmvee_switch(
        pid_t source,
        pid_t destination,
        unsigned long from,
        unsigned long size_one,
        unsigned long size_two,
        unsigned long flags)
{
    unsigned long ret = 0;
    unsigned long to, remove, i;
    struct task_struct *source_task, *destination_task;
    struct mm_struct *source_mm, *destination_mm;
    struct vm_area_struct *source_mapping, *tmp, *prev;
    struct rb_node **rb_link, *rb_parent;
    struct file *file;
    LIST_HEAD(uf);

    debugk("switching - %d >>> %d (0x%lx)\n", source, destination, from);


    // checks >
    // early exit if we are the leader.
    if (current->pid == source)
    {
        struct pid* destination_pid;

        current->pmvee_ignored_current = 0;
        if (!destination || destination == source)
            return 0;
        source_task = current;

        if (!(destination_pid = find_get_pid(destination)))
        {
            printk(KERN_INFO "Trying to switch with non-existing destination %d\n", destination);
            return -EINVAL;
        }
        if (!(destination_task = pid_task(destination_pid, PIDTYPE_PID)))
        {
            printk(KERN_INFO "Trying to switch with non-existing destination %d\n", destination);
            return -EINVAL;
        }    
    }
    else if (current->pid == destination)
    {
        struct pid* source_pid;

        if (!source || source == destination)
            return -422;

        destination_task = current;

        if (!(source_pid = find_get_pid(source)))
        {
            printk(KERN_INFO "Trying to switch with non-existing source %d\n", source);
            return -EINVAL;
        }
        if (!(source_task = pid_task(source_pid, PIDTYPE_PID)))
        {
            printk(KERN_INFO "Trying to switch with non-existing source %d\n", source);
            return -EINVAL;
        }    
    }
    else
    {
        return -420;
    }
    // checks <


    destination_mm = destination_task->mm;
    source_mm = source_task->mm;

    uprobe_start_dup_mmap();
    uprobe_dup_mmap(source_mm, destination_mm);
    if (down_write_killable(&source_mm->mmap_sem))
        return -EINTR;
    down_write_nested(&destination_mm->mmap_sem, SINGLE_DEPTH_NESTING);
	flush_cache_dup_mm(source_mm);


    source_mapping = source_mm->mmap;
    prev = destination_mm->mmap;
    while (source_mapping && source_mapping->vm_start < from)
    {
        debugk(" > skipping [ %lx ; %lx )\n", source_mapping->vm_start, source_mapping->vm_end);
        source_mapping = source_mapping->vm_next;
    }
    if (source_mapping->vm_start >= from + size_one + size_two)
	{
		ret = 0;
        goto cleanup;
	}
	if (!source_mapping)
	{
        printk(KERN_INFO "No mappings found in source %d\n", source);
		ret = -EINVAL;
        goto cleanup;
	}
    while (prev->vm_next && prev->vm_next->vm_start < from)
    {
        prev = prev->vm_next;
    }
	if (!prev)
	{
        printk(KERN_INFO "No mappings found in current\n");
		ret = -EINVAL;
        goto cleanup;
	}


    if (source_mapping && prev && prev->vm_next && prev->vm_next->vm_start < source_mapping->vm_start)
    {
        debugk(" > pre loop munmap(%llx, %llx)\n", from, source_mapping->vm_start - from);
        if ((ret = __do_munmap(destination_mm, from, source_mapping->vm_start - from, &uf, false)))
        {
            printk(" > got return code %ld while performing unmapping\n", ret);
            ret = -ENOMEM;
            goto cleanup;
        }
    }

	// printk("[%d] start\n", current->pid);
    // putting it in a separate function is annoying, hence this loop to run this twice.
    to = from + size_one;
    remove = ~(VM_EXEC | VM_MAYEXEC);
    debugk(" > [ %lx ; %lx )\n", (unsigned long)from, (unsigned long)(from + size_one + size_two));
    for (i = 0; i < 2; i++)
    {
        while (source_mapping && source_mapping->vm_end <= to)
        {
            debugk(" > doing [ %lx ; %lx )\n", source_mapping->vm_start, source_mapping->vm_end);
            // printk("[%d] doing [ %lx ; %lx )\n", current->pid, source_mapping->vm_start, source_mapping->vm_end);
            if (!(flags & PMVEE_FLAGS_DUP_EXEC) && (source_mapping->vm_flags & VM_EXEC))
                goto __pmvee_switch_next_mapping;

            if(source_mapping->vm_flags & VM_SHARED)
            {
                printk("Currently not supporting shared mappings in mp.");
                ret = -EFAULT;
                goto cleanup;
            }

			#if PMVEE_SKIP_LEVEL >= PMVEE_KERNEL_NO_UNMAP
            if (!prev || !prev->vm_next ||
                    prev->vm_next->vm_start != source_mapping->vm_start ||
                    prev->vm_next->vm_end != source_mapping->vm_end)
			#endif
            {
                unsigned long next_start;

                tmp = vm_area_dup(source_mapping);
                if (!tmp)
                {
                    ret = -ENOMEM;
                    goto cleanup;
                }
                tmp->vm_mm = destination_mm;
                if (anon_vma_fork(tmp, source_mapping))
                {
                    ret = -ENOMEM;
                    goto cleanup;
                }

                file = tmp->vm_file;
                if (file)
                {
                    struct inode *inode = file_inode(file);
                    struct address_space *mapping = file->f_mapping;

                    vma_get_file(tmp);
                    if (tmp->vm_flags & VM_DENYWRITE)
                        atomic_dec(&inode->i_writecount);
                    i_mmap_lock_write(mapping);
                    if (tmp->vm_flags & VM_SHARED)
                        atomic_inc(&mapping->i_mmap_writable);
                    flush_dcache_mmap_lock(mapping);
                    /* insert tmp into the share list, just after source_mapping */
                    vma_interval_tree_insert_after(tmp, source_mapping,
                            &mapping->i_mmap);
                    flush_dcache_mmap_unlock(mapping);
                    i_mmap_unlock_write(mapping);
                }

                next_start = (source_mapping->vm_next && source_mapping->vm_next->vm_start < to) ?
                        source_mapping->vm_next->vm_start : to;
                debugk(" > munmap(%llx, %llx)\n", tmp->vm_start, next_start - tmp->vm_start);
                if ((ret = __do_munmap(destination_mm, tmp->vm_start, next_start - tmp->vm_start, &uf, false)))
                {
                    printk(" > got return code %ld while performing unmapping\n", ret);
                    goto cleanup;
                }

                // link it in >
                find_vma_links(destination_mm, tmp->vm_start, tmp->vm_end, &prev, &rb_link, &rb_parent);
                tmp->vm_prev = prev;
                if (!prev)
                {
                    tmp->vm_next = destination_mm->mmap;
                    destination_mm->mmap->vm_prev = tmp;
                    destination_mm->mmap = tmp;
                }
                else
                {
                    tmp->vm_next = prev->vm_next;
                    prev->vm_next = tmp;
                    tmp->vm_next->vm_prev = tmp;
                }

                __vma_link_rb(destination_mm, tmp, rb_link, rb_parent);
                destination_mm->map_count++;

                if (copy_page_range(destination_mm, source_mm, source_mapping))
                {
                    printk(" > couldn't copy pages\n");
                    ret = -ENOMEM;
                    goto cleanup;
                }
                // link it in <
				if (tmp->vm_ops && tmp->vm_ops->open)
					tmp->vm_ops->open(tmp);
            }
			#if PMVEE_SKIP_LEVEL >= PMVEE_KERNEL_NO_UNMAP
            else
			{
                tmp = prev->vm_next;
				#if PMVEE_SKIP_LEVEL >= PMVEE_KERNEL_SKIP
                pmvee_zap_page_range(tmp, source_mapping, tmp->vm_start, tmp->vm_end - tmp->vm_start);
				  #if PMVEE_SKIP_LEVEL <= PMVEE_KERNEL_SKIP
                if (pmvee_copy_page_range(destination_mm, source_mm, source_mapping))
                {
                    printk(" > couldn't copy pages\n");
                    ret = -ENOMEM;
                    goto cleanup;
                }
				  #endif
				#else
                zap_page_range(tmp, tmp->vm_start, tmp->vm_end - tmp->vm_start);
                if (copy_page_range(destination_mm, source_mm, source_mapping))
                {
                    printk(" > couldn't copy pages\n");
                    ret = -ENOMEM;
                    goto cleanup;
                }
				#endif
            }
			#endif

            // remove unwanted permissions >
            if (tmp->vm_flags & ~remove)
            {
                tmp->vm_flags = source_mapping->vm_flags & remove;
                vma_set_page_prot(tmp);
                change_protection(tmp, tmp->vm_start, tmp->vm_end, tmp->vm_page_prot, false, 0);
            }
            // remove unwanted permissions <
            
            __pmvee_switch_next_mapping:
            prev = tmp;
            source_mapping = source_mapping->vm_next;
        }
        to = to + size_two;
        // remove = ~(VM_EXEC | VM_MAYEXEC | VM_WRITE | VM_MAYWRITE);
    }
	// printk("[%d] done\n", current->pid);
    debugk(" > done [ %lx ; %lx )\n", source_mapping->vm_start, source_mapping->vm_end);
    if (prev && prev->vm_next && prev->vm_next->vm_start < to)
    {
        unsigned long unmap_start = prev->vm_end;
        while (prev->vm_next && prev->vm_next->vm_start < to)
            prev = prev->vm_next;
        debugk("unmapping %lx -> %lx (%lx)\n", unmap_start, prev->vm_end, prev->vm_start);
        if ((ret = __do_munmap(destination_mm, unmap_start, (prev->vm_end > to ? to : prev->vm_end) - unmap_start, &uf, false)))
        {
            printk(" > got return code %ld while performing unmapping\n", ret);
            goto cleanup;
        }
    }

	debugk(" > switch done\n\n");


        
    cleanup:
    up_write(&destination_mm->mmap_sem);
    flush_tlb_mm(destination_mm);
    flush_tlb_mm(source_mm);
    up_write(&source_mm->mmap_sem);
    uprobe_end_dup_mmap();

    return 0;
}


static long actual_pmvee_check (
        pid_t source,
        pid_t destination,
        unsigned long from,
        unsigned long size_one,
        unsigned long size_two,
        unsigned long flags)
{
    unsigned long region_end;
    struct task_struct *source_task;
    struct task_struct *destination_task;
	struct vm_area_struct *mpnt, *source_mpnt;
	struct mm_struct *destination_mm, *source_mm;
	LIST_HEAD(uf);

    debugk("checking <%d> - %d to %d\n", current->pid, source, destination);
	// printk("[%d] from check\n", current->pid);
	// actual_pmvee_switch(source, destination, from, size_one, size_two, flags);

    if (current->pid == source)
    {
        struct pid* destination_pid;

        current->pmvee_ignored_current = 1;
        if (!destination || destination == source)
            return 0;
        source_task = current;

        if (!(destination_pid = find_get_pid(destination)))
        {
            printk(KERN_INFO "Trying to switch with non-existing destination %d\n", destination);
            return -EINVAL;
        }
        if (!(destination_task = pid_task(destination_pid, PIDTYPE_PID)))
        {
            printk(KERN_INFO "Trying to switch with non-existing destination %d\n", destination);
            return -EINVAL;
        }    
    }
    return 0;



	
    /*else*/ if (current->pid == destination)
    {
        struct pid* source_pid;

        if (!source || source == destination)
            return 0;

        destination_task = current;

        if (!(source_pid = find_get_pid(source)))
        {
            printk(KERN_INFO "Trying to switch with non-existing source %d\n", source);
            return -EINVAL;
        }
        if (!(source_task = pid_task(source_pid, PIDTYPE_PID)))
        {
            printk(KERN_INFO "Trying to switch with non-existing source %d\n", source);
            return -EINVAL;
        }
    }
    else
    {
        return -EINVAL;
    }


	destination_mm = destination_task->mm;
	source_mm = source_task->mm;
    if (!source_mm)
    {
        printk(KERN_INFO "Seems like our source has no memory to share | source pid: %d\n", source);
        return EINVAL;
    }
    // early exit <

    region_end = from + size_one + size_two;


    // check mappings for changes >
	source_mpnt = source_mm->mmap;
	while (source_mpnt && source_mpnt->vm_start < from)
		source_mpnt = source_mpnt->vm_next;
	if (!source_mpnt)
	{
        printk(KERN_INFO "No mappings found in source %d\n", source);
		return EINVAL;
	}
	mpnt = destination_mm->mmap;
	while (mpnt && mpnt->vm_start < from)
		mpnt = mpnt->vm_next;
	if (!mpnt)
	{
        printk(KERN_INFO "No mappings found in current\n");
		return EINVAL;
	}

	// assuming the two lists are in sync here. If they aren't... well, we're in a bit of trouble.
	while (source_mpnt && mpnt)
	{
		if (mpnt->vm_end > region_end)
			mpnt = NULL;
		if (source_mpnt->vm_end > region_end)
			source_mpnt = NULL;
		if (!mpnt || !source_mpnt)
			break;

        // check to make sure these mappings are actually the same range
        if (source_mpnt->vm_start != mpnt->vm_start)
        {
            printk("   > mismatching mappings: [ 0x%lx ; 0x%lx ) != [ 0x%lx ; 0x%lx )\n",
                    source_mpnt->vm_start, source_mpnt->vm_end, mpnt->vm_start, mpnt->vm_end);
            return -EFAULT;
        }
        if (source_mpnt->vm_end != mpnt->vm_end)
        {
            while(mpnt->vm_next && 
                    mpnt->vm_next->vm_end <= source_mpnt->vm_end &&
                    mpnt->vm_next->vm_start == mpnt->vm_end)
                mpnt = mpnt->vm_next;
            
            if (source_mpnt->vm_end != mpnt->vm_end)
            {
                printk("   > mismatching mappings: [ 0x%lx ; 0x%lx ) != [ 0x%lx ; 0x%lx )\n",
                        source_mpnt->vm_start, source_mpnt->vm_end, mpnt->vm_start, mpnt->vm_end);
                return -EFAULT;
            }
            // else
            //     zap_page_range(mpnt, mpnt->vm_start, mpnt->vm_end - mpnt->vm_start);
        }
		
		// next entries
		mpnt = mpnt->vm_next;
		source_mpnt = source_mpnt->vm_next;
	}
    // check mappings for changes <
    return 0;
}


unsigned char actual_pmvee_should_skip(struct pt_regs *regs, unsigned long entering)
{
    unsigned int syscall;
    
    syscall = (unsigned int)-1;
    if (entering)
    {
        syscall = regs->orig_ax;
        current->pmvee_last_call = regs->orig_ax;
    }
    else
    {
        syscall = current->pmvee_last_call;
        current->pmvee_last_call = (unsigned int)-1;
    }

    if (syscall == __NR_pmvee_switch || syscall == __NR_pmvee_check)
    {
        return 0;
    }
    if (syscall == __NR_mmap || syscall == __NR_munmap)
    {
        return 0;
    }
    // if (syscall == __NR_write)
    // {
    //     return 0;
    // }
    return current->pmvee_ignored_current;
}


static int __init pmvee_init(void) {
    pmvee_switch_stub = &actual_pmvee_switch;
    pmvee_check_stub  = &actual_pmvee_check;

    pmvee_should_skip_stub = &actual_pmvee_should_skip;
    current->pmvee_last_call = (unsigned int)-1;

    printk(KERN_INFO "PMVEE support module loaded\n");
    return 0;
}

static void __exit pmvee_exit(void) {
    pmvee_switch_stub = NULL;
    pmvee_check_stub  = NULL;

    pmvee_should_skip_stub = NULL;

    printk(KERN_INFO "PMVEE support module unloaded\n");
}


module_init(pmvee_init);
module_exit(pmvee_exit);
