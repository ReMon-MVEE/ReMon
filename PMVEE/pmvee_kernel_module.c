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


#define debugk(...) ; // printk(__VA_ARGS__);


extern long (*pmvee_switch_stub) (
    pid_t leader,
    unsigned long from,
    unsigned long size_one,
    unsigned long size_two,
    unsigned long flags);
extern long (*pmvee_check_stub)  (
    pid_t leader,
    unsigned long from,
    unsigned long size_one,
    unsigned long size_two,
    unsigned long flags);
extern unsigned char (*pmvee_should_skip_stub) (struct pt_regs *regs, unsigned long entering);

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
        pid_t leader,
        unsigned long from,
        unsigned long size_one,
        unsigned long size_two,
        unsigned long flags)
{
    unsigned long ret = 0;
    unsigned long to, remove, i;
    struct pid *leader_pid;
    struct task_struct *leader_task;
    struct mm_struct *follower_mm, *leader_mm;
    struct vm_area_struct *leader_mapping, *tmp, *prev;
    struct rb_node **rb_link, *rb_parent;
    struct file *file;
    LIST_HEAD(uf);


    // checks >
    // early exit if we are the leader.
    if (current->pid == leader)
    {
        current->pmvee_ignored_current = 0;
        return 0;
    }
    // checks <


    // Get relevant leader task struct >
    if (!(leader_pid = find_get_pid(leader)))
    {
        printk(KERN_INFO "Trying to switch to non-existing leader %d\n", leader);
        return EINVAL;
    }

    if (!(leader_task = pid_task(leader_pid, PIDTYPE_PID)))
    {
        printk(KERN_INFO "Trying to switch to non-existing leader %d\n", leader);
        return EINVAL;
    }    
    // Get relevant leader task struct <


    follower_mm = current->mm;
    leader_mm = leader_task->mm;

    uprobe_start_dup_mmap();
    uprobe_dup_mmap(leader_mm, follower_mm);
    if (down_write_killable(&leader_mm->mmap_sem))
        return -EINTR;
    down_write_nested(&follower_mm->mmap_sem, SINGLE_DEPTH_NESTING);
	flush_cache_dup_mm(leader_mm);


    leader_mapping = leader_mm->mmap;
    prev = follower_mm->mmap;
    while (leader_mapping && leader_mapping->vm_start < from)
    {
        leader_mapping = leader_mapping->vm_next;
    }
	if (!leader_mapping)
	{
        printk(KERN_INFO "No mappings found in leader %d\n", leader);
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

    #if 0
    printk("before:\n");
    struct vm_area_struct * temptemptemp = leader_mm->mmap;
    while (temptemptemp)
    {
        if (temptemptemp->vm_start >= from && temptemptemp->vm_end < from + size_one + size_two)
            printk("   > leader:   [ 0x%lx ; 0x%lx )\n", temptemptemp->vm_start, temptemptemp->vm_end);
        temptemptemp = temptemptemp->vm_next;
    }
    temptemptemp = follower_mm->mmap;
    while (temptemptemp)
    {
        if (temptemptemp->vm_start >= from && temptemptemp->vm_end < from + size_one + size_two)
            printk("   > follower: [ 0x%lx ; 0x%lx )\n", temptemptemp->vm_start, temptemptemp->vm_end);
        temptemptemp = temptemptemp->vm_next;
    }
    printk("done.\n");
    #endif

    if (leader_mapping && prev && prev->vm_next && prev->vm_next->vm_start < leader_mapping->vm_start)
    {
        if ((ret = __do_munmap(follower_mm, from, leader_mapping->vm_start - from, &uf, false)))
        {
            printk(" > got return code %ld while performing unmapping\n", ret);
            ret = -ENOMEM;
            goto cleanup;
        }
    }

    // putting it in a separate function is annoying, hence this loop to run this twice.
    to = from + size_one;
    remove = ~(VM_EXEC | VM_MAYEXEC);
    for (i = 0; i < 2; i++)
    {
        while (leader_mapping && leader_mapping->vm_end <= to)
        {
            if (!(flags & PMVEE_FLAGS_DUP_EXEC) && (leader_mapping->vm_flags & VM_EXEC))
                goto __pmvee_switch_next_mapping;

            if(leader_mapping->vm_flags & VM_SHARED)
            {
                printk("Currently not supporting shared mappings in mp.");
                ret = -EFAULT;
                goto cleanup;
            }

            if (!prev || !prev->vm_next ||
                    prev->vm_next->vm_start != leader_mapping->vm_start ||
                    prev->vm_next->vm_end != leader_mapping->vm_end)
            {
                unsigned long next_start;

                tmp = vm_area_dup(leader_mapping);
                if (!tmp)
                {
                    ret = -ENOMEM;
                    goto cleanup;
                }
                tmp->vm_mm = follower_mm;
                if (anon_vma_fork(tmp, leader_mapping))
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
                    /* insert tmp into the share list, just after leader_mapping */
                    vma_interval_tree_insert_after(tmp, leader_mapping,
                            &mapping->i_mmap);
                    flush_dcache_mmap_unlock(mapping);
                    i_mmap_unlock_write(mapping);
                }

                next_start = (leader_mapping->vm_next && leader_mapping->vm_next->vm_start < to) ?
                        leader_mapping->vm_next->vm_start : to;
                if ((ret = __do_munmap(follower_mm, tmp->vm_start, next_start - tmp->vm_start, &uf, false)))
                {
                    printk(" > got return code %ld while performing unmapping\n", ret);
                    goto cleanup;
                }

                // link it in >
                find_vma_links(follower_mm, tmp->vm_start, tmp->vm_end, &prev, &rb_link, &rb_parent);
                tmp->vm_prev = prev;
                if (!prev)
                {
                    tmp->vm_next = follower_mm->mmap;
                    follower_mm->mmap->vm_prev = tmp;
                    follower_mm->mmap = tmp;
                }
                else
                {
                    tmp->vm_next = prev->vm_next;
                    prev->vm_next = tmp;
                    tmp->vm_next->vm_prev = tmp;
                }

                __vma_link_rb(follower_mm, tmp, rb_link, rb_parent);
                follower_mm->map_count++;
                // link it in <
            }
            else
            {
                tmp = prev->vm_next;
                zap_page_range(tmp, tmp->vm_start, tmp->vm_end - tmp->vm_start);
            }

            if (tmp->vm_ops && tmp->vm_ops->open)
                tmp->vm_ops->open(tmp);
            // remove unwanted permissions >
            if (tmp->vm_flags & ~remove)
            {
                tmp->vm_flags = leader_mapping->vm_flags & remove;
                vma_set_page_prot(tmp);
                change_protection(tmp, tmp->vm_start, tmp->vm_end, tmp->vm_page_prot, false, 0);
            }
            // remove unwanted permissions <

            // copy pages >
            if (copy_page_range(follower_mm, leader_mm, leader_mapping))
            {
                printk(" > couldn't copy pages\n");
                ret = -ENOMEM;
                goto cleanup;
            }
            // copy pages <
            
            __pmvee_switch_next_mapping:
            prev = tmp;
            leader_mapping = leader_mapping->vm_next;
        }
        to = to + size_two;
        // remove = ~(VM_EXEC | VM_MAYEXEC | VM_WRITE | VM_MAYWRITE);
    }
    if (prev && prev->vm_next && prev->vm_next->vm_start < to)
    {
        if ((ret = __do_munmap(follower_mm, prev->vm_end, prev->vm_next->vm_end - prev->vm_end, &uf, false)))
        {
            printk(" > got return code %ld while performing unmapping\n", ret);
            goto cleanup;
        }
    }

    #if 0
    printk("after:\n");
    temptemptemp = leader_mm->mmap;
    while (temptemptemp)
    {
        // if (temptemptemp->vm_start >= from && temptemptemp->vm_end < from + size_one + size_two)
            printk("   > leader:   [ 0x%lx ; 0x%lx )\n", temptemptemp->vm_start, temptemptemp->vm_end);
        temptemptemp = temptemptemp->vm_next;
    }
    temptemptemp = follower_mm->mmap;
    while (temptemptemp)
    {
        // if (temptemptemp->vm_start >= from && temptemptemp->vm_end < from + size_one + size_two)
            printk("   > follower: [ 0x%lx ; 0x%lx )\n", temptemptemp->vm_start, temptemptemp->vm_end);
        temptemptemp = temptemptemp->vm_next;
    }
    #endif
        
    cleanup:
    up_write(&follower_mm->mmap_sem);
    flush_tlb_mm(follower_mm);
    flush_tlb_mm(leader_mm);
    up_write(&leader_mm->mmap_sem);
    uprobe_end_dup_mmap();

    debugk(" > pmvee switch done.\n");
    return from;
}


static long actual_pmvee_check (
        pid_t leader,
        unsigned long from,
        unsigned long size_one,
        unsigned long size_two,
        unsigned long flags)
{
    unsigned long region_end;
    struct pid *leader_pid;
    struct task_struct *leader_task;
	struct vm_area_struct *mpnt, *leader_mpnt;
	struct mm_struct *follower_mm, *leader_mm;
	LIST_HEAD(uf);

    // get relevant leader task struct >
    leader_pid = find_get_pid(leader);
    if (!leader_pid)
    {
        printk(KERN_INFO "Trying to check with non-existing leader %d\n", leader);
        return EINVAL;
    }

    leader_task = pid_task(leader_pid, PIDTYPE_PID);
    if (!leader_task)
    {
        printk(KERN_INFO "Trying to check with non-existing leader %d\n", leader);
        return EINVAL;
    }
    // get relevant leader task struct <

    // early exit >
    if (current->pid == leader)
	{
		// printk(" [switch] > in leader\n");
        current->pmvee_ignored_current = 1;
		return 0;
	}

	follower_mm = current->mm;
	leader_mm = leader_task->mm;
    if (!leader_mm)
    {
        printk(KERN_INFO "Seems like our leader has no memory to share | leader pid: %d\n", leader);
        return EINVAL;
    }
    // early exit <

    region_end = from + size_one + size_two;


    // check mappings for changes >
	leader_mpnt = leader_mm->mmap;
	while (leader_mpnt && leader_mpnt->vm_start < from)
		leader_mpnt = leader_mpnt->vm_next;
	if (!leader_mpnt)
	{
        printk(KERN_INFO "No mappings found in leader %d\n", leader);
		return EINVAL;
	}
	mpnt = follower_mm->mmap;
	while (mpnt && mpnt->vm_start < from)
		mpnt = mpnt->vm_next;
	if (!mpnt)
	{
        printk(KERN_INFO "No mappings found in current\n");
		return EINVAL;
	}

	// assuming the two lists are in sync here. If they aren't... well, we're in a bit of trouble.
	while (leader_mpnt && mpnt)
	{
		if (mpnt->vm_end > region_end)
			mpnt = NULL;
		if (leader_mpnt->vm_end > region_end)
			leader_mpnt = NULL;
		if (!mpnt || !leader_mpnt)
			break;

        // check to make sure these mappings are actually the same range
        if (leader_mpnt->vm_start != mpnt->vm_start || leader_mpnt->vm_end != mpnt->vm_end)
        {
            printk("   > mismatching mappings: [ 0x%lx ; 0x%lx ) != [ 0x%lx ; 0x%lx )\n",
                    leader_mpnt->vm_start, leader_mpnt->vm_end, mpnt->vm_start, mpnt->vm_end);
            return -EFAULT;
        }
		
		// next entries
		mpnt = mpnt->vm_next;
		leader_mpnt = leader_mpnt->vm_next;
	}
    // check mappings for changes <
    debugk(" > pmvee check done.\n")
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
