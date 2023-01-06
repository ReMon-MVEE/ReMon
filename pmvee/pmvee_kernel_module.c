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

#include <asm/tlb.h>


MODULE_LICENSE("GPL"); // todo
MODULE_AUTHOR("Jonas Vinck");
MODULE_DESCRIPTION("PMVEE project kernel module");
MODULE_VERSION("0.1");


/* Needed exported symbols =============================================================================================
 * vma_set_page_prot
 * change_protection
 * Needed exported symbols ========================================================================================== */


// #define DEBUG_k
#ifdef DEBUG_k
#define debugk(...) printk(__VA_ARGS__);
#else
#define debugk(...) ;
#endif


extern long (*pmvee_switch_stub) (pid_t leader, unsigned long from, unsigned long to, unsigned long flags);
extern long (*pmvee_check_stub)  (pid_t leader, unsigned long from, unsigned long to, unsigned long flags);


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


static long actual_pmvee_switch(pid_t leader, unsigned long from, unsigned long to, long flags)
{
    struct pid *leader_pid;
    struct task_struct *leader_task;
    struct mm_struct *follower_mm, *leader_mm;
    struct vm_area_struct *leader_mapping, *tmp, *prev;
    struct rb_node **rb_link, *rb_parent;
    LIST_HEAD(uf);

    debugk(" [%d] > <%d> [ %lx ; %lx )\n", current->pid, leader, from, to);


    // checks >
    // Start address cannot be greater then end.
    if (from > to)
        return EINVAL;

    // early exit if we are the leader.
    if (current->pid == leader)
        return 0;
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

    debugk(" [switch] > <%d> [ %lx ; %lx )\n", leader, from, to);

    // This is just here for now, we might want to do this when collisions occur while copying instead. Either not
    // copying or unmapping them then.
	while (find_vma_links(follower_mm, from, to, &prev, &rb_link, &rb_parent))
    {
 		if (__do_munmap(follower_mm, from, to - from, &uf, false))
 			return -ENOMEM;
    }

    uprobe_start_dup_mmap();
    uprobe_dup_mmap(leader_mm, follower_mm);
    if (down_write_killable(&leader_mm->mmap_sem))
        return -EINTR;
    down_write_nested(&follower_mm->mmap_sem, SINGLE_DEPTH_NESTING);

    leader_mapping = leader_mm->mmap;
    prev = follower_mm->mmap;
    while (leader_mapping && leader_mapping->vm_start < from)
    {
        leader_mapping = leader_mapping->vm_next;
    }
	if (!leader_mapping)
	{
        printk(KERN_INFO "No mappings found in leader %d\n", leader);
		return EINVAL;
	}
    while (prev->vm_next && prev->vm_next->vm_start < from)
    {
        prev = prev->vm_next;
    }
	if (!prev)
	{
        printk(KERN_INFO "No mappings found in current\n");
		return EINVAL;
	}

    if (prev->vm_start > from)
    {
        rb_link = &prev->vm_rb.rb_left;
        rb_parent = &prev->vm_rb;
        prev = NULL;
    }
    else
    {
        rb_link = &prev->vm_rb.rb_right;
        rb_parent = &prev->vm_rb;
    }

    while (leader_mapping && leader_mapping->vm_end <= to)
    {
        debugk("   > duping   [ 0x%lx ; 0x%lx )\n", leader_mapping->vm_start, leader_mapping->vm_end);

        tmp = vm_area_dup(leader_mapping);
        if (!tmp)
            return -ENOMEM;
        tmp->vm_mm = follower_mm;
        if (anon_vma_fork(tmp, leader_mapping))
            return -ENOMEM;

        // remove unwanted file permissions >
        // tmp->vm_flags = leader_mapping->vm_flags & ~(VM_WRITE | VM_EXEC | VM_MAYWRITE | VM_MAYEXEC);
        // vma_set_page_prot(tmp);
        // change_protection(tmp, tmp->vm_start, tmp->vm_end, tmp->vm_page_prot, false, 0);
        // remove unwanted file permissions <
        
        // link it in >
        if (!prev)
        {
            tmp->vm_next = follower_mm->mmap;
            tmp->vm_prev = NULL;
            follower_mm->mmap->vm_prev = tmp;
            follower_mm->mmap = tmp;
        }
        else
        {
            tmp->vm_next = prev->vm_next;
            tmp->vm_prev = prev;
            prev->vm_next = tmp;
            tmp->vm_next->vm_prev = tmp;
        }

        __vma_link_rb(follower_mm, tmp, rb_link, rb_parent);
        rb_link = &tmp->vm_rb.rb_right;
        rb_parent = &tmp->vm_rb;

        follower_mm->map_count++;
        // link it in <

        // copy pages >
        if (copy_page_range(follower_mm, leader_mm, leader_mapping))
        {
            printk(" > couldn't copy pages\n");
            return -ENOMEM;
        }
		if (tmp->vm_ops && tmp->vm_ops->open)
			tmp->vm_ops->open(tmp);
        // copy pages <

        prev = tmp;
        leader_mapping = leader_mapping->vm_next;
    }

    #ifdef DEBUG_K
    leader_mapping = leader_mm->mmap;
    while (leader_mapping)
    {
        debugk("   > leader:   [ 0x%lx ; 0x%lx )\n", leader_mapping->vm_start, leader_mapping->vm_end);
        leader_mapping = leader_mapping->vm_next;
    }
    tmp = follower_mm->mmap;
    while (tmp)
    {
        debugk("   > follower: [ 0x%lx ; 0x%lx )\n", tmp->vm_start, tmp->vm_end);
        tmp = tmp->vm_next;
    }
    #endif
        
    up_write(&follower_mm->mmap_sem);
    flush_tlb_mm(follower_mm);
    flush_tlb_mm(leader_mm);
    up_write(&leader_mm->mmap_sem);
    uprobe_end_dup_mmap();

    debugk(" > done.\n");
    return 0;
}


static long actual_pmvee_check (pid_t leader, unsigned long from, unsigned long to, unsigned long flags)
{
    struct pid *leader_pid;
    struct task_struct *leader_task;
	struct vm_area_struct *mpnt, *leader_mpnt;
	struct mm_struct *follower_mm, *leader_mm;
	LIST_HEAD(uf);

	debugk(" [%d] > <%d> [ %lx ; %lx )\n", current->pid, leader, from, to);
	

    // checks >
    if (from > to)
        return EINVAL;
    // checks <

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


	debugk(" [check]  > <%d> [ %lx ; %lx )\n", leader, from, to);


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
		if (mpnt->vm_end > to)
			mpnt = NULL;
		if (leader_mpnt->vm_end > to)
			leader_mpnt = NULL;
		if (!mpnt || !leader_mpnt)
			break;

		debugk("   > checking [ 0x%lx ; 0x%lx ) vs [ 0x%lx ; 0x%lx )\n", mpnt->vm_start, mpnt->vm_end, 
				leader_mpnt->vm_start, leader_mpnt->vm_end);

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

    return 0;
}


static int __init pmvee_init(void) {
    pmvee_switch_stub = &actual_pmvee_switch;
    pmvee_check_stub  = &actual_pmvee_check;

    printk(KERN_INFO "PMVEE support module loaded\n");
    return 0;
}

static void __exit pmvee_exit(void) {
    pmvee_switch_stub = NULL;
    pmvee_check_stub  = NULL;

    printk(KERN_INFO "PMVEE support module unloaded\n");
}


module_init(pmvee_init);
module_exit(pmvee_exit);