#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/sched/cputime.h>
#include <linux/kprobes.h>
#include <linux/hashtable.h>

#define WRITE_BUFFER_SIZE	(10240)
#define READ_BUFFER_SIZE	(1024)

/* Dynamic probe */
static struct kprobe kprb;

/* Global variables */
static struct proc_dir_entry *profiler;
static char proc_write_buffer[WRITE_BUFFER_SIZE];
static char proc_read_buffer[READ_BUFFER_SIZE];
static int data_ready = 0;
static int read_done = 0;
static int buffer_offset = 0;

/* Hashtable data */
DEFINE_HASHTABLE(htable, 14);
DEFINE_RWLOCK(htable_lock);

struct hash_obj {
    int pid;
    u64 schedule_count;
    u64 cputime;
    struct hlist_node node;
};

struct hash_obj *get_hash_bucket(int pid) {
    struct hash_obj *hobj;

    read_lock(&htable_lock);
    hash_for_each_possible(htable, hobj, node, pid) {
	if(hobj -> pid == pid) {
            read_unlock(&htable_lock);
	    return hobj;
	}
    }

    read_unlock(&htable_lock);
    return NULL;
}

static ssize_t profiler_read(struct file *file, char *buffer, size_t length, loff_t *offset) {
    struct hash_obj *hobj;
    int bytes = 0, iter;

    if(read_done) {
	read_done = 0;
	data_ready = 0;
	buffer_offset = 0;
        return 0;
    }
	
    if(data_ready == 0) {
        read_lock(&htable_lock);
	
	/* Iterate hastable to read data */
	hash_for_each(htable, iter, hobj, node) {
	    bytes += sprintf(proc_write_buffer + bytes, "PID: %d CPU Time (sec): %llu Context Switch Count: %llu\n", hobj -> pid, (hobj -> cputime)/1000000000, hobj -> schedule_count);
	}
    
        read_unlock(&htable_lock);
	data_ready = 1;
    }

    /* Mechanism to make sure the read process completes */
    if(bytes <= length) {
	copy_to_user(buffer, proc_write_buffer + buffer_offset, bytes);
        read_done = 1;
    } else {
	copy_to_user(buffer, proc_write_buffer + buffer_offset, length);
	buffer_offset += length;
	bytes -= length;
    }

    return bytes;
}

static ssize_t profiler_write(struct file *file, const char *buffer, size_t length, loff_t *offset) {
    int pid;
    struct hash_obj *hobj;

    /* Copy user data to kernel buffer */
    copy_from_user(proc_read_buffer, buffer, length);

    if(kstrtoint(proc_read_buffer, 10, &pid)) {
	printk("User data format not correct!\n");
        return length;
    }

    /* Check if node withi input PID already exists */
    hobj = get_hash_bucket(pid);

    if(hobj == NULL) {
	hobj = kmalloc(sizeof(struct hash_obj), GFP_KERNEL);
	hobj -> pid = pid;
	hobj -> schedule_count = 0;
        hash_add(htable, &hobj -> node, pid);
	printk("PID %d added to monitor for context switches.\n", pid);
    } else {
	printk("Already monitoring PID %d for context switches.\n", pid);
    }

    return length;
}

int pre_handle(struct kprobe *kp, struct pt_regs *regs) {
    return 0;
}

void post_handle(struct kprobe *kp, struct pt_regs *regs, unsigned long flags) {
    u64 utime, stime;
    struct task_struct *task = (struct task_struct *)(regs -> si);
    int pid = task -> pid;
    struct hash_obj *hobj = get_hash_bucket(pid);

    if(hobj != NULL) {
	/* Extract and update CPU time */
	task_cputime(task, &utime, &stime);
	hobj -> cputime = (utime + stime);

	/* Increment context switch counter */
	hobj -> schedule_count++;
    }
}

int fault_handle(struct kprobe *kp, struct pt_regs *regs, int trapnr) {

    return 0;
}

struct file_operations fops = {
    .read = profiler_read,
    .write = profiler_write,
};


int profiler_init(void) {
    /* Initialize hash table */
    hash_init(htable);

    /* Creating file in /proc */
    profiler = proc_create("profiler", 0666, NULL, &fops);

    if(profiler == NULL) {
	printk("Error creating proc file.\n");
        return -1;
    }

    /* Populate kprobe params */
    kprb.pre_handler = pre_handle;
    kprb.post_handler = post_handle;
    kprb.fault_handler = fault_handle;
    kprb.addr = (kprobe_opcode_t *) kallsyms_lookup_name("__switch_to");

    if(kprb.addr == NULL) {
	printk("Probe address not found!!\n");
        return -1;
    }
    
    /* Register kprobe */
    register_kprobe(&kprb);
    
    printk("/proc/profiler file created successfully!\n");

    return 0;
}

void profiler_exit(void) {
    /* Removing file from /proc */
    proc_remove(profiler);
    
    /* Unregister kprobe */
    unregister_kprobe(&kprb);
    printk("/proc/profiler file removed successfully!\n");
}



module_init(profiler_init);
module_exit(profiler_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sachin");
MODULE_DESCRIPTION("Profiler Module");
