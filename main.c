#include <scheme.h>
#include <linux/module.h>
#include <linux/security.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <asm/compat.h>
#include <linux/limits.h>
#include <mmu.h>

char argvs[ARG_MAX][PAGE_SIZE];
int argv_c = 0;

static int get_argv_from_bprm(struct linux_binprm *bprm) {
	int ret = 0;
	unsigned long offset, pos;
	char *kaddr;
	struct page *page;
	char *argv = NULL;
	int i = 0;
	int argc = 0;
	//int envc = 0;
	int count = 0;
	argv = vzalloc(PAGE_SIZE);
	if (!bprm || !argv) {
		goto out;
	}

	argc = bprm->argc;
	//envc = bprm->envc;
	pos = bprm->p;
	do {
		offset = pos & ~PAGE_MASK;
		page = get_arg_page(bprm, pos, 0);
		if (!page) {
			ret = 0;
			goto out;
		}
		kaddr = kmap_atomic(page);

		for (i = 0; offset < PAGE_SIZE && count < argc/* + envc*/  && i < PAGE_SIZE; offset++, pos++) {
			if (kaddr[offset] == '\0') {
				count++;
				pos++;
				//printk("page info is %s\n", argv);
				memcpy(argvs[argv_c++], argv, strlen(argv));
				memset(argv, 0, sizeof(argv));
				i = 0;
				continue;
			}
			argv[i] = kaddr[offset];
			i++;
		}
		
		kunmap_atomic(kaddr);
		put_arg_page(page);
	} while (offset == PAGE_SIZE);

	ret = 0;

out:
	return ret;
}

static int my_bprm_check_security(struct linux_binprm *bprm) {
	int ret = 0;
	int i;
	int len = 0;
	int insert_c = 0;
	if (!strcmp(bprm->filename, "/usr/bin/ls")) {
		printk("RUNING: %s\n", bprm->filename);
		ret = get_argv_from_bprm(bprm);
		for (i = 0; i < argv_c; i++) {
			//printk("%s\n", argvs[i]);
			len += strlen(argvs[i]);
		}
		len += argv_c;
		bprm->p += len;
		insert_c = 3;
		char *insert[3] = {"-a", "-l", "-F"};
		copy_strings_kernel(insert_c, insert, bprm);
		copy_strings_kernel(argv_c + 1, argvs, bprm);
	}
	return ret;
}

static struct security_operations ** security_ops_addr = NULL;
static struct security_operations * old_hooks = NULL;
static struct security_operations new_hooks = {0};

static inline void __hook(void) {
	memcpy(&new_hooks, old_hooks, sizeof(new_hooks));
	new_hooks.bprm_check_security = my_bprm_check_security;
	*security_ops_addr = &new_hooks;
}

static inline void __unhook(void) {
	if (old_hooks) {
		*security_ops_addr = old_hooks;
	}
}

static int __init xsec_init(void) {
	int retval = -EINVAL;
	int idx = 0;
	security_ops_addr = (struct security_operations **)kallsyms_lookup_name("security_ops");
	if (!security_ops_addr) {
		printk("no security hook heads\n");
		goto out;
	}
	printk("security ops addr is %p\n", security_ops_addr);
	old_hooks = *security_ops_addr;
	printk ("security old ops is %p\n", old_hooks);
	__hook();
	printk("new hooks ops is  %p\n", &new_hooks);
	printk("security new ops is %p\n", *security_ops_addr);
	retval = 0;
out:
	return retval;
}

static void __exit xsec_exit(void) {
	__unhook();
	return;
}

module_init(xsec_init);
module_exit(xsec_exit);


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("test for lsm");
MODULE_VERSION("0.1");
MODULE_ALIAS("lsmTest");
MODULE_AUTHOR("silver");
