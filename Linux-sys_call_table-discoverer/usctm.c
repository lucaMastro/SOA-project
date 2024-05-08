/*
*
* This is free software; you can redistribute it and/or modify it under the
* terms of the GNU General Public License as published by the Free Software
* Foundation; either version 3 of the License, or (at your option) any later
* version.
*
* This module is distributed in the hope that it will be useful, but WITHOUT ANY
* WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
* A PARTICULAR PURPOSE. See the GNU General Public License for more details.
*
* @file usctm.c
* @brief This is the main source for the Linux Kernel Module which implements
* 	 the runtime discovery of the syscall table position and of free entries (those
* 	 pointing to sys_ni_syscall)
*
* @author Francesco Quaglia
*
* @date November 22, 2020
*/

#define EXPORT_SYMTAB
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <linux/syscalls.h>
#include "./include/vtpmo.h"
/* #include "../reference-monitor-kprobes/lib/reference_monitor.h" */
#include "./lib/syscall_helper.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Francesco Quaglia <framcesco.quaglia@uniroma2.it>");
MODULE_DESCRIPTION("USCTM");



#define MODNAME "USCTM"


extern int sys_vtpmo(unsigned long vaddr);

/* extern int compute_hash(char *input_string, int input_size, char *output_buffer); */
/* extern reference_monitor_t reference_monitor; */

#define ADDRESS_MASK 0xfffffffffffff000//to migrate

#define START 			0xffffffff00000000ULL		// use this as starting address --> this is a biased search since does not start from 0xffff000000000000
#define MAX_ADDR		0xfffffffffff00000ULL
#define FIRST_NI_SYSCALL	134
#define SECOND_NI_SYSCALL	174
#define THIRD_NI_SYSCALL	182
#define FOURTH_NI_SYSCALL	183
#define FIFTH_NI_SYSCALL	214
#define SIXTH_NI_SYSCALL	215
#define SEVENTH_NI_SYSCALL	236

#define ENTRIES_TO_EXPLORE 256


unsigned long *hacked_ni_syscall=NULL;
unsigned long **hacked_syscall_tbl=NULL;

unsigned long sys_call_table_address = 0x0;
module_param(sys_call_table_address, ulong, 0660);

unsigned long sys_ni_syscall_address = 0x0;
module_param(sys_ni_syscall_address, ulong, 0660);



/*----------------------------------*/

sys_call_helper_t sys_call_helper;
EXPORT_SYMBOL(sys_call_helper);

/*----------------------------------*/



int good_area(unsigned long * addr){

	int i;

	for(i=1;i<FIRST_NI_SYSCALL;i++){
		if(addr[i] == addr[FIRST_NI_SYSCALL]) goto bad_area;
	}

	return 1;

bad_area:

	return 0;

}



/* This routine checks if the page contains the begin of the syscall_table.  */
int validate_page(unsigned long *addr){
	int i = 0;
	unsigned long page 	= (unsigned long) addr;
	unsigned long new_page 	= (unsigned long) addr;
	for(; i < PAGE_SIZE; i+=sizeof(void*)){
		new_page = page+i+SEVENTH_NI_SYSCALL*sizeof(void*);

		// If the table occupies 2 pages check if the second one is materialized in a frame
		if(
			( (page+PAGE_SIZE) == (new_page & ADDRESS_MASK) )
			&& sys_vtpmo(new_page) == NO_MAP
		)
			break;
		// go for patter matching
		addr = (unsigned long*) (page+i);
		if(
			   ( (addr[FIRST_NI_SYSCALL] & 0x3  ) == 0 )
			   && (addr[FIRST_NI_SYSCALL] != 0x0 )			// not points to 0x0
			   && (addr[FIRST_NI_SYSCALL] > 0xffffffff00000000 )	// not points to a locatio lower than 0xffffffff00000000
	//&& ( (addr[FIRST_NI_SYSCALL] & START) == START )
			&&   ( addr[FIRST_NI_SYSCALL] == addr[SECOND_NI_SYSCALL] )
			&&   ( addr[FIRST_NI_SYSCALL] == addr[THIRD_NI_SYSCALL]	 )
			&&   ( addr[FIRST_NI_SYSCALL] == addr[FOURTH_NI_SYSCALL] )
			&&   ( addr[FIRST_NI_SYSCALL] == addr[FIFTH_NI_SYSCALL] )
			&&   ( addr[FIRST_NI_SYSCALL] == addr[SIXTH_NI_SYSCALL] )
			&&   ( addr[FIRST_NI_SYSCALL] == addr[SEVENTH_NI_SYSCALL] )
			&&   (good_area(addr))
		){
			hacked_ni_syscall = (void*)(addr[FIRST_NI_SYSCALL]);				// save ni_syscall
			sys_ni_syscall_address = (unsigned long)hacked_ni_syscall;
			hacked_syscall_tbl = (void*)(addr);				// save syscall_table address
			sys_call_table_address = (unsigned long) hacked_syscall_tbl;
			return 1;
		}
	}
	return 0;
}

/* This routines looks for the syscall table.  */
void syscall_table_finder(void){
	unsigned long k; // current page
	unsigned long candidate; // current page

	for(k=START; k < MAX_ADDR; k+=4096){
		candidate = k;
		if(
			(sys_vtpmo(candidate) != NO_MAP)
		){
			// check if candidate maintains the syscall_table
			if(validate_page( (unsigned long *)(candidate)) ){
				printk("%s: syscall table found at %px\n",MODNAME,(void*)(hacked_syscall_tbl));
				printk("%s: sys_ni_syscall found at %px\n",MODNAME,(void*)(hacked_ni_syscall));
				break;
			}
		}
	}

}


int free_entries[MAX_FREE];
module_param_array(free_entries,int,NULL,0660);//default array size already known - here we expose what entries are free


/* ----------SYSCALL DEFINITION UTILITIES -----------------*/

unsigned long cr0;

static inline void
write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    /* __asm__ __volatile__( */
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}

static inline void
protect_memory(void)
{
    write_cr0_forced(cr0);
}

static inline void
unprotect_memory(void)
{
    write_cr0_forced(cr0 & ~X86_CR0_WP);
}


/* ----------SYSCALL INSTALL -----------------*/

int install_syscall(unsigned long *new_sys_call_addr){
    int index;
    int sct_index;
	cr0 = read_cr0();
    // which index of free list has to be used?
    index = sys_call_helper.last_entry_used + 1;
    if (index >= sys_call_helper.free_entries_count){
        printk("%s: cannot install another syscall\n",MODNAME);
        return -1;
    }
    // what is the syscall index to be used?
    sct_index = sys_call_helper.free_entries[index];

    // installation
    unprotect_memory();
    sys_call_helper.hacked_syscall_tbl[sct_index] = new_sys_call_addr;
    protect_memory();

    // updating
    sys_call_helper.last_entry_used++;
	/* printk("%s: a sys_call has been installed as a trial on the sys_call_table at displacement %d\n",MODNAME,sct_index); */
    return sct_index;
}

void uninstall_syscalls(void){
    int i;
	cr0 = read_cr0();
    unprotect_memory();
    for (i = 0; i <= sys_call_helper.last_entry_used; i++)
        hacked_syscall_tbl[sys_call_helper.free_entries[i]] = (unsigned long*)hacked_ni_syscall;
    protect_memory();
    /* reset the helper */
    sys_call_helper.last_entry_used = -1;

}

/* ----------------------------------------------*/


int init_module(void) {

	int i,j;

        printk("%s: initializing\n",MODNAME);

	syscall_table_finder();

	if(!hacked_syscall_tbl){
		printk("%s: failed to find the sys_call_table\n",MODNAME);
		return -1;
	}

	j=0;

    /*----------------------------------*/
    sys_call_helper.hacked_syscall_tbl = hacked_syscall_tbl;
    sys_call_helper.free_entries_count = 0;
    sys_call_helper.last_entry_used = -1;
    sys_call_helper.install_syscall = install_syscall;
    sys_call_helper.uninstall_syscalls = uninstall_syscalls;
    /*----------------------------------*/

	for(i=0;i<ENTRIES_TO_EXPLORE;i++)
		if(hacked_syscall_tbl[i] == hacked_ni_syscall){
			printk("%s: found sys_ni_syscall entry at syscall_table[%d] and address: %px\n",MODNAME,i,&hacked_syscall_tbl[i]);
            /*----------------------------------*/
            sys_call_helper.free_entries[j] = i;
            sys_call_helper.free_entries_count++;
            /*----------------------------------*/
			free_entries[j++] = i;
			if(j>=MAX_FREE) break;
		}

    /* install_syscall(sys_add_path); */


        printk("%s: module correctly mounted\n",MODNAME);

        /* char hash[32]; */
        /* printk("%s: invoke compute hash",MODNAME); */
        /* compute_hash("prova", 5, hash); */
        /* char hex_hash[64]; */
        /* bin2hex(hex_hash, hash, 32); */
        /* printk("%s: hex_hash: %s",MODNAME, hex_hash); */
        /* bin2hex(hex_hash, reference_monitor.hashed_pass, 32); */
        /* printk("%s: hex_hash: %s",MODNAME, hex_hash); */
        /* printk("%s: HASHED PWD COMPUTED\n",MODNAME); */

        return 0;

}

void cleanup_module(void) {

	/* cr0 = read_cr0(); */
    /* unprotect_memory(); */
    /* hacked_syscall_tbl[FIRST_NI_SYSCALL] = (unsigned long*)hacked_ni_syscall; */
    /* protect_memory(); */
    /* uninstall_syscalls(); */
    printk("%s: shutting down\n",MODNAME);

}





