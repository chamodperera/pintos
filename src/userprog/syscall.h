#include "threads/synch.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H


void syscall_init (void);

/* 
 * File system lock
 * Used to synchronize file system operations
 */
struct lock file_system_lock;    
   
#endif /* userprog/syscall.h */
