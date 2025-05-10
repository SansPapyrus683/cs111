#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

// ok so like this is most certainly a bad place semantically to put this
// but like adding new files messes up the makefile and i really don't wanna...
extern struct lock fs_lock;

#endif /* userprog/syscall.h */
