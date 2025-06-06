#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/kernel/list.h"
#include "lib/string.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

static void syscall_handler(struct intr_frame *);

void fine_buff(const char *ptr, size_t length);
void fine_str(const char *str);

// SCREW OFF!!! DIE!! DIE IN A PLANE CRASH!!!!!
bool create(const char *name, unsigned init_size);
bool remove(const char *name);
int open(const char *name);
struct ofd *get_file(int fd);
int filesize(int fd);
void close(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned pos);
unsigned tell(int fd);

// they said filesys operations weren't already synced, gg
struct lock fs_lock;

void syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&fs_lock);
}

static uint32_t get_arg(uint32_t *args, int ind) {
    fine_buff((const char *) (args + ind), 4);
    return args[ind];
}

static void syscall_handler(struct intr_frame *f) {
    uint32_t *args = ((uint32_t *) f->esp);

    int ret_val;
    switch (get_arg(args, 0)) {
    case SYS_EXIT: {
        const int exit_code = get_arg(args, 1);
        f->eax = exit_code;
        thread_exit(exit_code);
    } break;

    case SYS_INCREMENT:
        ret_val = get_arg(args, 1) + 1;
        break;

    case SYS_WRITE: {
        const int fd = get_arg(args, 1);
        const char *msg = (const char *) get_arg(args, 2);
        const unsigned size = get_arg(args, 3);
        if (fd == 1) {
            fine_str(msg);
            putbuf(msg, size);
            ret_val = size;
        } else {
            ret_val = write(fd, msg, size);
        }
        break;
    }
    case SYS_READ: {
        const int fd = get_arg(args, 1);
        char *buff = (char *) get_arg(args, 2);
        const unsigned size = get_arg(args, 3);
        if (fd == 0) {
            fine_buff(buff, size);
            for (size_t i = 0; i < size; i++) {
                buff[i] = input_getc();
            }
            ret_val = size;
        } else {
            ret_val = read(fd, buff, size);
        }
    } break;

    case SYS_CREATE:
        ret_val = create((char *) get_arg(args, 1), get_arg(args, 2));
        break;
    case SYS_REMOVE:
        ret_val = remove((char *) get_arg(args, 1));
        break;
    case SYS_OPEN:
        ret_val = open((char *) get_arg(args, 1));
        break;
    case SYS_FILESIZE:
        ret_val = filesize(get_arg(args, 1));
        break;
    case SYS_CLOSE:
        close(get_arg(args, 1));
        break;
    case SYS_SEEK:
        seek(get_arg(args, 1), get_arg(args, 2));
        break;
    case SYS_TELL:
        ret_val = tell(get_arg(args, 1));
        break;

    case SYS_EXEC: {
        const char *cmdline = (const char *) get_arg(args, 1);
        fine_str(cmdline);
        ret_val = process_execute(cmdline);
    } break;
    case SYS_WAIT:
        ret_val = process_wait(get_arg(args, 1));
        break;

    // why did they even has us impl this lol it's like one line
    case SYS_HALT:
        shutdown_power_off();
        break;
    }

    f->eax = ret_val;
}

void fine_buff(const char *pointer, size_t length) {
    uint32_t *pd = thread_current()->pagedir;
    for (size_t i = 0; i < length; i++) {
        const char *check = pointer + i;
        if (!is_user_vaddr(check) || pagedir_get_page(pd, check) == NULL) {
            thread_exit(-1);
        }
    }
}

void fine_str(const char *str) {
    fine_buff(str, 1);
    for (size_t i = 0; str[i] != '\0'; i++) {
        fine_buff(str + i + 1, 1);
    }
}

bool create(const char *name, unsigned init_size) {
    fine_str(name);
    lock_acquire(&fs_lock);
    bool res = filesys_create(name, init_size);
    lock_release(&fs_lock);
    return res;
}

bool remove(const char *name) {
    fine_str(name);
    lock_acquire(&fs_lock);
    bool res = filesys_remove(name);
    lock_release(&fs_lock);
    return res;
}

int open(const char *name) {
    fine_str(name);
    lock_acquire(&fs_lock);
    struct file *fptr = filesys_open(name);
    lock_release(&fs_lock);
    if (fptr == NULL) {
        return -1;
    }

    int largest_fd = 1;
    struct thread *t = thread_current();
    for (struct list_elem *at = list_begin(&t->ofds); at != list_end(&t->ofds);
         at = list_next(at)) {
        struct ofd *ofd = list_entry(at, struct ofd, elem);
        largest_fd = largest_fd >= ofd->fd ? largest_fd : ofd->fd;
    }

    struct ofd *new_ofd = malloc(sizeof(struct ofd));
    new_ofd->fd = largest_fd + 1;
    new_ofd->file = fptr;

    list_push_back(&t->ofds, &new_ofd->elem);
    return new_ofd->fd;
}

struct ofd *get_file(int fd) {
    struct thread *t = thread_current();
    for (struct list_elem *at = list_begin(&t->ofds); at != list_end(&t->ofds);
         at = list_next(at)) {
        struct ofd *ofd = list_entry(at, struct ofd, elem);
        if (ofd->fd == fd) {
            return ofd;
        }
    }
    return NULL;
}

int filesize(int fd) {
    struct ofd *f = get_file(fd);
    if (f == NULL) {
        return -1;
    }
    lock_acquire(&fs_lock);
    int ret = file_length(f->file);
    lock_release(&fs_lock);
    return ret;
}

void close(int fd) {
    struct ofd *f = get_file(fd);
    if (f == NULL) {
        return;
    }
    lock_acquire(&fs_lock);
    file_close(f->file);
    lock_release(&fs_lock);

    list_remove(&f->elem);
    free(f);
}

int read(int fd, void *buffer, unsigned size) {
    fine_buff(buffer, size);
    struct ofd *f = get_file(fd);
    if (f == NULL) {
        return -1;
    }

    lock_acquire(&fs_lock);
    int ret = file_read(f->file, buffer, size);
    lock_release(&fs_lock);
    return ret;
}

int write(int fd, const void *buffer, unsigned size) {
    fine_buff(buffer, size);
    struct ofd *f = get_file(fd);
    if (f == NULL) {
        return -1;
    }

    lock_acquire(&fs_lock);
    int ret = file_write(f->file, buffer, size);
    lock_release(&fs_lock);
    return ret;
}

void seek(int fd, unsigned pos) {
    struct ofd *f = get_file(fd);
    if (f == NULL) {
        return;
    }
    lock_acquire(&fs_lock);
    file_seek(f->file, pos);
    lock_release(&fs_lock);
}

unsigned tell(int fd) {
    struct ofd *f = get_file(fd);
    if (f == NULL) {
        return 0;
    }
    lock_acquire(&fs_lock);
    unsigned ret = file_tell(f->file);
    lock_release(&fs_lock);
    return ret;
}
