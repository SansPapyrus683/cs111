#include "userprog/process.h"

#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/tss.h"

struct fight {
    tid_t parent;
    tid_t kid;
    int exit_code;
    int alive;
    struct semaphore status;
    struct lock alive_lock;
    struct list_elem elem;
};

struct start_proc_args {
    char *file_name;
    bool ok;
    struct semaphore start;
    struct semaphore end;
};

static bool init_alr = false;
static struct list fights; // parent-child relationships

static thread_func start_process NO_RETURN;
static bool load(char *file_name, void (**eip)(void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute(const char *file_name) {
    if (!init_alr) {  // ts so scuffed :heartbreak:
        init_alr = true;
        list_init(&fights);
    }

    /* Make a copy of FILE_NAME.
       Otherwise there's a race between the caller and load(). */
    char *fn_copy = palloc_get_page(0);
    if (fn_copy == NULL)
        return TID_ERROR;
    strlcpy(fn_copy, file_name, PGSIZE / 2);

    char *actual_name = NULL;
    int i;
    for (i = 0; file_name[i] != '\0'; i++) {
        if (file_name[i] == ' ') {
            actual_name = malloc(i + 1);
            strlcpy(actual_name, file_name, i + 1);
            break;
        }
    }
    if (actual_name == NULL) {
        actual_name = malloc(i + 1);
        strlcpy(actual_name, file_name, i + 1);
    }

    struct start_proc_args *args = malloc(sizeof(struct start_proc_args));
    args->file_name = fn_copy;
    sema_init(&args->start, 0);
    sema_init(&args->end, 0);

    /* Create a new thread to execute FILE_NAME. */
    tid_t tid = thread_create(actual_name, PRI_DEFAULT, start_process, args);
    if (tid == TID_ERROR) {
        palloc_free_page(fn_copy);
    }
    
    sema_down(&args->start);
    if (!args->ok) {
        return TID_ERROR;
    }

    tid_t parent = thread_current()->tid;
    if (parent != -1) {
        struct fight *f = malloc(sizeof(struct fight));
        f->parent = parent;
        f->kid = tid;
        f->alive = 2;
        lock_init(&f->alive_lock);
        sema_init(&f->status, 0);
        list_push_back(&fights, &f->elem);
    }
    sema_up(&args->end);

    return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void *args_) {
    struct start_proc_args *args = args_;
    char *file_name = args->file_name;
    struct intr_frame if_;

    /* Initialize interrupt frame and load executable. */
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;

    lock_acquire(&fs_lock);
    args->ok = load(file_name, &if_.eip, &if_.esp);
    lock_release(&fs_lock);

    palloc_free_page(file_name);
    sema_up(&args->start);
    /* If load failed, quit. */
    if (!args->ok) {
        free(args);
        thread_exit(-1);
    }
    sema_down(&args->end);
    free(args);

    /* Start the user process by simulating a return from an
       interrupt, implemented by intr_exit (in
       threads/intr-stubs.S).  Because intr_exit takes all of its
       arguments on the stack in the form of a `struct intr_frame',
       we just point the stack pointer (%esp) to our stack frame
       and jump to it. */
    asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
    NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(tid_t child_tid) {
    const tid_t par_tid = thread_current()->tid;
    struct fight *fight = NULL;
    for (struct list_elem *at = list_begin(&fights); at != list_end(&fights);
         at = list_next(at)) {
        struct fight *f = list_entry(at, struct fight, elem);
        if (f->kid == child_tid && f->parent == par_tid) {
            fight = f;
            break;
        }
    }
    if (fight == NULL) {
        return -1;
    }

    sema_down(&fight->status);
    list_remove(&fight->elem);
    int ret = fight->exit_code;
    free(fight);
    return ret;
}

/* Free the current process's resources. */
void process_exit(int exit_code) {
    struct thread *cur = thread_current();
    uint32_t *pd;

    /* Destroy the current process's page directory and switch back
       to the kernel-only page directory. */
    pd = cur->pagedir;
    if (pd != NULL) {
        /* Correct ordering here is crucial.  We must set
           cur->pagedir to NULL before switching page directories,
           so that a timer interrupt can't switch back to the
           process page directory.  We must activate the base page
           directory before destroying the process's page
           directory, or our active page directory will be one
           that's been freed (and cleared). */
        cur->pagedir = NULL;
        pagedir_activate(NULL);
        pagedir_destroy(pd);
    }

    lock_acquire(&fs_lock);
    file_close(cur->exe); // closing it allows writes again

    // they actually don't check for this but i should still prolly have it
    while (!list_empty(&cur->ofds)) {
        struct list_elem *e = list_pop_front(&cur->ofds);
        struct ofd *ofd = list_entry(e, struct ofd, elem);
        file_close(ofd->file);
        free(ofd);
    }
    lock_release(&fs_lock);

    tid_t curr_tid = cur->tid;
    for (struct list_elem *at = list_begin(&fights); at != list_end(&fights);) {
        struct fight *f = list_entry(at, struct fight, elem);
        if (f->parent == curr_tid || f->kid == curr_tid) {
            lock_acquire(&f->alive_lock);

            if (f->kid == curr_tid) {
                f->exit_code = exit_code;
                sema_up(&f->status);
            }

            if (--f->alive == 0) {
                at = list_remove(&f->elem);
                free(f);
            } else {
                lock_release(&f->alive_lock);
                at = list_next(at);
            }
        } else {
            at = list_next(at); // scuff, scuff, scuff
        }
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate(void) {
    struct thread *t = thread_current();

    /* Activate thread's page tables. */
    pagedir_activate(t->pagedir);

    /* Set thread's kernel stack for use in processing
       interrupts. */
    tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
    unsigned char e_ident[16];
    Elf32_Half e_type;
    Elf32_Half e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off e_phoff;
    Elf32_Off e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
    Elf32_Word p_type;
    Elf32_Off p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0 /* Ignore. */
#define PT_LOAD 1 /* Loadable segment. */
#define PT_DYNAMIC 2 /* Dynamic linking info. */
#define PT_INTERP 3 /* Name of dynamic loader. */
#define PT_NOTE 4 /* Auxiliary info. */
#define PT_SHLIB 5 /* Reserved. */
#define PT_PHDR 6 /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void **esp, const char *cmdline);
static bool validate_segment(const struct Elf32_Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(char *file_name, void (**eip)(void), void **esp) {
    struct thread *t = thread_current();
    struct Elf32_Ehdr ehdr;
    off_t file_ofs;
    bool success = false;
    int i;

    /* Allocate and activate page directory. */
    t->pagedir = pagedir_create();
    if (t->pagedir == NULL)
        goto done;
    process_activate();

    bool messed_up = false;
    for (int i = 0; file_name[i] != '\0'; i++) {
        if (file_name[i] == ' ') {
            file_name[i] = '\0';
            messed_up = true;
            break;
        }
    }
    struct file *exe = filesys_open(file_name);
    if (exe == NULL) {
        printf("load: %s: open failed\n", file_name);
        goto done;
    }
    if (messed_up) {
        int bad = 0;
        while (file_name[bad] != '\0') {
            bad++;
        }
        file_name[bad] = ' ';
    }

    /* Read and verify executable header. */
    if (file_read(exe, &ehdr, sizeof ehdr) != sizeof ehdr ||
        memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 ||
        ehdr.e_machine != 3 || ehdr.e_version != 1 ||
        ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
        printf("load: %s: error loading executable\n", file_name);
        goto done;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++) {
        struct Elf32_Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length(exe))
            goto done;
        file_seek(exe, file_ofs);

        if (file_read(exe, &phdr, sizeof phdr) != sizeof phdr)
            goto done;
        file_ofs += sizeof phdr;
        switch (phdr.p_type) {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
            /* Ignore this segment. */
            break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
            goto done;
        case PT_LOAD:
            if (validate_segment(&phdr, exe)) {
                bool writable = (phdr.p_flags & PF_W) != 0;
                uint32_t file_page = phdr.p_offset & ~PGMASK;
                uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                uint32_t page_offset = phdr.p_vaddr & PGMASK;
                uint32_t read_bytes, zero_bytes;
                if (phdr.p_filesz > 0) {
                    /* Normal segment.
                       Read initial part from disk and zero the rest. */
                    read_bytes = page_offset + phdr.p_filesz;
                    zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) -
                                  read_bytes);
                } else {
                    /* Entirely zero.
                       Don't read anything from disk. */
                    read_bytes = 0;
                    zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                }
                if (!load_segment(exe, file_page, (void *) mem_page, read_bytes,
                                  zero_bytes, writable))
                    goto done;
            } else
                goto done;
            break;
        }
    }

    /* Set up stack. */
    if (!setup_stack(esp, file_name))
        goto done;

    /* Start address. */
    *eip = (void (*)(void)) ehdr.e_entry;

    success = true;

done:
    /* We arrive here whether the load is successful or not. */
    if (success) {
        t->exe = exe;
        file_deny_write(exe);
    } else {
        file_close(exe);
    }
    return success;
}

/* load() helpers. */

static bool install_page(void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr *phdr, struct file *file) {
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
        return false;

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (Elf32_Off) file_length(file))
        return false;

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz)
        return false;

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0)
        return false;

    /* The virtual memory region must both start and end within the
       user address space range. */
    if (!is_user_vaddr((void *) phdr->p_vaddr))
        return false;
    if (!is_user_vaddr((void *) (phdr->p_vaddr + phdr->p_memsz)))
        return false;

    /* The region cannot "wrap around" across the kernel virtual
       address space. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
        return false;

    /* Disallow mapping page 0.
       Not only is it a bad idea to map page 0, but if we allowed
       it then user code that passed a null pointer to system calls
       could quite likely panic the kernel by way of null pointer
       assertions in memcpy(), etc. */
    if (phdr->p_vaddr < PGSIZE)
        return false;

    /* It's okay. */
    return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable) {
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    file_seek(file, ofs);
    while (read_bytes > 0 || zero_bytes > 0) {
        /* Calculate how to fill this page.
           We will read PAGE_READ_BYTES bytes from FILE
           and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* Get a page of memory. */
        uint8_t *kpage = palloc_get_page(PAL_USER);
        if (kpage == NULL)
            return false;

        /* Load this page. */
        if (file_read(file, kpage, page_read_bytes) != (int) page_read_bytes) {
            palloc_free_page(kpage);
            return false;
        }
        memset(kpage + page_read_bytes, 0, page_zero_bytes);

        /* Add the page to the process's address space. */
        if (!install_page(upage, kpage, writable)) {
            palloc_free_page(kpage);
            return false;
        }

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void **esp, const char *cmdline) {
    uint8_t *kpage;
    bool success = false;

    const int len = strlen(cmdline);

    kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage != NULL) {
        success = install_page(((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
        if (success)
            *esp = PHYS_BASE - 4 * (len + 1);
        else
            palloc_free_page(kpage);
    }

    strlcpy(*esp, cmdline, len + 1);

    char *tok_state = NULL;
    char *tok = strtok_r(*esp, " ", &tok_state);
    int argc = 0;
    while (tok != NULL) {
        *esp -= 0x4;
        *((char **) *esp) = tok;
        tok = strtok_r(NULL, " ", &tok_state);
        argc++;
    }
    *esp -= 0x4;
    *((char **) *esp) = NULL;

    for (int i = 0; i < (argc + 1) / 2; i++) {
        char *tmp = ((char **) *esp)[i];
        ((char **) *esp)[i] = ((char **) *esp)[argc - i];
        ((char **) *esp)[argc - i] = tmp;
    }
    int *arr_start = *esp;

    while (((uint32_t) *esp) % 16 != 8) {
        *esp -= 0x4;
    }

    *esp -= 0xc;
    ((int *) *esp)[1] = argc;
    ((int **) *esp)[2] = arr_start; // I HAVE NO IDEA WTH IS GOING ON

    return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void *upage, void *kpage, bool writable) {
    struct thread *t = thread_current();

    /* Verify that there's not already a page at that virtual
       address, then map our page there. */
    return (pagedir_get_page(t->pagedir, upage) == NULL &&
            pagedir_set_page(t->pagedir, upage, kpage, writable));
}
