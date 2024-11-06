#include "userprog/syscall.h"
#include "lib/user/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler(struct intr_frame *f);
static bool is_valid_user_pointer(const void *ptr);
static bool is_valid_user_buffer(const void *buffer, unsigned size);
static bool is_valid_user_string(const char *str);
static void *get_stack_argument(void *esp, int offset);

void syscall_init(void) {
    lock_init(&file_system_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame *f) {
    if (!is_valid_user_pointer(f->esp)) {
        exit(-1);
        return;
    }

    int syscall_num = *(int *)f->esp;

    switch (syscall_num) {
        case SYS_HALT:
            halt();
            break;
        case SYS_EXIT: {
            int status = *(int *)get_stack_argument(f->esp, 1);
            exit(status);
            break;
        }
        case SYS_EXEC: {
            const char *cmd_line = *(const char **)get_stack_argument(f->esp, 1);
            if (!is_valid_user_string(cmd_line)) {
                exit(-1);
                break;
            }
            f->eax = exec(cmd_line);
            break;
        }
        case SYS_WAIT: {
            tid_t pid = *(tid_t *)get_stack_argument(f->esp, 1);
            f->eax = wait(pid);
            break;
        }
        case SYS_CREATE: {
            const char *file = *(const char **)get_stack_argument(f->esp, 1);
            unsigned initial_size = *(unsigned *)get_stack_argument(f->esp, 2);
            if (!is_valid_user_string(file)) {
                exit(-1);
                break;
            }
            f->eax = create(file, initial_size);
            break;
        }
        case SYS_REMOVE: {
            const char *file = *(const char **)get_stack_argument(f->esp, 1);
            if (!is_valid_user_string(file)) {
                exit(-1);
                break;
            }
            f->eax = remove(file);
            break;
        }
        case SYS_OPEN: {
            const char *file = *(const char **)get_stack_argument(f->esp, 1);
            if (!is_valid_user_string(file)) {
                exit(-1);
                break;
            }
            f->eax = open(file);
            break;
        }
        case SYS_FILESIZE: {
            int fd = *(int *)get_stack_argument(f->esp, 1);
            f->eax = filesize(fd);
            break;
        }
        case SYS_READ: {
            int fd = *(int *)get_stack_argument(f->esp, 1);
            void *buffer = *(void **)get_stack_argument(f->esp, 2);
            unsigned size = *(unsigned *)get_stack_argument(f->esp, 3);
            if (!is_valid_user_buffer(buffer, size)) {
                exit(-1);
                break;
            }
            f->eax = read(fd, buffer, size);
            break;
        }
        case SYS_WRITE: {
            int fd = *(int *)get_stack_argument(f->esp, 1);
            const void *buffer = *(const void **)get_stack_argument(f->esp, 2);
            unsigned size = *(unsigned *)get_stack_argument(f->esp, 3);
            if (!is_valid_user_buffer(buffer, size)) {
                exit(-1);
                break;
            }
            f->eax = write(fd, buffer, size);
            break;
        }
        case SYS_SEEK: {
            int fd = *(int *)get_stack_argument(f->esp, 1);
            unsigned position = *(unsigned *)get_stack_argument(f->esp, 2);
            seek(fd, position);
            break;
        }
        case SYS_TELL: {
            int fd = *(int *)get_stack_argument(f->esp, 1);
            f->eax = tell(fd);
            break;
        }
        case SYS_CLOSE: {
            int fd = *(int *)get_stack_argument(f->esp, 1);
            close(fd);
            break;
        }
        default:
            printf("Unimplemented system call number: %d\n", syscall_num);
            thread_exit();
    }
}

void halt(void) {
    shutdown_power_off();
}

void exit(int status) {
    struct thread *cur = thread_current();
    cur->exit_status = status;
    printf("%s: exit(%d)\n", cur->name, status);
    thread_exit();
}

tid_t exec(const char *cmd_line) {
    if (!cmd_line || !is_valid_user_string(cmd_line)) return -1;

    // Execute the command
    tid_t pid = process_execute(cmd_line);

    // If process creation failed, return -1
    if (pid == TID_ERROR) return -1;

    struct thread *child = get_thread_by_tid(pid); // Implement this to get the child thread
    if (!child) return -1;

    // Wait until child sets its load status
    sema_down(&child->file_load_sema); // Semaphore to synchronize loading

    // Check if the child loaded successfully
    if (!child->load_success) {
        return -1;
    }

    return pid;
}

int wait(tid_t pid) {
    return process_wait(pid);
}

bool create(const char *file, unsigned initial_size) {
    if (!file || !is_valid_user_string(file)) return false;
    lock_acquire(&file_system_lock);
    bool success = filesys_create(file, initial_size);
    lock_release(&file_system_lock);
    return success;
}

bool remove(const char *file) {
    if (!file || !is_valid_user_string(file)) return false;
    lock_acquire(&file_system_lock);
    bool success = filesys_remove(file);
    lock_release(&file_system_lock);
    return success;
}

int open(const char *file) {
    if (!file || !is_valid_user_string(file)) return -1;
    lock_acquire(&file_system_lock);
    struct file *f = filesys_open(file);
    lock_release(&file_system_lock);
    if (!f) return -1;

    struct thread *cur = thread_current();
    int fd = cur->next_fd++;
    cur->fd_table[fd] = f;
    return fd;
}

int filesize(int fd) {
    struct file *f = thread_current()->fd_table[fd];
    if (!f) return -1;
    lock_acquire(&file_system_lock);
    int size = file_length(f);
    lock_release(&file_system_lock);
    return size;
}

int read(int fd, void *buffer, unsigned size) {
    if (fd == STDIN_FILENO) {
        uint8_t *buf = (uint8_t *)buffer;
        for (unsigned i = 0; i < size; i++) buf[i] = input_getc();
        return size;
    }

    struct file *f = thread_current()->fd_table[fd];
    if (!f) return -1;

    lock_acquire(&file_system_lock);
    int bytes_read = file_read(f, buffer, size);
    lock_release(&file_system_lock);
    return bytes_read;
}

int write(int fd, const void *buffer, unsigned size) {
    if (fd == STDOUT_FILENO) {
        putbuf(buffer, size);
        return size;
    }

    struct file *f = thread_current()->fd_table[fd];
    if (!f) return -1;

    lock_acquire(&file_system_lock);
    int bytes_written = file_write(f, buffer, size);
    lock_release(&file_system_lock);
    return bytes_written;
}

void seek(int fd, unsigned position) {
    struct file *f = thread_current()->fd_table[fd];
    if (!f) return;

    lock_acquire(&file_system_lock);
    file_seek(f, position);
    lock_release(&file_system_lock);
}

unsigned tell(int fd) {
    struct file *f = thread_current()->fd_table[fd];
    if (!f) return -1;

    lock_acquire(&file_system_lock);
    unsigned position = file_tell(f);
    lock_release(&file_system_lock);
    return position;
}

void close(int fd) {
    struct file *f = thread_current()->fd_table[fd];
    if (f) {
        lock_acquire(&file_system_lock);
        file_close(f);
        thread_current()->fd_table[fd] = NULL;
        lock_release(&file_system_lock);
    }
}

static bool is_valid_user_pointer(const void *ptr) {
    return ptr != NULL && is_user_vaddr(ptr) && pagedir_get_page(thread_current()->pagedir, ptr) != NULL;
}

static bool is_valid_user_buffer(const void *buffer, unsigned size) {
    for (unsigned i = 0; i < size; i++) {
        if (!is_valid_user_pointer(buffer + i)) return false;
    }
    return true;
}

static bool is_valid_user_string(const char *str) {
    if (!is_valid_user_pointer(str)) return false;
    while (*str != '\0') {
        str++;
        if (!is_valid_user_pointer(str)) return false;
    }
    return true;
}

static void *get_stack_argument(void *esp, int offset) {
    return (void *)((char *)esp + offset * 4);
}
