#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "lib/user/syscall.h"
#include <stdio.h>
#include "lib/stdio.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);
static bool validate_user_ptr (const void *ptr);
static bool validate_user_buffer(const void *buffer, unsigned size);
static bool validate_user_string(const char *str);
static void *get_offset_ptr(void *ptr, int n);
static int get_fd_from_filename(struct thread *t, char *filename);

void
syscall_init (void) 
{
  lock_init(&file_system_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // validate the stack pointer
  if(!validate_user_ptr(f->esp)){
    exit(EXIT_ERROR);
    return;
  }

  // retrieve the system call number
  int syscall_num = *(int *)f->esp;

  // switch on the system call number
  switch (syscall_num) {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
    {
      int *status = (int *)get_offset_ptr(f->esp, 1);
      if(!validate_user_ptr(status))
        *status = EXIT_ERROR;
      exit(*status);
      break;
    }
    case SYS_EXEC:
    {
      char* cmd_line = *(char **)get_offset_ptr(f->esp, 1);
      // if cmd_line is null pointer or empty string, exit
      if(!validate_user_string(cmd_line)){
        exit(EXIT_ERROR);
        break;
      }
      f->eax = exec(cmd_line);
      break;
    }
    case SYS_WAIT:
    {
      void* pid = (void*)get_offset_ptr(f->esp, 1);
      if(!validate_user_ptr(pid)){
        exit(EXIT_ERROR);
        break;
      }
      f->eax = wait(*(pid_t*)pid);
      break;
    }
    case SYS_CREATE:
    {
      char* file = *(char **)get_offset_ptr(f->esp, 1);
      if(!validate_user_string(file)){
        exit(EXIT_ERROR);
        break;
      }
      unsigned int initial_size = *(unsigned int *)get_offset_ptr(f->esp, 2);
      bool success = create(file, initial_size);
      f->eax = success;
      break;
    }
    case SYS_REMOVE:
    {
      const char* file = *(char **)get_offset_ptr(f->esp, 1);
      if(!validate_user_string(file)){
        exit(EXIT_ERROR);
        break;
      }
      bool success = remove(file);
      f->eax = success;
      break;
    }
    case SYS_OPEN:
    {
      char* file = *(char **)get_offset_ptr(f->esp, 1);
      // if file name is null pointer or empty string, exit
      if(!validate_user_string(file)){
        exit(EXIT_ERROR);
        break;
      }
      int fd = open(file);
      f->eax = fd;
      break;
    }
    case SYS_FILESIZE:
    {
      int* fd = (int *)get_offset_ptr(f->esp, 1);
      if(!validate_user_ptr(fd)){
        exit(EXIT_ERROR);
        break;
      }
      f->eax = filesize((int)*fd);
      break;
    }
    case SYS_READ:
    {
      int fd = *(int *)get_offset_ptr(f->esp, 1);
      void *buffer = *(void **)get_offset_ptr(f->esp, 2);
      unsigned length = *(unsigned *)get_offset_ptr(f->esp, 3);
      if(!validate_user_buffer(buffer, length)){
        exit(EXIT_ERROR);
        break;
      } 
      f->eax = read(fd, buffer, length);
      break;
    }
    case SYS_WRITE:
    {
      int* fd = (int *)get_offset_ptr(f->esp, 1);
      const void *buffer = *(void **)get_offset_ptr(f->esp, 2);
      unsigned* length = (unsigned *)get_offset_ptr(f->esp, 3);
      if(!validate_user_buffer(buffer, *length)){
        exit(EXIT_ERROR);
        break;
      }
      f->eax = write((int)*fd, buffer, (unsigned)*length);
      break;
    }
    case SYS_SEEK:
    {
      int fd = *(int *)get_offset_ptr(f->esp, 1);
      unsigned position = *(int *)get_offset_ptr(f->esp, 2);
      seek(fd, position);
      break;
    }
    case SYS_TELL:
    {
      int fd = *(int *)get_offset_ptr(f->esp, 1);
      f->eax = tell(fd);
      break;
    }
    case SYS_CLOSE:
    {
      void* file_name = get_offset_ptr(f->esp, 1);
      if(!validate_user_ptr(file_name)){
        exit(EXIT_ERROR);
        break;
      }
      int fd = get_fd_from_filename(thread_current(), (char*)file_name);
      if(fd != NULL){
        close(fd);
      }
      break;
    }
    default:
      printf("System call number %d is not implemented\n", syscall_num);
      break; 
  }
}

/* Shutdown pintos */ 
void halt(void)
{
  shutdown_power_off();
}

/* Exit process */
void exit(int status)
{
  struct thread *t = thread_current();
  t->exit_status = status; // set exit status for parent to retrieve
  printf("%s: exit(%d)\n", t->name, status);
  thread_exit();
}

/* Create child process and 
 * runs the executable whose name is given in cmd_line, 
 * passing any given arguments, and 
 * returns the new process's program id (pid) */
pid_t exec(const char *cmd_line)
{
  struct thread *curr_t = thread_current();
  struct thread *child_t;
  struct list_elem *child_elem;

  // execute cmd_line and make a child process
  tid_t child_tid = process_execute(cmd_line);
  if (child_tid == TID_ERROR)
  {
    return child_tid;
  }

  // Check if child_tid is in current threads children.
  for (
      child_elem = list_begin(&curr_t->child_list);
      child_elem != list_end(&curr_t->child_list);
      child_elem = list_next(child_elem))
  {
    child_t = list_entry(child_elem, struct thread, child_elem);
    if (child_t->tid == child_tid)
    {
      break;
    }
  }
  // If child with child_tid was not in list, its not a child of the calling process
  if (child_elem == list_end(&curr_t->child_list))
    return EXIT_ERROR;

  sema_down(&child_t->file_load_sema);
  if (!child_t->load_success)
    return EXIT_ERROR;

  return child_tid;
}

/* Waits for a child process pid and 
 * retrieves the child's exit status */
int wait(pid_t pid)
{
  return process_wait(pid);
}

/* 
 * Creates a new file called file initially initial_size bytes in size. 
 * Returns true if successful, false otherwise. 
 * */
bool create(const char *file, unsigned initial_size)
{
  lock_acquire(&file_system_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&file_system_lock);
  return success;
}

/* 
* Deletes the file called file. 
* Returns true if successful, false otherwise. 
* A file may be removed regardless of whether it is open or closed, and removing an open file does not close it.
*/
bool remove (const char *file){
  lock_acquire(&file_system_lock);
  bool success = filesys_remove(file);
  lock_release(&file_system_lock);
  return success;
}

/* Opens the file called file. 
* Returns a nonnegative integer handle called a "file descriptor" (fd), 
* or -1 if the file could not be opened. */
int open (const char *file){

  lock_acquire(&file_system_lock);
  struct file *f = filesys_open(file);
  lock_release(&file_system_lock);
  if(f == NULL)
    return EXIT_ERROR;
  
  // add file to fd_table
  struct thread *curr_t = thread_current();
  curr_t->fd_table[curr_t->next_fd] = f;
  curr_t->next_fd++;
  return curr_t->next_fd - 1;
}

/* Returns the size, in bytes, of the file open as fd.*/
int filesize (int fd){
  struct thread *curr_t = thread_current();
  struct file *f = curr_t->fd_table[fd];
  if(f == NULL)
    return EXIT_ERROR;
  lock_acquire(&file_system_lock);
  off_t length = file_length(f);
  lock_release(&file_system_lock);
  return length;
}


/* Reads size bytes from the file open as fd into buffer. 
Returns the number of bytes actually read (0 at end of file), 
or -1 if the file could not be read (due to a condition other than end of file). 
Fd 0 reads from the keyboard using input_getc(). */
int read (int fd, void *buffer, unsigned size)
{
  int read_size = 0;
  if(fd == STDIN_FILENO){
    uint8_t *buf = (uint8_t *)buffer;
    for(unsigned i = 0; i < size; i++){
      buf[i] = input_getc();
    }
    read_size = size;
  }else if(fd == STDOUT_FILENO){
    return EXIT_ERROR;
  }
  else{
    struct thread *curr_t = thread_current();
    struct file *f = curr_t->fd_table[fd];
    if(f == NULL)
      return EXIT_ERROR;
    lock_acquire(&file_system_lock);
    read_size = file_read(f, buffer, size);
    lock_release(&file_system_lock);
  }
  return read_size;
}

int 
write (int fd, const void *buffer, unsigned length)
{
  int written_size = 0;
  if(fd == STDOUT_FILENO){
    putbuf(buffer, length);
    written_size = length;
  }
  else if(fd == STDIN_FILENO){
    return EXIT_ERROR;
  }
  else{
    struct thread *curr_t = thread_current();
    struct file *f = curr_t->fd_table[fd];
    if(f == NULL)
      return EXIT_ERROR;
    written_size = file_write(f, buffer, length);
  }
  return written_size;
};

/*
 * Changes the next byte to be read or written in open file fd to 
 * position, expressed in bytes from the beginning of the file. 
 * (Thus, a position of 0 is the file's start.) */
void seek (int fd, unsigned position)
{
  struct thread *curr_t = thread_current();
  struct file *f = curr_t->fd_table[fd];
  if(f == NULL){
    exit(EXIT_ERROR);
    return;
  }
  lock_acquire(&file_system_lock);
  file_seek(f, position);
  lock_release(&file_system_lock);
}

// Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file.
unsigned tell (int fd)
{
  struct thread *curr_t = thread_current();
  struct file *f = curr_t->fd_table[fd];
  if(f == NULL)
    return EXIT_ERROR;
  lock_acquire(&file_system_lock);
  off_t offset = file_tell(f);
  lock_release(&file_system_lock);
  return offset;
}
/* Closes file descriptor fd. 
 * Exiting or terminating a process implicitly closes all 
 * its open file descriptors, as if by calling this function for each one.
 */
void close (int fd)
{
  struct thread *curr_t = thread_current();
  struct file *f = curr_t->fd_table[fd];
  if(f == NULL){
    return;
  }
  lock_acquire(&file_system_lock);
  file_close(f);
  f = NULL;
  lock_release(&file_system_lock);
}

/*
 * Checks if the pointer is a valid user pointer
 * User pointer is valid if it is not null pointer, 
 * a pointer to kernel virtual address space (above PHYS_BASE)
 * or a pointer to unmapped virtual memory, 
 */
static
bool is_valid_ptr(const void *ptr){
  if (ptr == NULL) {
    return false;
  }

  if (is_kernel_vaddr(ptr)) {
    return false;
  }

  struct thread *curr_t = thread_current();
  if (pagedir_get_page(curr_t->pagedir, ptr) == NULL) {
    return false;
  }

  return true;
}

static 
bool validate_user_ptr(const void *ptr)
{
  // validate ptr and next to ensure that the first byte is not the only valid byte 
  return is_valid_ptr(ptr) && is_valid_ptr(ptr+4);
}

static 
bool validate_user_buffer(const void *buffer, unsigned size)
{
  for(unsigned i = 0; i < size; i++){
    if(!is_valid_ptr(buffer + i))
      return false;
  }
  return true;
}

static 
bool validate_user_string(const char *str)
{
  if(!is_valid_ptr(str))
    return false;
  while(*str != '\0'){
    str++;
    if(!is_valid_ptr(str))
      return false;
  }
  return true;
}

static
void *get_offset_ptr(void *ptr, int n)
{
  void *next_ptr = ptr + 4*n;
  return next_ptr;
}

static
int get_fd_from_filename(struct thread *t, char *filename)
{
  struct file *f;
  for(int i = 0; i < t->next_fd; i++){
    f = t->fd_table[i];
    if(f == NULL)
      continue;
    if(strcmp(filename, f) == 0)
      return i;
  }
  return NULL;
}