/* SPDX-License-Identifier: GPL-2.0-or-later */
/* app_none.inc - the hooks a program-specific layer can use; this default fabricates nothing and rewrites nothing.
 * linux_syscalls.c calls these from recomp_svc(); each returns the value that means "not mine, do the plain host
 * operation".  To adapt the runtime to a program that expects devices or files the host does not have, copy this file,
 * give the hooks bodies, and put your copy on the include path in place of this one. */
#define A64PORT_APP_UNUSED __attribute__((unused))

/* fabricated device fds: no types, so read/ioctl/ppoll/close fall through to the host */
enum { FT_NONE = 0, FT_GPIO, FT_SYSFS_ZERO, FT_SYSFS_CPUS };
int a64port_device_fdtype(int fd) { (void)fd; return FT_NONE; }
int a64port_device_is_drm(int fd) { (void)fd; return 0; }
static A64PORT_APP_UNUSED void device_reg(int fd, int t) { (void)fd; (void)t; }
static A64PORT_APP_UNUSED int device_open(const char* path) { (void)path; return -1; }       /* >= 0: an fd that replaces the open */
static A64PORT_APP_UNUSED int device_is_fabricated(const char* path) { (void)path; return 0; }
static A64PORT_APP_UNUSED ssize_t device_read(GuestContext* c, int fd, void* buf, size_t n) { (void)c; (void)fd; (void)buf; (void)n; errno = ENOSYS; return -1; }
static A64PORT_APP_UNUSED ssize_t device_readv(GuestContext* c, int fd, struct iovec* iov, int cnt) { (void)c; (void)fd; (void)iov; (void)cnt; errno = ENOSYS; return -1; }
static A64PORT_APP_UNUSED int device_ioctl(GuestContext* c, int t, int fd, uint64_t req, uint64_t arg) { (void)c; (void)t; (void)fd; (void)req; (void)arg; return -ENOTTY; }
static A64PORT_APP_UNUSED int device_ppoll(GuestContext* c, struct pollfd* fds, uint64_t nfds, int timeout_ms) { (void)c; (void)fds; (void)nfds; (void)timeout_ms; return -2; }  /* -2: the host ppoll */
static A64PORT_APP_UNUSED unsigned long long in_now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (unsigned long long)t.tv_sec * 1000ull + (unsigned long long)t.tv_nsec / 1000000ull; }
static unsigned long long g_last_clone_ms;

/* guest network interface names: the host's */
static A64PORT_APP_UNUSED const char* host_link_iface(void) { return ""; }
static A64PORT_APP_UNUSED int guest_ifname_is_alias(const char* name) { (void)name; return 0; }
static A64PORT_APP_UNUSED int is_guest_ifreq_ioctl(uint64_t req) { (void)req; return 0; }
static A64PORT_APP_UNUSED int guest_netif_ioctl(GuestContext* c, int fd, uint64_t req, uint64_t arg) { (void)c; (void)fd; (void)req; (void)arg; return -ENOTTY; }

/* execve of a shell probe (A64PORT_SHELL_STUB=1): not emulated */
static A64PORT_APP_UNUSED int sandbox_shell_command(const char* command) { (void)command; return 0; }
