/*
 * container.h
 *
 * Detect and access containers.
 */

#ifndef _CONTAINER_H
#define _CONTAINER_H

extern int			shell_open_namespace_dir(pid_t container_pid, const char *command);
extern int			shell_set_namespaces_from(int procfd);

#endif /* _CONTAINER_H */
