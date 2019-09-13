#ifndef _DD_DLOPEN_H_
#define _DD_DLOPEN_H_

void* dd_dlopen(const char*);
void* dd_dlsym(void *, const char*);
void dd_dlclose(void *);

#endif
