 /*
    Copyright (C) 2018  Shyamsundar.R

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

typedef unsigned int uint32_t;

struct mem_header {
    uint32_t magic;
    size_t size;
};

#define GF_MEM_HEADER_SIZE (sizeof(struct mem_header))
#define GF_MEM_TRAILER_SIZE 8
#define GF_MEM_HEADER_MAGIC 0xCAFEBABE
#define GF_MEM_TRAILER_MAGIC 0xBAADF00D

void *
my_malloc(size_t size)
{
    size_t tot_size = 0;
    char *ptr = NULL;
    struct mem_header *header = NULL;

    tot_size = size + GF_MEM_HEADER_SIZE + GF_MEM_TRAILER_SIZE;

    ptr = malloc(tot_size);
    if (!ptr) {
        return NULL;
    }

    header = (struct mem_header *)ptr;
    header->size = size;
    header->magic = GF_MEM_HEADER_MAGIC;

    ptr += sizeof(struct mem_header);
    *(uint32_t *)(ptr + size) = GF_MEM_TRAILER_MAGIC;

    return (void *)ptr;
}

void
my_free(void *free_ptr)
{
    void *ptr = NULL;
    struct mem_header *header = NULL;

    if (!free_ptr)
        return;

    ptr = free_ptr - GF_MEM_HEADER_SIZE;
    header = (struct mem_header *)ptr;

    if (!(GF_MEM_HEADER_MAGIC == header->magic)) {
        printf ("Header corrupted\n");
    } else {
        printf ("Header intact!\n");
    }

    if (!(GF_MEM_TRAILER_MAGIC ==
          *(uint32_t *)((char *)free_ptr + header->size))) {
        printf ("Trailer corrupted\n");
    } else {
        printf ("Trailer intact!\n");
    }

    free(ptr);
}

#define COPY_STR "Test string!"
#define TEST_FILE "./test.txt"

void
main(void) {
    char *buf, *taint_buf;
    int fd;
    ssize_t bytesread;

    buf = my_malloc(sizeof(COPY_STR));
    if (buf != NULL) {
        memcpy(buf, COPY_STR, sizeof(COPY_STR));
        printf("%s\n", buf);
        my_free(buf);
    }

    taint_buf = my_malloc(sizeof(COPY_STR));
    if (taint_buf == NULL)
        return;

    fd = open(TEST_FILE, O_RDWR);
    if (fd == -1) {
        printf ("Missing test file %s\n", TEST_FILE);
        my_free(taint_buf);
        return;
    }

    bytesread = read(fd, taint_buf, sizeof(COPY_STR));
    if (bytesread == sizeof(COPY_STR)) {
        /*taint_buf[bytesread - 1] = '\0';*/
        printf("%s\n", taint_buf);
    } else {
        printf ("Not enough data in test file %s\n", TEST_FILE);
    }

    my_free (taint_buf);

    return;
}
