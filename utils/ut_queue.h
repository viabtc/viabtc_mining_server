/*
 * Description: A variable length circular queue, support single process or
 *              thread write and single process or thread read.
 *              Support use file as storage.
 *     History: damonyang@tencent.com, 2013/06/08, create
 */

# pragma once

# include <stdint.h>
# include <sys/types.h>

typedef struct
{
    void   *memory;
    void   *read_buf;
    size_t read_buf_size;
} queue_t;

/*
 * pragma:
 *      name         : to identification queue
 *      shm_key      : if not 0 use share memory, else use malloc
 *      mem_size     : size of memory cache
 *      reserve_file : if not NULL, write data wo file when memory is full
 *      file_max_size: the max size of reserve file
 * return:
 *      <  0: error
 *      == 0: success
 */
int queue_init(queue_t *queue, char *name, key_t shm_key,
        uint32_t mem_size, char *reserve_file, uint64_t file_max_size);

/*
 * return:
 *      <  -1: error
 *      == -1: full
 *      ==  0: success
 */
int queue_push(queue_t *queue, void *data, uint32_t size);

/*
 * return:
 *      <  -1: error
 *      == -1: empty
 *      ==  0: success
 */
int queue_pop(queue_t *queue, void **data, uint32_t *size);

/* return queue len in byte */
uint64_t queue_len(queue_t *queue);

/* return queue unit num */
uint64_t queue_num(queue_t *queue);

/* get queue stat */
int queue_stat(queue_t *queue, \
        uint32_t *mem_num, uint32_t *mem_size, uint32_t *file_num, uint64_t *file_size);

/* free a queue */
void queue_fini(queue_t *queue);

