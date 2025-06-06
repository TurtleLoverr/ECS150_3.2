#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

#define SIGNATURE "ECS150FS" //signature for the file system we want
#define SIGNATURE_LENGTH 8 
#define FAT_EOC 0XFFFF //marks end of block chain (FAT)

typedef struct superblock_tag{ //struct for the first block 
	uint8_t signature[SIGNATURE_LENGTH];
	uint16_t total_blocks;
	uint16_t root_index;
	uint16_t data_block_index;
	uint16_t data_block_amount;
	uint8_t fat_block_count;
	uint8_t padding[4079];
}__attribute__((packed)) superblock_t; //packed so there's no padding between the variables of the struct

typedef struct root_dir_tag{ //struct for each entry in root directory
	char filename[FS_FILENAME_LEN];
	uint32_t size;
	uint16_t first_block_index;
	uint8_t padding[10];
}__attribute__((packed)) root_dir_entry_t; 

static superblock_t superblock;
static root_dir_entry_t *root_dir = NULL; 
static uint16_t *fat = NULL;
static uint8_t mounted = 0;

typedef struct {
    int     in_use;          // 0 = free, 1 = open
    int     root_dir_index;  // index into root_dir[] for this FD
    size_t  offset;          // current byte offset within the file
} fs_fd_entry_t;

static fs_fd_entry_t fd_table[FS_OPEN_MAX_COUNT];

/* TODO: Phase 1 */

int fs_mount(const char *diskname)
{
	/* TODO: Phase 1 */
	if(block_disk_open(diskname) == -1){ //we try to open the disk
		return(-1); //if we can't open it
	}
	if(block_read(0, &superblock) == -1){ //reading the superblock from disk into the superblock struct 
		block_disk_close();
		return(-1); //if we can't read it
	}
	if(memcmp(superblock.signature, SIGNATURE, SIGNATURE_LENGTH) != 0){ //checking if signature matches what we want (ECS150FS)
		block_disk_close();
		return(-1);
	}
	int block_count = block_disk_count();//getting the actual number of blocks 
	if(block_count == -1){
		block_disk_close();
		return(-1); //if we can't get the block count
	}
	if(block_count != superblock.total_blocks){ //checking that the superblock's total blocks matches the actual disk size 
		block_disk_close();
		return(-1);
	}

	uint8_t expected_fat_block_count = ((superblock.data_block_amount * 2) + (BLOCK_SIZE -1))/BLOCK_SIZE; //calculating how mmany blocks FAT should occupy 

	if(expected_fat_block_count != superblock.fat_block_count){
		block_disk_close();
		return(-1); //if the FAT size isn't right
	}
	if(superblock.root_index != superblock.fat_block_count+1){ //checking that the root directory is right after the FAT blocks
		block_disk_close();
		return(-1); //if it's not
	}
	if(superblock.data_block_index != superblock.root_index+1){
		block_disk_close();
		return(-1);
	}
	fat = (uint16_t *)calloc(superblock.data_block_amount, sizeof(uint16_t)); //allocating memory for FAT (using calloc to initialize to 0)
	if(fat == NULL){
		block_disk_close();
		return(-1);
	}
	
	uint8_t *fat_buffer = calloc(superblock.fat_block_count, BLOCK_SIZE); //allocating temporary buffer to read all FAT blocks
    if(fat_buffer == NULL){
        block_disk_close();
        free(fat);
        fat = NULL;
        return(-1);
    }

	for(int i = 0; i < superblock.fat_block_count; i++){ //read FAT blocks into the buffer
		if(block_read(i+1, fat_buffer +(i * BLOCK_SIZE)) == -1){ 
			block_disk_close();
			free(fat);
			free(fat_buffer);
			fat = NULL; 
			return(-1);
		}
	}

	memcpy(fat, fat_buffer, superblock.data_block_amount * sizeof(uint16_t)); //copy the FAT data from the temporary buffer into the actual FAT
    free(fat_buffer);
	if(fat[0] != (uint16_t) FAT_EOC){ //checking that first entry is set to FAT_EOC
		block_disk_close();
		free(fat);
		fat = NULL;
		return(-1);
	}
	
	root_dir = (root_dir_entry_t *)calloc(FS_FILE_MAX_COUNT, sizeof(root_dir_entry_t)); 
	if(root_dir == NULL){
		block_disk_close();
		free(fat);
		fat = NULL;
		return(-1);
	}
	if(block_read(superblock.root_index, root_dir) == -1){
		block_disk_close();
		free(fat);
		fat = NULL; 
		free(root_dir);
		root_dir = NULL;
		return(-1);
	}

    //  initialize FD table: all descriptors start closed 
    for (int i = 0; i < FS_OPEN_MAX_COUNT; i++) {
        fd_table[i].in_use         = 0;
        fd_table[i].root_dir_index = -1;
        fd_table[i].offset         = 0;
    }

	mounted = 1;
	return 0;
}


int fs_umount(void)
{
	/* TODO: Phase 1 */
	if(!mounted){
		return(-1);
	}
	for(int i=1; i < superblock.root_index; i++){
		if(block_write(i, fat + (i-1)*BLOCK_SIZE) == -1){
			return(-1);
		}
	}
	if(block_write(superblock.root_index, root_dir) == -1){
		return(-1);
	}
	free(fat);
	free(root_dir);
	fat = NULL; 
	root_dir = NULL; 
	if(block_disk_close() == -1){
		return(-1);
	}
	return 0;
}

int fs_info(void)
{
	/* TODO: Phase 1 */
	if(!mounted){
		return(-1);
	}
	int fat_free_blocks = 0; //counting how many blocks are available
	for(int i=1; i < superblock.data_block_amount; i++){ //skipping index 0 since it's always FAT_EOC 
		if(fat[i] == 0){
			fat_free_blocks++;
		}
	}

	int rdir_free_entries = 0;//counting how many root directory entries are available
	for(int i=0; i < FS_FILE_MAX_COUNT; i++){
		if(root_dir[i].filename[0] == '\0'){
			rdir_free_entries++;
		}
	}

	printf("FS Info:\n");
	printf("total_blk_count=%u\n", superblock.total_blocks);
	printf("fat_blk_count=%u\n", superblock.fat_block_count);
	printf("rdir_blk=%u\n", superblock.root_index);
	printf("data_blk=%u\n", superblock.data_block_index);
	printf("data_blk_count=%u\n", superblock.data_block_amount);
	printf("fat_free_ratio=%d/%u\n", fat_free_blocks, superblock.data_block_amount);
	printf("rdir_free_ratio=%d/%d\n", rdir_free_entries, FS_FILE_MAX_COUNT);

	return 0;
}

int fs_create(const char *filename)
{
	/* TODO: Phase 2 */
	if(!mounted){
		return(-1);
	}
	if(filename == NULL){
		return(-1);
	}
	if(strlen(filename)>= FS_FILENAME_LEN){
		return(-1);
	}
	int empty_entry_idx = -1;
	for(int i=0; i < FS_FILE_MAX_COUNT; i++){
		if(strcmp(root_dir[i].filename, filename) == 0){ //checking if file already exists
			return(-1); //return -1 if it does
		}
		if(empty_entry_idx == -1 && root_dir[i].filename[0] == '\0'){ //if next empty index isn't found yet, we check the current root directory entry
			empty_entry_idx = i;
		}
	}
	if(empty_entry_idx == -1){ //root directory is full(no empty entry)
		return(-1);
	}
	strcpy(root_dir[empty_entry_idx].filename, filename);
	root_dir[empty_entry_idx].size = 0;
	root_dir[empty_entry_idx].first_block_index = FAT_EOC;

	return 0;
}

int fs_delete(const char *filename)
{
	/* TODO: Phase 2 */
	if(!mounted){ //checking if we have a file system actually mounted 
		return(-1);
	}
	if(!filename){ 
		return(-1);
	}
	if(strlen(filename) == 0 || strlen(filename) >= FS_FILENAME_LEN){ //checking that the filename isn't empty or too long(cuz we have a limit)
		return(-1);
	}

	int file_idx = -1; //now we have to actually find the file in our root directory 
	for(int i = 0; i < FS_FILE_MAX_COUNT; i++){ 
		if(strcmp(root_dir[i].filename, filename) == 0){ //it was found
			file_idx = i;
			break;
		}
	}
	if(file_idx == -1){  //if we can't find the file
		return(-1); 
	}

    // refuse to delete if this file is currently open 
    for (int i = 0; i < FS_OPEN_MAX_COUNT; i++) {
        if (fd_table[i].in_use && fd_table[i].root_dir_index == file_idx) {
            return -1;
        }
    }
	
	uint16_t current_block = root_dir[file_idx].first_block_index; //now we have to free all the blocks this file was using
	while(current_block != FAT_EOC){
		uint16_t next_block = fat[current_block];
		fat[current_block] = 0; //marking the current block as free
		current_block = next_block; //moving on to the next block
	}

    // also clear the directory entry
    root_dir[file_idx].filename[0]    = '\0';
    root_dir[file_idx].size           = 0;
    root_dir[file_idx].first_block_index = FAT_EOC;

	return 0;
}

int fs_ls(void)
{
	/* TODO: Phase 2 */
	if(!mounted){
		return(-1);
	}
	printf("FS Ls:\n");
	for(int i=0; i < FS_FILE_MAX_COUNT; i++){
		if(root_dir[i].filename[0] != '\0'){
			printf("file: %s, size: %u, data_blk: %u\n", root_dir[i].filename, root_dir[i].size, root_dir[i].first_block_index);
		}
	}
	return 0;
}



int fs_open(const char *filename)
{
	// reject if no file system is mounted of if filename is NULL
    if (!mounted || filename == NULL) {
        return -1;
    }

    // find the root_dir entry for this filename
    int dir_idx = -1;
    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		// check non-empty slot and compare strings
        if (root_dir[i].filename[0] != '\0' &&
            strcmp(root_dir[i].filename, filename) == 0) {
            dir_idx = i;
            break;
        }
    }
	// if not found then return error
    if (dir_idx < 0) {
        return -1;  // file not found
    }

    // find a free slot in fd_table[]
    int fd = -1;
    for (int i = 0; i < FS_OPEN_MAX_COUNT; i++) {
        if (!fd_table[i].in_use) {
            fd = i;
            break;
        }
    }
    if (fd < 0) {
        return -1;  // no available file descriptors
    }

    
    fd_table[fd].in_use         = 1; // mark slot in use
    fd_table[fd].root_dir_index = dir_idx; // remember which root directory entry it refers to
    fd_table[fd].offset         = 0; // set file offest to beginning of file

    return fd;
}

int fs_close(int fd)
{
	// reject if no FS is mounted
    if (!mounted) {
        return -1;
    }
	// reject invalid descriptor values
    if (fd < 0 || fd >= FS_OPEN_MAX_COUNT) {
        return -1;
    }
    if (!fd_table[fd].in_use) {
        return -1;
    }

    // mark descriptor free again
    fd_table[fd].in_use         = 0;
    fd_table[fd].root_dir_index = -1;
    fd_table[fd].offset         = 0;
    return 0;
}

int fs_stat(int fd)
{
    if (!mounted) {
        return -1;
    }
    if (fd < 0 || fd >= FS_OPEN_MAX_COUNT) {
        return -1;
    }
    if (!fd_table[fd].in_use) {
        return -1;
    }
	// look up which root directory entry this fd points to
    int rindex = fd_table[fd].root_dir_index;
    return (int)root_dir[rindex].size; // return the file's current size
}

int fs_lseek(int fd, size_t offset)
{
    if (!mounted) {
        return -1;
    }
    if (fd < 0 || fd >= FS_OPEN_MAX_COUNT) {
        return -1;
    }
    if (!fd_table[fd].in_use) {
        return -1;
    }
	// get the file's root directory index
    int rindex    = fd_table[fd].root_dir_index;
    size_t fsize  = root_dir[rindex].size;
    if (offset > fsize) {
        return -1;  // cannot seek past EOF
    }
    fd_table[fd].offset = offset;
    return 0;
}



int fs_write(int fd, void *buf, size_t count)
{
    if (!mounted || buf == NULL) {
        return -1;
    }
    if (fd < 0 || fd >= FS_OPEN_MAX_COUNT || !fd_table[fd].in_use) {
        return -1;
    }

    int    rindex     = fd_table[fd].root_dir_index;
    size_t old_size   = root_dir[rindex].size; // current file size
    size_t old_offset = fd_table[fd].offset; // current file offset
    if (old_offset > old_size) { // cant write if offset is larger than current size
        return -1;
    }

    // compute new file size
    size_t end_pos  = old_offset + count;
    size_t new_size = (end_pos > old_size) ? end_pos : old_size;

    // count currently allocated blocks
    uint16_t head = root_dir[rindex].first_block_index;
    int current_blocks = 0;
    if (head != FAT_EOC) {
        uint16_t cur = head;
        while (cur != FAT_EOC) {
            current_blocks++;
            cur = fat[cur];
        }
    }

    // how many blocks the new size needs
    int required_blocks = (new_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    if (required_blocks > current_blocks) {
		// we need to allocate "requried_blocks - current_blocks" to get the number of new blocks
        int to_alloc = required_blocks - current_blocks;
        // find last block of existing chain
        uint16_t last_idx = FAT_EOC;
        if (head != FAT_EOC) {
            last_idx = head;
            while (fat[last_idx] != FAT_EOC) {
                last_idx = fat[last_idx];
            }
        }
        // allocate new blocks one by one
        for (int i = 0; i < to_alloc; i++) {
            int free_idx = -1;

			// search FAT for a free block value == 0
            for (int j = 0; j < superblock.data_block_amount; j++) {
                if (fat[j] == 0) { 
                    free_idx = j;
                    break;
                }
            }
			// no free blocks
            if (free_idx < 0) {
                return -1;  // no free blocks
            }
			// mark this block as the end of chain
            fat[free_idx] = FAT_EOC;
            if (head == FAT_EOC) {
                // first block in chain
                root_dir[rindex].first_block_index = free_idx;
                head = free_idx;
            } else {
                fat[last_idx] = free_idx;
            }
            last_idx = free_idx;
        }
    }

    // wqrite data block by block - read-modify-write loop
    size_t remaining = count;
    uint8_t *write_ptr = (uint8_t *)buf;
    size_t pos = old_offset;
    uint8_t block_data[BLOCK_SIZE];

    while (remaining > 0) {
		// determine which FAT chain index corresponds to pos
        int block_idx_in_chain = pos / BLOCK_SIZE;
        int block_offset       = pos % BLOCK_SIZE;

        // traverse FAT to find the block index
        uint16_t cur = root_dir[rindex].first_block_index;
        for (int i = 0; i < block_idx_in_chain; i++) {
            cur = fat[cur];
        }
        uint16_t fat_idx    = cur;
        uint16_t disk_block = superblock.data_block_index + fat_idx;

        // read the existing block (for read–modify–write)
        if (block_read(disk_block, block_data) == -1) {
            return -1;
        }
		// compute how many bytes to copy in this block
        int chunk = BLOCK_SIZE - block_offset;
        if ((size_t)chunk > remaining) {
            chunk = remaining;
        }

		// copy from user buffer into the block buffer
        memcpy(block_data + block_offset, write_ptr, chunk);

		// write the updated block back to the disk
        if (block_write(disk_block, block_data) == -1) {
            return -1;
        }

		// advance the pointers and counters!
        remaining -= chunk;
        write_ptr  += chunk;
        pos        += chunk;
    }

    // update the file's metadata with the new size and new offset
    root_dir[rindex].size      = new_size;
    fd_table[fd].offset        = old_offset + count;
    return (int)count;
}

int fs_read(int fd, void *buf, size_t count)
{
    if (!mounted || buf == NULL) {
        return -1;
    }
    if (fd < 0 || fd >= FS_OPEN_MAX_COUNT || !fd_table[fd].in_use) {
        return -1;
    }

    int rindex = fd_table[fd].root_dir_index;
    size_t file_size  = root_dir[rindex].size;
    size_t old_offset = fd_table[fd].offset;
    if (old_offset >= file_size) {
        return 0;  // EOF
    }
	// determine how many bytes we actually read
    size_t max_can_read  = file_size - old_offset;
    size_t bytes_to_read = (count < max_can_read) ? count : max_can_read;

    size_t remaining = bytes_to_read;
    uint8_t *read_ptr = (uint8_t *)buf;
    size_t pos = old_offset;
    uint8_t block_data[BLOCK_SIZE];

    while (remaining > 0) {
		// determine which block in the FAT chain contains pos
        int block_idx_in_chain = pos / BLOCK_SIZE;
        int block_offset       = pos % BLOCK_SIZE;

		// traverse FAT to get to the correct block-index in chain
        uint16_t cur     = root_dir[rindex].first_block_index;
        for (int i = 0; i < block_idx_in_chain; i++) {
            cur = fat[cur];
        }
        uint16_t fat_idx    = cur;
        uint16_t disk_block = superblock.data_block_index + fat_idx;

		// read that block from disk
        if (block_read(disk_block, block_data) == -1) {
            return -1;
        }
		
		// compute how many bytes to copy out of this block
        int chunk = BLOCK_SIZE - block_offset;
        if ((size_t)chunk > remaining) {
            chunk = remaining;
        }
		// copy from block buffer into user buffer
        memcpy(read_ptr, block_data + block_offset, chunk);

        remaining -= chunk;
        read_ptr   += chunk;
        pos        += chunk;
    }
	// update the file offset by how many bytes we actually read
    fd_table[fd].offset = old_offset + bytes_to_read;
    return (int)bytes_to_read;
}


/*Sources
https://www.gnu.org/software/libc/manual/html_node/Integers.html
https://www.geeksforgeeks.org/dynamic-memory-allocation-in-c-using-malloc-calloc-free-and-realloc/
https://gcc.gnu.org/onlinedocs/gcc-4.1.0/gcc/Type-Attributes.html
*/