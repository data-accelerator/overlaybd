#pragma once
#include <sys/stat.h>
#include <ext2fs/ext2fs.h>
#include <photon/fs/filesystem.h>
#include <photon/common/alog.h>

static errcode_t ufs_open(const char *name, int flags, io_channel *channel);
static errcode_t ufs_close(io_channel channel);
static errcode_t ufs_set_blksize(io_channel channel, int blksize);
static errcode_t ufs_read_blk(io_channel channel, unsigned long block, int count, void *buf);
static errcode_t ufs_read_blk64(io_channel channel, unsigned long long block, int count, void *buf);
static errcode_t ufs_write_blk(io_channel channel, unsigned long block, int count, const void *buf);
static errcode_t ufs_write_blk64(io_channel channel, unsigned long long block, int count, const void *buf);
static errcode_t ufs_flush(io_channel channel);
static errcode_t ufs_discard(io_channel channel, unsigned long long block, unsigned long long count);
static errcode_t ufs_cache_readahead(io_channel channel, unsigned long long block, unsigned long long count);
static errcode_t ufs_zeroout(io_channel channel, unsigned long long block, unsigned long long count);

static struct struct_io_manager struct_ufs_manager = {
	.magic				= EXT2_ET_MAGIC_IO_MANAGER,
	.name				= "ufs I/O Manager",
	.open				= ufs_open,
	.close				= ufs_close,
	.set_blksize		= ufs_set_blksize,
	.read_blk			= ufs_read_blk,
	.write_blk			= ufs_write_blk,
	.flush				= ufs_flush,
	.read_blk64			= ufs_read_blk64,
	.write_blk64		= ufs_write_blk64,
	.discard			= ufs_discard,
	.cache_readahead	= ufs_cache_readahead,
	.zeroout			= ufs_zeroout,
};

static photon::fs::IFile *ufs_file;

struct unix_private_data {
	int	magic;
	int	dev;
	int	flags;
	int	align;
	int	access_time;
	ext2_loff_t offset;
	void	*bounce;
	struct struct_io_stats io_stats;
};

static errcode_t ufs_open(const char *name, int flags, io_channel *channel) {
	io_channel	io = NULL;
	struct unix_private_data *data = NULL;
	errcode_t	retval;
	ext2fs_struct_stat st;

	retval = ext2fs_get_mem(sizeof(struct struct_io_channel), &io);
	if (retval)
		return -retval;
	memset(io, 0, sizeof(struct struct_io_channel));
	io->magic = EXT2_ET_MAGIC_IO_CHANNEL;
	retval = ext2fs_get_mem(sizeof(struct unix_private_data), &data);
	if (retval)
		return -retval;

	io->manager = &struct_ufs_manager;
	retval = ext2fs_get_mem(strlen(name)+1, &io->name);
	if (retval)
		return -retval;

	strcpy(io->name, name);
	io->private_data = data;
	io->block_size = 1024;
	io->read_error = 0;
	io->write_error = 0;
	io->refcount = 1;
	io->flags = 0;

	memset(data, 0, sizeof(struct unix_private_data));
	data->magic = EXT2_ET_MAGIC_UNIX_IO_CHANNEL;
	data->io_stats.num_fields = 2;
	data->flags = flags;
	data->dev = 0;


	*channel = io;
	return 0;
}


static errcode_t ufs_close(io_channel channel) {
	LOG_INFO("ufs close");
	return ext2fs_free_mem(&channel);
}

static errcode_t ufs_set_blksize(io_channel channel, int blksize) {
	// LOG_INFO("set_blksize");
	channel->block_size = blksize;
	return 0;
}

// int get_disk_id(io_channel channel) {
// 	return (int)channel->private_data;
// }

static errcode_t ufs_read_blk(io_channel channel, unsigned long block, int count, void *buf) {
	// int disk_id = get_disk_id(channel);
	// disk_id 没什么用？
	// LOG_INFO("ufs_read_blk block size=`, ", channel->block_size, VALUE(block), VALUE(count));
	off_t offset = (ext2_loff_t) block * channel->block_size;
	ssize_t size = count < 0 ? -count :  (ext2_loff_t) count * channel->block_size;
	// LOG_INFO("read ", VALUE(offset), VALUE(size));
	auto res = ufs_file->pread(buf, size, offset);
	if (res == size) {
		return 0;
	}
	LOG_ERROR("failed to pread, got `, expect `", res, size);
	return -1;
}

static errcode_t ufs_read_blk64(io_channel channel, unsigned long long block, int count, void *buf) {
	return ufs_read_blk(channel, block, count, buf);
}

static errcode_t ufs_write_blk(io_channel channel, unsigned long block, int count, const void *buf) {
	// LOG_INFO("ufs_write_blk block size=`, ", channel->block_size, VALUE(block), VALUE(count));
	off_t offset = (ext2_loff_t) block * channel->block_size;
	ssize_t size = count < 0 ? -count :  (ext2_loff_t) count * channel->block_size;
	// LOG_INFO("write ", VALUE(offset), VALUE(size));
	auto res = ufs_file->pwrite(buf, size, offset);
	if (res == size) {
		return 0;
	}
	LOG_ERROR("failed to pwrite, got `, expect `", res, size);
	return -1;
}

static errcode_t ufs_write_blk64(io_channel channel, unsigned long long block, int count, const void *buf) {
	return ufs_write_blk(channel, block, count, buf);
}

static errcode_t ufs_flush(io_channel channel) {
	return 0;
}

static errcode_t ufs_discard(io_channel channel, unsigned long long block, unsigned long long count) {
	return 0;
}

static errcode_t ufs_cache_readahead(io_channel channel, unsigned long long block, unsigned long long count) {
	return 0;
}

static errcode_t ufs_zeroout(io_channel channel, unsigned long long block, unsigned long long count) {
	return 0;
}