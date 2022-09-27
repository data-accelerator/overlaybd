#include <ext2fs/ext2fs.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include <photon/photon.h>
#include <photon/common/alog.h>
#include <photon/common/alog-stdstring.h>
#include <photon/fs/filesystem.h>
#include <photon/fs/localfs.h>
#include <photon/fs/aligned-file.h>

#include "lsmt/file.h"
#include "zfile/zfile.h"


std::vector<std::string> lowers_fn;
std::vector<photon::fs::IFile*> lower_files;
struct struct_io_manager *im = nullptr;
photon::fs::IFile *image_file;
io_manager lsmt_io_manager;


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

static errcode_t lsmt_open(const char *name, int flags, io_channel *channel)
{
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

	io->manager = lsmt_io_manager;
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


static errcode_t lsmt_close(io_channel channel) {
	LOG_INFO("lsmt close");
	return ext2fs_free_mem(&channel);
}

static errcode_t set_blksize(io_channel channel, int blksize) {
	LOG_INFO("set_blksize");
	channel->block_size = blksize;
	return 0;
}

// int get_disk_id(io_channel channel) {
// 	return (int)channel->private_data;
// }

static errcode_t lsmt_read_blk(io_channel channel, unsigned long block, int count, void *buf) {
	// int disk_id = get_disk_id(channel);
	// disk_id 没什么用？
	LOG_INFO("lsmt_read_blk block size=`, ", channel->block_size, VALUE(block), VALUE(count));
	off_t offset = (ext2_loff_t) block * channel->block_size;
	ssize_t size = count < 0 ? -count :  (ext2_loff_t) count * channel->block_size;
	LOG_INFO("read ", VALUE(offset), VALUE(size));
	auto res = image_file->pread(buf, size, offset);
	if (res == size) {
		return 0;
	}
	LOG_ERROR("failed to pread, got `, expect `", res, size);
	return -1;
}

static errcode_t lsmt_read_blk64(io_channel channel, unsigned long long block, int count, void *buf) {
	return lsmt_read_blk(channel, block, count, buf);
}

static errcode_t lsmt_write_blk(io_channel channel, unsigned long block, int count, const void *buf) {
	LOG_INFO("lsmt_write_blk block size=`, ", channel->block_size, VALUE(block), VALUE(count));
	off_t offset = (ext2_loff_t) block * channel->block_size;
	ssize_t size = count < 0 ? -count :  (ext2_loff_t) count * channel->block_size;
	LOG_INFO("write ", VALUE(offset), VALUE(size));
	auto res = image_file->pwrite(buf, size, offset);
	if (res == size) {
		return 0;
	}
	LOG_ERROR("failed to pwrite, got `, expect `", res, size);
	return -1;
}

static errcode_t lsmt_write_blk64(io_channel channel, unsigned long long block, int count, const void *buf) {
	return lsmt_write_blk(channel, block, count, buf);
}

static errcode_t lsmt_flush(io_channel channel) {
	return 0;
}

static errcode_t lsmt_discard(io_channel channel, unsigned long long block, unsigned long long count) {
	return 0;
}

static errcode_t lsmt_cache_readahead(io_channel channel, unsigned long long block, unsigned long long count) {
	return 0;
}

static errcode_t lsmt_zeroout(io_channel channel, unsigned long long block, unsigned long long count) {
	return 0;
}

static struct struct_io_manager struct_lsmt_manager = {
	.magic		= EXT2_ET_MAGIC_IO_MANAGER,
	.name		= "LSMT I/O Manager",
	.open		= lsmt_open,
	.close		= lsmt_close,
	.set_blksize	= set_blksize,
	.read_blk	= lsmt_read_blk,
	.write_blk	= lsmt_write_blk,
	.flush		= lsmt_flush,
	.read_blk64	= lsmt_read_blk64,
	.write_blk64	= lsmt_write_blk64,
	.discard	= lsmt_discard,
	.cache_readahead	= lsmt_cache_readahead,
	.zeroout	= lsmt_zeroout,
};


struct struct_ext2_filsys *fs;

int init_lsmt() {
	lowers_fn.emplace_back("/root/u-overlaybd/ext4_64");

	for (int i = 0; i < 1; i ++) {
		auto file = photon::fs::open_localfile_adaptor(lowers_fn[i].c_str(), O_RDONLY, 0644, 0);
		if (!file) {
			LOG_ERROR("failed to open `", lowers_fn[i]);
			return -1;
		}
		if (ZFile::is_zfile(file) == 1) {
			auto zf = ZFile::zfile_open_ro(file, false, true);
        	if (!zf) {
            	LOG_ERRNO_RETURN(0, -1, "zfile_open_ro failed");
        	}
			file = zf;
		}
		lower_files.emplace_back(file);
	}



	auto lower = LSMT::open_files_ro((photon::fs::IFile **)&(lower_files[0]), lower_files.size(), false);
    if (!lower) {
        LOG_ERROR("LSMT::open_files_ro(files, `, `) return NULL", lower_files.size(), false);
        return -1;
    }

	auto data_file = photon::fs::open_localfile_adaptor("/root/u-overlaybd/rw_data", O_RDWR, 0644, 0);
    if (!data_file) {
        LOG_ERROR("open rw data failed");
        return -1;
    }

    auto idx_file = photon::fs::open_localfile_adaptor("/root/u-overlaybd/rw_index", O_RDWR, 0644, 0);
    if (!idx_file) {
        LOG_ERROR("open rw index failed");
        return -1;
    }
	auto upper = LSMT::open_file_rw(data_file, idx_file, true);

	auto stack_file = LSMT::stack_files(upper, lower, true, false);
    if (!stack_file) {
        LOG_ERROR("stack_files failed");
     	return -1;
    }
	// image_file = stack_file;
	image_file = photon::fs::new_aligned_file_adaptor(stack_file, 4096, true, true);

	return 0;
}


ext2_ino_t string_to_inode(ext2_filsys fs, const char *str, int follow) {
	ext2_ino_t ino;
	int retval = 0;
	if (follow) {
		retval = ext2fs_namei_follow(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, str, &ino);
	} else {
		retval = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, str, &ino);
	}
	if (retval) {
		return 0;
	}
	return ino;
}

ext2_ino_t get_parent_dir_ino(ext2_filsys fs, const char* path) {
	char* last_slash = strrchr((char*)path, '/');
	if (last_slash == 0) {
		return 0;
	}
	unsigned int parent_len = last_slash - path + 1;
	char* parent_path = strndup(path, parent_len);
	ext2_ino_t parent_ino = string_to_inode(fs, parent_path, 1);
	free(parent_path);
	return parent_ino;
}

char* get_filename(const char* path) {
	char* last_slash = strrchr((char*)path, (int)'/');
	if (last_slash == NULL) {
		return NULL;
	}
	char* filename = last_slash + 1;
	if (strlen(filename) == 0) {
		return NULL;
	}
	return filename;
}


errcode_t create_file(ext2_filsys fs, const char* path, unsigned int mode, ext2_ino_t* ino) {
	LOG_INFO("create file ", VALUE(path));
	// Returns a >= 0 error code
	errcode_t ret = 0;
	ext2_ino_t parent_ino = get_parent_dir_ino(fs, path);
	if (parent_ino == 0) {
		return ENOTDIR;
	}
	LOG_INFO("ext2fs_new_inode", VALUE(parent_ino));
	ret = ext2fs_new_inode(fs, parent_ino, mode, 0, ino);
	if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed to ext2fs_new_inode", VALUE(ret));
	}
	char* filename = get_filename(path);
	if (filename == NULL) {
		// This should never happen.
		return EISDIR;
	}
	ret = ext2fs_link(fs, parent_ino, filename, *ino, EXT2_FT_REG_FILE);
	if (ret == EXT2_ET_DIR_NO_SPACE) {
		ret = ext2fs_expand_dir(fs, parent_ino);
		if (ret) return ret;
		ret = ext2fs_link(fs, parent_ino, filename, *ino, EXT2_FT_REG_FILE);
	}
	if (ret) return ret;
	if (ext2fs_test_inode_bitmap2(fs->inode_map, *ino)) {
		printf("Warning: inode already set\n");
	}
	ext2fs_inode_alloc_stats2(fs, *ino, +1, 0);
	struct ext2_inode inode;
	memset(&inode, 0, sizeof(inode));
	inode.i_mode = (mode & ~LINUX_S_IFMT) | LINUX_S_IFREG;
	inode.i_atime = inode.i_ctime = inode.i_mtime = time(0);
	inode.i_links_count = 1;
	ret = ext2fs_inode_size_set(fs, &inode, 0);	// TODO: update size? also on write?
	if (ret) return ret;
	if (ext2fs_has_feature_inline_data(fs->super)) {
		inode.i_flags |= EXT4_INLINE_DATA_FL;
	} else if (ext2fs_has_feature_extents(fs->super)) {
		ext2_extent_handle_t handle;
		inode.i_flags &= ~EXT4_EXTENTS_FL;
		ret = ext2fs_extent_open2(fs, *ino, &inode, &handle);
		if (ret) return ret;
		ext2fs_extent_free(handle);
	}
	ret = ext2fs_write_new_inode(fs, *ino, &inode);
	if (ret) return ret;
	if (inode.i_flags & EXT4_INLINE_DATA_FL) {
		ret = ext2fs_inline_data_init(fs, *ino);
		if (ret) return ret;
	}
	return 0;
}

unsigned int translate_open_flags(unsigned int js_flags) {
	unsigned int result = 0;
	if (js_flags & (O_WRONLY | O_RDWR)) {
		result |= EXT2_FILE_WRITE;
	}
	if (js_flags & O_CREAT) {
		result |= EXT2_FILE_CREATE;
	}
	return result;
}


ext2_file_t do_ext2fs_open_file(ext2_filsys fs, char* path, unsigned int flags, unsigned int mode) {
	ext2_ino_t ino = string_to_inode(fs, path, !(flags & O_NOFOLLOW));
	LOG_INFO(VALUE(ino));
	errcode_t ret;
	if (ino == 0) {
		if (!(flags & O_CREAT)) {
			return nullptr;
		}
		ret = create_file(fs, path, mode, &ino);
		if (ret) {
			LOG_ERROR("failed to create file ", VALUE(ret), VALUE(path));
			return nullptr;
		}
	} else if (flags & O_EXCL) {
		return nullptr;
	}
	if ((flags & O_DIRECTORY) && ext2fs_check_directory(fs, ino)) {
		return nullptr;
	}
	ext2_file_t file;
	ret = ext2fs_file_open(fs, ino, translate_open_flags(flags), &file);
	if (ret) return nullptr;
	if (flags & O_TRUNC) {
		ret = ext2fs_file_set_size2(file, 0);
		if (ret) return nullptr;
	}
	return file;
}

int main() {
	photon::init(photon::INIT_EVENT_DEFAULT, photon::INIT_IO_DEFAULT);

	lsmt_io_manager = &struct_lsmt_manager;

	init_lsmt();

	ext2_filsys fs;
	errcode_t ret = ext2fs_open(
		"lsmt-image",
		EXT2_FLAG_RW,				// flags
		0,							// superblock
		4096,							// block_size
		lsmt_io_manager,			// manager
		&fs							// ret_fs
	);
	if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed to ext2fs_open, ret=`", ret);
	}

	ret = ext2fs_read_bitmaps(fs);
	if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed to ext2fs_read_bitmaps, ret=`", ret);
	}

	auto file = do_ext2fs_open_file(fs, "/xx", O_CREAT | O_RDWR, 0755);
	if (!file) {
		LOG_ERRNO_RETURN(0, -1, "failed to ext2fs_file_write");
	}
	char buf[4096];
	for (int i = 0; i < 4096; i++) buf[i] = 'a';
	unsigned int n;
    ret = ext2fs_file_write(file, buf, 4096, &n);
    if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed to ext2fs_file_write");
	}
	ret = ext2fs_file_flush(file);
	if (ret) {
		LOG_ERROR("failed to ext2fs_file_flush");
		return -1;
	}
	ret = ext2fs_file_close(file);
	if (ret) {
		LOG_ERROR("failed to ext2fs_file_close");
		return -1;
	}

	ret = ext2fs_close(fs);
	if (ret) {
		LOG_ERROR("failed to ext2fs_close");
		return -1;
	}

	return 0;
}