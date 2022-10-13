#include <ext2fs/ext2fs.h>
#include <utime.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <vector>
#include <sys/sysmacros.h>

#include <photon/photon.h>
#include <photon/common/alog.h>
#include <photon/common/alog-stdstring.h>
#include <photon/fs/filesystem.h>
#include <photon/fs/localfs.h>
#include <photon/fs/aligned-file.h>

#include "lsmt/file.h"
#include "zfile/zfile.h"

/*
 * Extended fields will fit into an inode if the filesystem was formatted
 * with large inodes (-I 256 or larger) and there are not currently any EAs
 * consuming all of the available space. For new inodes we always reserve
 * enough space for the kernel's known extended fields, but for inodes
 * created with an old kernel this might not have been the case. None of
 * the extended inode fields is critical for correct filesystem operation.
 * This macro checks if a certain field fits in the inode. Note that
 * inode-size = GOOD_OLD_INODE_SIZE + i_extra_isize
 */
#define EXT4_FITS_IN_INODE(ext4_inode, field)		\
	((offsetof(typeof(*ext4_inode), field) +	\
		sizeof((ext4_inode)->field))			\
	 <= ((size_t) EXT2_GOOD_OLD_INODE_SIZE +		\
			(ext4_inode)->i_extra_isize))		\

static inline __u32 ext4_encode_extra_time(const struct timespec *time) {
	__u32 extra = sizeof(time->tv_sec) > 4 ?
			((time->tv_sec - (__s32)time->tv_sec) >> 32) &
			EXT4_EPOCH_MASK : 0;
	return extra | (time->tv_nsec << EXT4_EPOCH_BITS);
}

static inline void ext4_decode_extra_time(struct timespec *time, __u32 extra) {
	if (sizeof(time->tv_sec) > 4 && (extra & EXT4_EPOCH_MASK)) {
		__u64 extra_bits = extra & EXT4_EPOCH_MASK;
		/*
		 * Prior to kernel 3.14?, we had a broken decode function,
		 * wherein we effectively did this:
		 * if (extra_bits == 3)
		 *		 extra_bits = 0;
		 */
		time->tv_sec += extra_bits << 32;
	}
	time->tv_nsec = ((extra) & EXT4_NSEC_MASK) >> EXT4_EPOCH_BITS;
}

#define EXT4_INODE_SET_XTIME(xtime, timespec, raw_inode) \
do {																										 \
	(raw_inode)->xtime = (timespec)->tv_sec;							 \
	if (EXT4_FITS_IN_INODE(raw_inode, xtime ## _extra))		\
		(raw_inode)->xtime ## _extra =											 \
				ext4_encode_extra_time(timespec);								\
} while (0)

static int __translate_error(ext2_filsys fs, errcode_t err, ext2_ino_t ino,
					 const char *file, int line);
#define translate_error(fs, ino, err) __translate_error((fs), (err), (ino), \
			__FILE__, __LINE__)

#define EXT4_INODE_GET_XTIME(xtime, timespec, raw_inode)					 \
do {												 \
	(timespec)->tv_sec = (signed)((raw_inode)->xtime);					 \
	if (EXT4_FITS_IN_INODE(raw_inode, xtime ## _extra))					 \
		ext4_decode_extra_time((timespec),						 \
							 (raw_inode)->xtime ## _extra);				 \
	else											 \
		(timespec)->tv_nsec = 0;							 \
} while (0)




static int __translate_error(ext2_filsys fs, errcode_t err, ext2_ino_t ino,
					 const char *file, int line)
{
	struct timespec now;
	int ret = err;
	int is_err = 0;

	// int disk_id = get_disk_id(fs->io);

	/* Translate ext2 error to unix error code */
	if (err < EXT2_ET_BASE)
		goto no_translation;
	switch (err) {
	case EXT2_ET_NO_MEMORY:
	case EXT2_ET_TDB_ERR_OOM:
		ret = -ENOMEM;
		break;
	case EXT2_ET_INVALID_ARGUMENT:
	case EXT2_ET_LLSEEK_FAILED:
		ret = -EINVAL;
		break;
	case EXT2_ET_NO_DIRECTORY:
		ret = -ENOTDIR;
		break;
	case EXT2_ET_FILE_NOT_FOUND:
		ret = -ENOENT;
		break;
	case EXT2_ET_DIR_NO_SPACE:
		is_err = 1;
		/* fallthrough */
	case EXT2_ET_TOOSMALL:
	case EXT2_ET_BLOCK_ALLOC_FAIL:
	case EXT2_ET_INODE_ALLOC_FAIL:
	case EXT2_ET_EA_NO_SPACE:
		ret = -ENOSPC;
		break;
	case EXT2_ET_SYMLINK_LOOP:
		ret = -EMLINK;
		break;
	case EXT2_ET_FILE_TOO_BIG:
		ret = -EFBIG;
		break;
	case EXT2_ET_TDB_ERR_EXISTS:
	case EXT2_ET_FILE_EXISTS:
		ret = -EEXIST;
		break;
	case EXT2_ET_MMP_FAILED:
	case EXT2_ET_MMP_FSCK_ON:
		ret = -EBUSY;
		break;
	case EXT2_ET_EA_KEY_NOT_FOUND:
#ifdef ENODATA
		ret = -ENODATA;
#else
		ret = -ENOENT;
#endif
		break;
	/* Sometimes fuse returns a garbage file handle pointer to us... */
	case EXT2_ET_MAGIC_EXT2_FILE:
		ret = -EFAULT;
		break;
	case EXT2_ET_UNIMPLEMENTED:
		ret = -EOPNOTSUPP;
		break;
	default:
		is_err = 1;
		ret = -EIO;
		break;
	}

no_translation:
	if (!is_err)
		return ret;

	if (ino)
		fprintf(stderr, "lsmt_ext2fs: (inode #%d) at %s:%d.", ino, file, line);
	else
		fprintf(stderr, "lsmt_ext2fs: at %s:%d.", file, line);

	ext2fs_mark_super_dirty(fs);
	ext2fs_flush(fs);

	return ret;
}

static int ext2_file_type(unsigned int mode) {
	if (LINUX_S_ISREG(mode))
		return EXT2_FT_REG_FILE;

	if (LINUX_S_ISDIR(mode))
		return EXT2_FT_DIR;

	if (LINUX_S_ISCHR(mode))
		return EXT2_FT_CHRDEV;

	if (LINUX_S_ISBLK(mode))
		return EXT2_FT_BLKDEV;

	if (LINUX_S_ISLNK(mode))
		return EXT2_FT_SYMLINK;

	if (LINUX_S_ISFIFO(mode))
		return EXT2_FT_FIFO;

	if (LINUX_S_ISSOCK(mode))
		return EXT2_FT_SOCK;

	return 0;
}

static unsigned int translate_open_flags(unsigned int js_flags) {
	unsigned int result = 0;
	if (js_flags & (O_WRONLY | O_RDWR)) {
		result |= EXT2_FILE_WRITE;
	}
	if (js_flags & O_CREAT) {
		result |= EXT2_FILE_CREATE;
	}
	return result;
}

//---------------------------------------------

static errcode_t ufs_open(const char *name, int flags, io_channel *channel);
static errcode_t ufs_close(io_channel channel);
static errcode_t set_blksize(io_channel channel, int blksize);
static errcode_t ufs_read_blk(io_channel channel, unsigned long block, int count, void *buf);
static errcode_t ufs_read_blk64(io_channel channel, unsigned long long block, int count, void *buf);
static errcode_t ufs_write_blk(io_channel channel, unsigned long block, int count, const void *buf);
static errcode_t ufs_write_blk64(io_channel channel, unsigned long long block, int count, const void *buf);
static errcode_t ufs_flush(io_channel channel);
static errcode_t ufs_discard(io_channel channel, unsigned long long block, unsigned long long count);
static errcode_t ufs_cache_readahead(io_channel channel, unsigned long long block, unsigned long long count);
static errcode_t ufs_zeroout(io_channel channel, unsigned long long block, unsigned long long count);

static struct struct_io_manager struct_lsmt_manager = {
	.magic				= EXT2_ET_MAGIC_IO_MANAGER,
	.name				= "LSMT I/O Manager",
	.open				= ufs_open,
	.close				= ufs_close,
	.set_blksize		= set_blksize,
	.read_blk			= ufs_read_blk,
	.write_blk			= ufs_write_blk,
	.flush				= ufs_flush,
	.read_blk64			= ufs_read_blk64,
	.write_blk64		= ufs_write_blk64,
	.discard			= ufs_discard,
	.cache_readahead	= ufs_cache_readahead,
	.zeroout			= ufs_zeroout,
};

photon::fs::IFile *ufs_file;

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

static errcode_t ufs_open(const char *name, int flags, io_channel *channel)
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

	io->manager = &struct_lsmt_manager;
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
	LOG_INFO("lsmt close");
	return ext2fs_free_mem(&channel);
}

static errcode_t set_blksize(io_channel channel, int blksize) {
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

int init_img() {
	char path[] = "/home/zhuangbowei.zbw/tmp/ext2fs/test.img";
	ufs_file = photon::fs::open_localfile_adaptor(path, O_RDWR, 0644, 0);
	if (!ufs_file) {
		LOG_ERRNO_RETURN(0, -1, "failed to open `", path);
	}
	return 0;
}


static ext2_ino_t string_to_inode(ext2_filsys fs, const char *str, int follow) {
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

static ext2_ino_t get_parent_dir_ino(ext2_filsys fs, const char* path) {
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

static char* get_filename(const char* path) {
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


static errcode_t create_file(ext2_filsys fs, const char* path, unsigned int mode, ext2_ino_t* ino) {
	LOG_INFO("create file ", VALUE(path));
	// Returns a >= 0 error code
	errcode_t ret = 0;
	ext2_ino_t parent_ino = get_parent_dir_ino(fs, path);
	if (parent_ino == 0) {
		return ENOTDIR;
	}
	LOG_INFO(VALUE(parent_ino));
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

static void get_now(struct timespec *now) {
#ifdef CLOCK_REALTIME
	if (!clock_gettime(CLOCK_REALTIME, now))
		return;
#endif

	now->tv_sec = time(NULL);
	now->tv_nsec = 0;
}

static void increment_version(struct ext2_inode *inode) {
	inode->osd1.linux1.l_i_version++;
}

static int update_ctime(ext2_filsys fs, ext2_ino_t ino,
			struct ext2_inode_large *pinode) {
	errcode_t err;
	struct timespec now;
	struct ext2_inode_large inode;

	get_now(&now);

	/* If user already has a inode buffer, just update that */
	if (pinode) {
	increment_version((struct ext2_inode *) &inode);
		EXT4_INODE_SET_XTIME(i_ctime, &now, pinode);
		return 0;
	}

	/* Otherwise we have to read-modify-write the inode */
	memset(&inode, 0, sizeof(inode));
	err = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&inode,
						 sizeof(inode));
	if (err)
		return translate_error(fs, ino, err);

	increment_version((struct ext2_inode *) &inode);
	EXT4_INODE_SET_XTIME(i_ctime, &now, &inode);

	err = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&inode,
							sizeof(inode));
	if (err)
		return translate_error(fs, ino, err);

	return 0;
}

static int update_atime(ext2_filsys fs, ext2_ino_t ino) {
	errcode_t err;
	struct ext2_inode_large inode, *pinode;
	struct timespec atime, mtime, now;

	if (!(fs->flags & EXT2_FLAG_RW))
		return 0;
	memset(&inode, 0, sizeof(inode));
	err = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&inode,
						 sizeof(inode));
	if (err)
		return translate_error(fs, ino, err);

	pinode = &inode;
	EXT4_INODE_GET_XTIME(i_atime, &atime, pinode);
	EXT4_INODE_GET_XTIME(i_mtime, &mtime, pinode);
	get_now(&now);
	/*
	 * If atime is newer than mtime and atime hasn't been updated in thirty
	 * seconds, skip the atime update.	Same idea as Linux "relatime".
	 */
	if (atime.tv_sec >= mtime.tv_sec && atime.tv_sec >= now.tv_sec - 30)
		return 0;
	EXT4_INODE_SET_XTIME(i_atime, &now, &inode);

	err = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&inode,
							sizeof(inode));
	if (err)
		return translate_error(fs, ino, err);

	return 0;
}

static int update_mtime(ext2_filsys fs, ext2_ino_t ino,
			struct ext2_inode_large *pinode) {
	errcode_t err;
	struct ext2_inode_large inode;
	struct timespec now;

	if (pinode) {
		get_now(&now);
		EXT4_INODE_SET_XTIME(i_mtime, &now, pinode);
		EXT4_INODE_SET_XTIME(i_ctime, &now, pinode);
		increment_version((struct ext2_inode *) pinode);
		return 0;
	}

	memset(&inode, 0, sizeof(inode));
	err = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&inode,
						 sizeof(inode));
	if (err)
		return translate_error(fs, ino, err);

	get_now(&now);
	EXT4_INODE_SET_XTIME(i_mtime, &now, &inode);
	EXT4_INODE_SET_XTIME(i_ctime, &now, &inode);
	increment_version((struct ext2_inode *) &inode);

	err = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&inode,
							sizeof(inode));
	if (err)
		return translate_error(fs, ino, err);

	return 0;
}

static errcode_t update_xtime(ext2_file_t file, bool a, bool c, bool m, struct timespec *file_time = nullptr) {
	errcode_t err = 0;
	ext2_filsys fs = ext2fs_file_get_fs(file);
	ext2_ino_t ino = ext2fs_file_get_inode_num(file);
	ext2_inode *inode = ext2fs_file_get_inode(file);
	err = ext2fs_read_inode(fs, ino, inode);
	if (err) return err;
	struct timespec now;
	if (file_time == nullptr) {
		get_now(&now);
	} else {
		now = *file_time;
	}
	if (a) {
		inode->i_atime = now.tv_sec;
	}
	if (c) {
		inode->i_ctime = now.tv_sec;
	}
	if (m) {
		inode->i_mtime = now.tv_sec;
	}
	increment_version(inode);
	err = ext2fs_write_inode(fs, ino, inode);
	return err;
}

static int remove_inode(ext2_filsys fs, ext2_ino_t ino)
{
	errcode_t err;
	struct ext2_inode_large inode;
	int ret = 0;

	memset(&inode, 0, sizeof(inode));
	err = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&inode,
						 sizeof(inode));
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out;
	}
	LOG_INFO("put ino=` links=`", ino, inode.i_links_count);

	switch (inode.i_links_count) {
	case 0:
		return 0; /* XXX: already done? */
	case 1:
		inode.i_links_count--;
		inode.i_dtime = time(0);
		break;
	default:
		inode.i_links_count--;
	}

	ret = update_ctime(fs, ino, &inode);
	if (ret)
		goto out;

	if (inode.i_links_count)
		goto write_out;

	/* Nobody holds this file; free its blocks! */
	err = ext2fs_free_ext_attr(fs, ino, &inode);
	if (err)
		goto write_out;

	if (ext2fs_inode_has_valid_blocks2(fs, (struct ext2_inode *)&inode)) {
		err = ext2fs_punch(fs, ino, (struct ext2_inode *)&inode, NULL,
					 0, ~0ULL);
		if (err) {
			ret = translate_error(fs, ino, err);
			goto write_out;
		}
	}

	ext2fs_inode_alloc_stats2(fs, ino, -1,
					LINUX_S_ISDIR(inode.i_mode));

write_out:
	err = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&inode,
							sizeof(inode));
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out;
	}
out:
	return ret;
}


//-----------------------------------------------------------------------------

ext2_file_t do_ext2fs_open_file(ext2_filsys fs, const char* path, unsigned int flags, unsigned int mode) {
	ext2_ino_t ino = string_to_inode(fs, path, !(flags & O_NOFOLLOW));
	LOG_INFO(VALUE(ino));
	errcode_t ret;
	if (ino == 0) {
		if (!(flags & O_CREAT)) {
			LOG_ERRNO_RETURN(ENOENT, nullptr, "");
		}
		ret = create_file(fs, path, mode, &ino);
		if (ret) {
			LOG_ERRNO_RETURN(-translate_error(fs, ino, ret), nullptr, "failed to create file ", VALUE(ret), VALUE(path));
		}
	} else if (flags & O_EXCL) {
		LOG_ERRNO_RETURN(EEXIST, nullptr, "");
	}
	if ((flags & O_DIRECTORY) && ext2fs_check_directory(fs, ino)) {
		LOG_ERRNO_RETURN(ENOTDIR, nullptr, "");
	}
	ext2_file_t file;
	ret = ext2fs_file_open(fs, ino, translate_open_flags(flags), &file);
	if (ret) {
		LOG_ERRNO_RETURN(-translate_error(fs, ino, ret), nullptr, "");
	}
	if (flags & O_TRUNC) {
		ret = ext2fs_file_set_size2(file, 0);
		LOG_ERRNO_RETURN(-translate_error(fs, ino, ret), nullptr, "");
	}
	return file;
}

long do_ext2fs_read(
	ext2_file_t file,
	int flags,
	char *buffer,
	unsigned long count,	// requested count
	unsigned long offset	// offset in file, -1 for current offset
) {
	errcode_t ret = 0;
	if ((flags & O_WRONLY) != 0) {
		// Don't try to read write only files.
		return -EBADF;
	}
	if (offset != -1) {
		ret = ext2fs_file_llseek(file, offset, EXT2_SEEK_SET, NULL);
		if (ret) return -ret;
	}
	unsigned int got;
	ret = ext2fs_file_read(file, buffer, count, &got);
	if (ret) return -ret;
	if ((flags & O_NOATIME) == 0) {
		ret = update_xtime(file, true, false, false);
		if (ret) return -ret;
	}
	return got;
}

long do_ext2fs_write(
	ext2_file_t file,
	int flags,
	const char *buffer,
	unsigned long count,	// requested count
	unsigned long offset	// offset in file, -1 for current offset
) {
	if ((flags & (O_WRONLY | O_RDWR)) == 0) {
		// Don't try to write to readonly files.
		return -EBADF;
	}
	errcode_t ret = 0;
	if ((flags & O_APPEND) != 0) {
		// append mode: seek to the end before each write
		ret = ext2fs_file_llseek(file, 0, EXT2_SEEK_END, NULL);
	} else if (offset != -1) {
		ret = ext2fs_file_llseek(file, offset, EXT2_SEEK_SET, NULL);
	}

	if (ret) return -ret;
	unsigned int written;
	ret = ext2fs_file_write(file, buffer, count, &written);
	if (ret) return -ret;
	ret = update_xtime(file, false, true, true);
	if (ret) return -ret;

	ret = ext2fs_file_flush(file);
	if (ret) {
		return translate_error(ext2fs_file_get_fs(file), ext2fs_file_get_inode_num(file), ret);
	}

	return written;
}

static int unlink_file_by_name(ext2_filsys fs, const char *path) {
	errcode_t err;
	ext2_ino_t dir;
	char *filename = strdup(path);
	char *base_name;
	int ret;

	base_name = strrchr(filename, '/');
	if (base_name) {
		*base_name++ = '\0';
		err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, filename,
					 &dir);
		if (err) {
			free(filename);
			return translate_error(fs, 0, err);
		}
	} else {
		dir = EXT2_ROOT_INO;
		base_name = filename;
	}

	LOG_INFO("unlinking name=` from dir=`", base_name, dir);
	err = ext2fs_unlink(fs, dir, base_name, 0, 0);
	free(filename);
	if (err)
		return translate_error(fs, dir, err);

	return update_mtime(fs, dir, NULL);
}

errcode_t do_ext2fs_unlink(ext2_filsys fs, const char *path) {
	ext2_ino_t ino;
	errcode_t err;
	int ret = 0;

	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino);
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out;
	}

	if (ext2fs_check_directory(fs, ino) == 0) {
		return -EISDIR;
	}

	ret = unlink_file_by_name(fs, path);
	if (ret)
		goto out;

	ret = remove_inode(fs, ino);

out:
	return ret;
}

errcode_t do_ext2fs_mkdir(
	ext2_filsys fs,
	const char *path,
	int mode
) {
	ext2_ino_t parent_ino = get_parent_dir_ino(fs, path);
	LOG_INFO(VALUE(parent_ino));
	if (parent_ino == 0) {
		return -ENOTDIR;
	}
	char* filename = get_filename(path);
	if (filename == NULL) {
		// This should never happen.
		return -EISDIR;
	}
	LOG_INFO(VALUE(filename));
	ext2_ino_t newdir;
	errcode_t ret;
	ret = ext2fs_new_inode(
		fs,
		parent_ino,
		LINUX_S_IFDIR,
		NULL,
		&newdir
	);
	if (ret) return -ret;
	LOG_INFO(VALUE(newdir));
	ret = ext2fs_mkdir(fs, parent_ino, newdir, filename);
	if (ret) return -ret;
	struct ext2_inode inode;
	ret = ext2fs_read_inode(fs, newdir, &inode);
 if (ret) return -ret;
	inode.i_mode = (mode & ~LINUX_S_IFMT) | LINUX_S_IFDIR;
	ret = ext2fs_write_inode(fs, newdir, &inode);
	return -ret;
}

struct rd_struct {
	ext2_ino_t	parent;
	int		empty;
};

static int rmdir_proc(
	ext2_ino_t dir,
	int	entry,
	struct ext2_dir_entry *dirent,
	int	offset,
	int	blocksize,
	char	*buf,
	void	*priv_data
) {
	struct rd_struct *rds = (struct rd_struct *) priv_data;

	if (dirent->inode == 0)
		return 0;
	if (((dirent->name_len & 0xFF) == 1) && (dirent->name[0] == '.'))
		return 0;
	if (((dirent->name_len & 0xFF) == 2) && (dirent->name[0] == '.') &&
			(dirent->name[1] == '.')) {
		rds->parent = dirent->inode;
		return 0;
	}
	rds->empty = 0;
	return 0;
}

errcode_t do_ext2fs_rmdir(ext2_filsys fs, const char *path) {
	ext2_ino_t child;
	errcode_t err;
	struct ext2_inode_large inode;
	struct rd_struct rds;
	int ret = 0;

	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &child);
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out;
	}

	LOG_INFO("rmdir path=` ino=`", path, child);

	rds.parent = 0;
	rds.empty = 1;

	err = ext2fs_dir_iterate2(fs, child, 0, 0, rmdir_proc, &rds);
	if (err) {
		ret = translate_error(fs, child, err);
		goto out;
	}

	if (rds.empty == 0) {
		ret = -ENOTEMPTY;
		goto out;
	}

	ret = unlink_file_by_name(fs, path);
	if (ret)
		goto out;
	/* Directories have to be "removed" twice. */
	ret = remove_inode(fs, child);
	if (ret)
		goto out;
	ret = remove_inode(fs, child);
	if (ret)
		goto out;

	if (rds.parent) {
		LOG_INFO("decr dir=` link count", rds.parent);
		err = ext2fs_read_inode_full(fs, rds.parent,
							 (struct ext2_inode *)&inode,
							 sizeof(inode));
		if (err) {
			ret = translate_error(fs, rds.parent, err);
			goto out;
		}
		if (inode.i_links_count > 1)
			inode.i_links_count--;
		ret = update_mtime(fs, rds.parent, &inode);
		if (ret)
			goto out;
		err = ext2fs_write_inode_full(fs, rds.parent,
								(struct ext2_inode *)&inode,
								sizeof(inode));
		if (err) {
			ret = translate_error(fs, rds.parent, err);
			goto out;
		}
	}

out:
	return ret;
}

struct update_dotdot {
	ext2_ino_t new_dotdot;
};

static int update_dotdot_helper(
	ext2_ino_t dir,
	int entry,
	struct ext2_dir_entry *dirent,
	int offset,
	int blocksize,
	char *buf,
	void *priv_data
) {
	struct update_dotdot *ud = (struct update_dotdot *) priv_data;

	if (ext2fs_dirent_name_len(dirent) == 2 &&
			dirent->name[0] == '.' && dirent->name[1] == '.') {
		dirent->inode = ud->new_dotdot;
		return DIRENT_CHANGED | DIRENT_ABORT;
	}

	return 0;
}

errcode_t do_ext2fs_rename(ext2_filsys fs, const char *from, const char *to) {
	errcode_t err;
	ext2_ino_t from_ino, to_ino, to_dir_ino, from_dir_ino;
	char *temp_to = NULL, *temp_from = NULL;
	char *cp, a;
	struct ext2_inode inode;
	struct update_dotdot ud;
	int ret = 0;

	LOG_INFO("renaming ` to `", from, to);

	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, from, &from_ino);
	if (err || from_ino == 0) {
		ret = translate_error(fs, 0, err);
		goto out;
	}

	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, to, &to_ino);
	if (err && err != EXT2_ET_FILE_NOT_FOUND) {
		ret = translate_error(fs, 0, err);
		goto out;
	}

	if (err == EXT2_ET_FILE_NOT_FOUND)
		to_ino = 0;

	/* Already the same file? */
	if (to_ino != 0 && to_ino == from_ino) {
		ret = 0;
		goto out;
	}

	temp_to = strdup(to);
	if (!temp_to) {
		ret = -ENOMEM;
		goto out;
	}

	temp_from = strdup(from);
	if (!temp_from) {
		ret = -ENOMEM;
		goto out2;
	}

	/* Find parent dir of the source and check write access */
	cp = strrchr(temp_from, '/');
	if (!cp) {
		ret = -EINVAL;
		goto out2;
	}

	a = *(cp + 1);
	*(cp + 1) = 0;
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, temp_from,
				 &from_dir_ino);
	*(cp + 1) = a;
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out2;
	}
	if (from_dir_ino == 0) {
		ret = -ENOENT;
		goto out2;
	}

	/* Find parent dir of the destination and check write access */
	cp = strrchr(temp_to, '/');
	if (!cp) {
		ret = -EINVAL;
		goto out2;
	}

	a = *(cp + 1);
	*(cp + 1) = 0;
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, temp_to,
				 &to_dir_ino);
	*(cp + 1) = a;
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out2;
	}
	if (to_dir_ino == 0) {
		ret = -ENOENT;
		goto out2;
	}

	/* If the target exists, unlink it first */
	if (to_ino != 0) {
		err = ext2fs_read_inode(fs, to_ino, &inode);
		if (err) {
			ret = translate_error(fs, to_ino, err);
			goto out2;
		}

		LOG_INFO("unlinking ` ino=`",
				 LINUX_S_ISDIR(inode.i_mode) ? "dir" : "file",
				 to_ino);
		if (LINUX_S_ISDIR(inode.i_mode))
			ret = do_ext2fs_rmdir(fs, to);
		else
			ret = do_ext2fs_unlink(fs, to);
		if (ret)
			goto out2;
	}

	/* Get ready to do the move */
	err = ext2fs_read_inode(fs, from_ino, &inode);
	if (err) {
		ret = translate_error(fs, from_ino, err);
		goto out2;
	}

	/* Link in the new file */
	LOG_INFO("linking ino=`/path=` to dir=`", from_ino, cp + 1, to_dir_ino);
	err = ext2fs_link(fs, to_dir_ino, cp + 1, from_ino,
				ext2_file_type(inode.i_mode));
	if (err == EXT2_ET_DIR_NO_SPACE) {
		err = ext2fs_expand_dir(fs, to_dir_ino);
		if (err) {
			ret = translate_error(fs, to_dir_ino, err);
			goto out2;
		}

		err = ext2fs_link(fs, to_dir_ino, cp + 1, from_ino,
						 ext2_file_type(inode.i_mode));
	}
	if (err) {
		ret = translate_error(fs, to_dir_ino, err);
		goto out2;
	}

	/* Update '..' pointer if dir */
	err = ext2fs_read_inode(fs, from_ino, &inode);
	if (err) {
		ret = translate_error(fs, from_ino, err);
		goto out2;
	}

	if (LINUX_S_ISDIR(inode.i_mode)) {
		ud.new_dotdot = to_dir_ino;
		LOG_INFO("updating .. entry for dir=`", to_dir_ino);
		err = ext2fs_dir_iterate2(fs, from_ino, 0, NULL,
						update_dotdot_helper, &ud);
		if (err) {
			ret = translate_error(fs, from_ino, err);
			goto out2;
		}

		/* Decrease from_dir_ino's links_count */
		LOG_INFO("moving linkcount from dir=` to dir=`",from_dir_ino, to_dir_ino);
		err = ext2fs_read_inode(fs, from_dir_ino, &inode);
		if (err) {
			ret = translate_error(fs, from_dir_ino, err);
			goto out2;
		}
		inode.i_links_count--;
		err = ext2fs_write_inode(fs, from_dir_ino, &inode);
		if (err) {
			ret = translate_error(fs, from_dir_ino, err);
			goto out2;
		}

		/* Increase to_dir_ino's links_count */
		err = ext2fs_read_inode(fs, to_dir_ino, &inode);
		if (err) {
			ret = translate_error(fs, to_dir_ino, err);
			goto out2;
		}
		inode.i_links_count++;
		err = ext2fs_write_inode(fs, to_dir_ino, &inode);
		if (err) {
			ret = translate_error(fs, to_dir_ino, err);
			goto out2;
		}
	}

	/* Update timestamps */
	ret = update_ctime(fs, from_ino, NULL);
	if (ret)
		goto out2;

	ret = update_mtime(fs, to_dir_ino, NULL);
	if (ret)
		goto out2;

	/* Remove the old file */
	ret = unlink_file_by_name(fs, from);
	if (ret)
		goto out2;

	/* Flush the whole mess out */
	err = ext2fs_flush2(fs, 0);
	if (err)
		ret = translate_error(fs, 0, err);

out2:
	free(temp_from);
	free(temp_to);
out:
	return ret;
}

errcode_t do_ext2fs_link(ext2_filsys fs, const char *src, const char *dest)
{
	char *temp_path;
	errcode_t err;
	char *node_name, a;
	ext2_ino_t parent, ino;
	struct ext2_inode_large inode;
	int ret = 0;

	LOG_INFO("src=` dest=`", src, dest);
	temp_path = strdup(dest);
	if (!temp_path) {
		ret = -ENOMEM;
		goto out;
	}
	node_name = strrchr(temp_path, '/');
	if (!node_name) {
		ret = -ENOMEM;
		goto out;
	}
	node_name++;
	a = *node_name;
	*node_name = 0;

	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, temp_path, &parent);
	*node_name = a;
	if (err) {
		err = -ENOENT;
		goto out;
	}


	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, src, &ino);
	if (err || ino == 0) {
		ret = translate_error(fs, 0, err);
		goto out;
	}

	memset(&inode, 0, sizeof(inode));
	err = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&inode, sizeof(inode));
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out;
	}

	inode.i_links_count++;
	ret = update_ctime(fs, ino, &inode);
	if (ret)
		goto out;

	err = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&inode, sizeof(inode));
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out;
	}

	LOG_INFO("linking ino=`/name=` to dir=`", ino, node_name, parent);
	err = ext2fs_link(fs, parent, node_name, ino, ext2_file_type(inode.i_mode));
	if (err == EXT2_ET_DIR_NO_SPACE) {
		err = ext2fs_expand_dir(fs, parent);
		if (err) {
			ret = translate_error(fs, parent, err);
			goto out;
		}

		err = ext2fs_link(fs, parent, node_name, ino, ext2_file_type(inode.i_mode));
	}
	if (err) {
		ret = translate_error(fs, parent, err);
		goto out;
	}

	ret = update_mtime(fs, parent, NULL);
	if (ret)
		goto out;

out:
	free(temp_path);
	return ret;
}

int do_ext2fs_symlink(ext2_filsys fs, const char *src, const char *dest) {
	ext2_ino_t parent, child;
	char *temp_path;
	errcode_t err;
	char *node_name, a;
	struct ext2_inode_large inode;
	int ret = 0;

	LOG_INFO("symlink ` to `", src, dest);
	temp_path = strdup(dest);
	if (!temp_path) {
		ret = -ENOMEM;
		goto out;
	}
	node_name = strrchr(temp_path, '/');
	if (!node_name) {
		ret = -ENOMEM;
		goto out;
	}
	node_name++;
	a = *node_name;
	*node_name = 0;

	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, temp_path,
				 &parent);
	*node_name = a;
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out;
	}
	LOG_INFO(VALUE(parent));

	/* Create symlink */
	err = ext2fs_symlink(fs, parent, 0, node_name, src);
	if (err == EXT2_ET_DIR_NO_SPACE) {
		err = ext2fs_expand_dir(fs, parent);
		if (err) {
			ret = translate_error(fs, parent, err);
			goto out;
		}

		err = ext2fs_symlink(fs, parent, 0, node_name, src);
	}
	if (err) {
		ret = translate_error(fs, parent, err);
		goto out;
	}

	/* Update parent dir's mtime */
	ret = update_mtime(fs, parent, NULL);
	if (ret)
		goto out;

	/* Still have to update the uid/gid of the symlink */
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, temp_path,
				 &child);
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out;
	}
	LOG_INFO("symlinking ino=`/name=` to dir=`", child, node_name, parent);

	memset(&inode, 0, sizeof(inode));
	err = ext2fs_read_inode_full(fs, child, (struct ext2_inode *)&inode,
						 sizeof(inode));
	if (err) {
		ret = translate_error(fs, child, err);
		goto out;
	}

	err = ext2fs_write_inode_full(fs, child, (struct ext2_inode *)&inode,
							sizeof(inode));
	if (err) {
		ret = translate_error(fs, child, err);
		goto out;
	}
out:
	free(temp_path);
	return ret;
}

errcode_t do_ext2fs_chmod(ext2_file_t file, int mode) {
	ext2_filsys fs = ext2fs_file_get_fs(file);
	ext2_ino_t ino = ext2fs_file_get_inode_num(file);
	ext2_inode *inode = ext2fs_file_get_inode(file);
	errcode_t ret = ext2fs_read_inode(fs, ino, inode);
	if (ret) return -ret;
	// keep only fmt (file or directory)
	inode->i_mode &= LINUX_S_IFMT;
	// apply new mode
	inode->i_mode |= (mode & ~LINUX_S_IFMT);
	increment_version(inode);
	ret = ext2fs_write_inode(fs, ino, inode);
	return -ret;
}

errcode_t do_ext2fs_chown(
	ext2_file_t file,
	int uid,
	int gid
) {
	ext2_filsys fs = ext2fs_file_get_fs(file);
	ext2_ino_t ino = ext2fs_file_get_inode_num(file);
	ext2_inode *inode = ext2fs_file_get_inode(file);
	// TODO handle 32 bit {u,g}ids
	errcode_t ret = ext2fs_read_inode(fs, ino, inode);
	if (ret) return -ret;
	// keep only the lower 16 bits
	inode->i_uid = uid & 0xFFFF;
	ext2fs_set_i_uid_high(*inode, uid >> 16);
	inode->i_gid = gid & 0xFFFF;
	ext2fs_set_i_gid_high(*inode, gid >> 16);
	increment_version(inode);
	ret = ext2fs_write_inode(fs, ino, inode);
	return -ret;
}

errcode_t do_ext2fs_mknod(ext2_filsys fs, const char *path,
			    unsigned int st_mode, unsigned int st_rdev)
{
	ext2_ino_t		ino;
	errcode_t		retval;
	struct ext2_inode	inode;
	unsigned long		devmajor, devminor, mode;
	int			filetype;

	ino = string_to_inode(fs, path, 0);
	if (ino) {
		return -EEXIST;
	}

	ext2_ino_t parent_ino = get_parent_dir_ino(fs, path);
	if (parent_ino == 0) {
		return -ENOTDIR;
	}
	char *filename = get_filename(path);
	if (filename == NULL) {
		return -EISDIR;
	}

	switch(st_mode & S_IFMT) {
	case S_IFCHR:
		mode = LINUX_S_IFCHR;
		filetype = EXT2_FT_CHRDEV;
		break;
	case S_IFBLK:
		mode = LINUX_S_IFBLK;
		filetype =  EXT2_FT_BLKDEV;
		break;
	case S_IFIFO:
		mode = LINUX_S_IFIFO;
		filetype = EXT2_FT_FIFO;
		break;
#ifndef _WIN32
	case S_IFSOCK:
		mode = LINUX_S_IFSOCK;
		filetype = EXT2_FT_SOCK;
		break;
#endif
	default:
		return EXT2_ET_INVALID_ARGUMENT;
	}

	retval = ext2fs_new_inode(fs, parent_ino, 010755, 0, &ino);
	if (retval) {
		LOG_ERROR("while allocating inode \"`\"", filename);
		return retval;
	}
	LOG_INFO(VALUE(ino));

#ifdef DEBUGFS
	printf("Allocated inode: %u\n", ino);
#endif
	retval = ext2fs_link(fs, parent_ino, filename, ino, filetype);
	if (retval == EXT2_ET_DIR_NO_SPACE) {
		retval = ext2fs_expand_dir(fs, parent_ino);
		if (retval) {
			LOG_ERROR("while expanding directory");
			return retval;
		}
		retval = ext2fs_link(fs, parent_ino, filename, ino, filetype);
	}
	if (retval) {
		LOG_ERROR("while creating inode \"`\"", filename);
		return retval;
	}
	if (ext2fs_test_inode_bitmap2(fs->inode_map, ino))
		LOG_ERROR("Warning: inode already set");
	ext2fs_inode_alloc_stats2(fs, ino, +1, 0);
	memset(&inode, 0, sizeof(inode));
	inode.i_mode = st_mode;
	inode.i_atime = inode.i_ctime = inode.i_mtime =
		fs->now ? fs->now : time(0);

	if (filetype != S_IFIFO) {
		devmajor = major(st_rdev);
		devminor = minor(st_rdev);

		if ((devmajor < 256) && (devminor < 256)) {
			inode.i_block[0] = devmajor * 256 + devminor;
			inode.i_block[1] = 0;
		} else {
			inode.i_block[0] = 0;
			inode.i_block[1] = (devminor & 0xff) | (devmajor << 8) |
					   ((devminor & ~0xff) << 12);
		}
	}
	inode.i_links_count = 1;

	retval = ext2fs_write_new_inode(fs, ino, &inode);
	if (retval)
		LOG_ERROR("while writing inode `", ino);

	return retval;
}

int test() {
	photon::init(photon::INIT_EVENT_DEFAULT, photon::INIT_IO_DEFAULT);
	set_log_output_level(1);

	// init_lsmt();
	init_img();

	ext2_filsys fs;
	errcode_t ret = ext2fs_open(
		"lsmt-image",
		EXT2_FLAG_RW,				// flags
		0,							// superblock
		4096,						// block_size
		&struct_lsmt_manager,		// manager
		&fs							// ret_fs
	);
	if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed to ext2fs_open, ret=`", ret);
	}

	ret = ext2fs_read_bitmaps(fs);
	if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed ext2fs_read_bitmaps, ret=`", ret);
	}

	// ret = do_ext2fs_mknod(fs, "/testblk-1", S_IFBLK | 0644, makedev(240, 0));
	// if (ret) {
	// 	LOG_ERRNO_RETURN(0, -1, "failed do_ext2fs_mknod, ret=`", ret);
	// }

	// ret = do_ext2fs_rename(fs, "/todir", "/toodir");
	// if (ret) {
	// 	LOG_ERRNO_RETURN(0, -1, "failed rename, ret=`", ret);
	// }

	// ret = do_ext2fs_unlink(fs, "/xx");
	// if (ret) {
	// 	LOG_ERRNO_RETURN(0, -1, "failed do_ext2fs_unlink");
	// }

	ext2_file_t file = do_ext2fs_open_file(fs, "/to", 0, 0644);
	if (!file) {
		LOG_ERRNO_RETURN(0, -1, "failed to do_ext2fs_open_file, ret=`", (errcode_t) file);
	}

	// LOG_INFO(VALUE(1377514 & 0xFFFF));
	// ret = do_ext2fs_chown(file, 1377514, 100);
	// if (ret) {
	// 	LOG_ERRNO_RETURN(0, -1, "failed do_ext2fs_chown, ret=`", ret);
	// }

	// ret = do_ext2fs_chmod(file, 0755);
	// if (ret) {
	// 	LOG_ERRNO_RETURN(0, -1, "failed do_ext2fs_chmod, ret=`", ret);
	// }

	// ret = do_ext2fs_symlink(fs, "/todir", "/xxdir");
	// if (ret) {
	// 	LOG_ERRNO_RETURN(0, -1, "failed do_ext2fs_symlink, ret=`", ret);
	// }

	char buf[4096];
	for (int i = 0; i < 5; i++) buf[i] = 'y';
	long n = do_ext2fs_write(file, O_RDWR | O_APPEND, buf, 5, 0);
    if (n < 0) {
		LOG_ERRNO_RETURN(0, -1, "failed to do_ext2fs_write");
	}
	LOG_INFO("write ` bytes", n);

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

class UserSpaceFile : public photon::fs::IFile {
	public:
		UserSpaceFile(ext2_file_t _file) :file(_file) {}

		~UserSpaceFile() {
			close();
		}

		ssize_t pread(void *buf, size_t count, off_t offset) override {
			return do_ext2fs_read(file, O_RDONLY, (char *) buf, count, offset);
		}
		ssize_t pwrite(const void *buf, size_t count, off_t offset) override {
			return do_ext2fs_write(file, O_RDWR, (const char *) buf, count, offset);
		}
		int fchmod(mode_t mode) override {
			return do_ext2fs_chmod(file, mode);
		}
		int fchown(uid_t owner, gid_t group) override {
			return do_ext2fs_chown(file, owner, group);
		}
		int close() override {
			return ext2fs_file_close(file);
		}

		UNIMPLEMENTED_POINTER(IFileSystem* filesystem() override);
		UNIMPLEMENTED(ssize_t preadv(const struct iovec *iov, int iovcnt, off_t offset) override);
        UNIMPLEMENTED(ssize_t pwritev(const struct iovec *iov, int iovcnt, off_t offset) override);
		UNIMPLEMENTED(off_t lseek(off_t offset, int whence) override);
		UNIMPLEMENTED(int fsync() override);
        UNIMPLEMENTED(int fdatasync() override);
        UNIMPLEMENTED(int fstat(struct stat *buf) override);
        UNIMPLEMENTED(int ftruncate(off_t length) override);
		UNIMPLEMENTED(ssize_t read(void *buf, size_t count) override);
		UNIMPLEMENTED(ssize_t readv(const struct iovec *iov, int iovcnt) override);
		UNIMPLEMENTED(ssize_t write(const void *buf, size_t count) override);
    	UNIMPLEMENTED(ssize_t writev(const struct iovec *iov, int iovcnt) override);
	private:
		ext2_file_t file;
};

class UserSpaceFileSystem : public photon::fs::IFileSystem {
    public:
		UserSpaceFileSystem(IFile *_image_file) {
			ufs_file = _image_file;
			errcode_t ret = ext2fs_open(
				"lsmt-image",
				EXT2_FLAG_RW,				// flags
				0,							// superblock
				4096,						// block_size
				&struct_lsmt_manager,		// manager
				&fs							// ret_fs
			);
			if (ret) {
				LOG_ERROR("failed ext2fs_open, ret=`", ret);
				return;
			}
			ret = ext2fs_read_bitmaps(fs);
			if (ret) {
				LOG_ERROR("failed ext2fs_read_bitmaps, ret=`", ret);
				return;
			}
		}
		~UserSpaceFileSystem() {
			ext2fs_close(fs);
		}
		IFile* open(const char *pathname, int flags, mode_t mode) override {
			ext2_file_t file = do_ext2fs_open_file(fs, pathname, flags, mode);
			if (!file) {
				return nullptr;
			}
			return new UserSpaceFile(file);
		}
		IFile* open(const char *pathname, int flags) override {
			return open(pathname, flags, 0666);
		}

		int mkdir(const char *pathname, mode_t mode) override {
			return do_ext2fs_mkdir(fs, pathname, mode);
		}
		int rmdir(const char *pathname) override {
			return do_ext2fs_rmdir(fs, pathname);
		}
		int symlink(const char *oldname, const char *newname) override {
			return do_ext2fs_symlink(fs, oldname, newname);
		}
		int link(const char *oldname, const char *newname) override{
			return do_ext2fs_link(fs, oldname, newname);
		}
		int rename(const char *oldname, const char *newname) override{
			return do_ext2fs_rename(fs, oldname, newname);
		}
		int unlink(const char *filename) override{
			return do_ext2fs_unlink(fs, filename);
		}
		int mknod(const char *path, mode_t mode, dev_t dev) override{
			return do_ext2fs_mknod(fs, path, mode, dev);
		}
		int utime(const char *path, const struct utimbuf *file_times) override{
			ext2_file_t file = do_ext2fs_open_file(fs, path, O_RDWR, 0666);
			timespec tm{};
			if (!file) {
				return -1;
			}
			tm.tv_sec = file_times->actime;
			update_xtime(file, true, false, false, &tm);
			tm.tv_sec = file_times->modtime;
			update_xtime(file, false, false, true, &tm);
			update_xtime(file, false, true, false);
			return 0;
		}
		int utimes(const char *path, const struct timeval tv[2]) override{
			return 0;
		}
		int lutimes(const char *path, const struct timeval tv[2]) override{
			ext2_file_t file = do_ext2fs_open_file(fs, path, O_RDWR | O_NOFOLLOW, 0666);
			timespec tm{};
			if (!file) {
				return -1;
			}
			tm = {tv[0].tv_sec, tv[0].tv_usec};
			update_xtime(file, true, false, false, &tm);
			tm = {tv[1].tv_sec, tv[1].tv_usec};
			update_xtime(file, false, false, true, &tm);
			update_xtime(file, false, true, false);
			return 0;
		}
		int chown(const char *pathname, uid_t owner, gid_t group) override{
			IFile *file = this->open(pathname, 0);
			if (file == nullptr) {
				return -1;
			}
			DEFER({delete file;});
			return file->fchown(owner, group);
		}
		int lchown(const char *pathname, uid_t owner, gid_t group) override{
			IFile *file = this->open(pathname, O_NOFOLLOW);
			if (file == nullptr) {
				return -1;
			}
			DEFER({delete file;});
			return file->fchown(owner, group);
		}
		int chmod(const char *pathname, mode_t mode) override {
			IFile *file = this->open(pathname, O_NOFOLLOW);
			if (file == nullptr) {
				return -1;
			}
			DEFER({delete file;});
			return file->fchmod(mode);
		}

		IFileSystem* filesystem() {
			return this;
		}

		UNIMPLEMENTED_POINTER(IFile *creat(const char *, mode_t) override);
		UNIMPLEMENTED(ssize_t readlink(const char *filename, char *buf, size_t bufsize) override);
		UNIMPLEMENTED(int statfs(const char *path, struct statfs *buf) override);
    	UNIMPLEMENTED(int statvfs(const char *path, struct statvfs *buf) override);
		UNIMPLEMENTED(int lstat(const char *path, struct stat *buf) override);
		UNIMPLEMENTED(int stat(const char *path, struct stat *buf) override);
		UNIMPLEMENTED(int access(const char *pathname, int mode) override);
    	UNIMPLEMENTED(int truncate(const char *path, off_t length) override);
		UNIMPLEMENTED(int syncfs() override);
		UNIMPLEMENTED_POINTER(DIR *opendir(const char *) override);
	private:
		ext2_filsys fs;
};


photon::fs::IFileSystem* new_userspace_fs(photon::fs::IFile *file) {
	return new UserSpaceFileSystem(file);
}