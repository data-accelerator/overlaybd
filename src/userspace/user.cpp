#include "user.h"
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

#include "ext2_utils.h"
#include "lsmt/file.h"
#include "zfile/zfile.h"

struct struct_ext2_filsys *fs;

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

errcode_t do_ext2fs_mkdir(ext2_filsys fs, const char *path, int mode) {
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

errcode_t do_ext2fs_link(ext2_filsys fs, const char *src, const char *dest) {
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

errcode_t do_ext2fs_chown(ext2_file_t file, int uid, int gid) {
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

errcode_t do_ext2fs_mknod(ext2_filsys fs, const char *path, unsigned int st_mode, unsigned int st_rdev) {
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

int do_ext2fs_stat(ext2_filsys fs, ext2_ino_t ino, struct stat *statbuf) {
	struct ext2_inode_large inode;
	dev_t fakedev = 0;
	errcode_t err;
	int ret = 0;
	struct timespec tv;

	memset(&inode, 0, sizeof(inode));
	err = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&inode,
				     sizeof(inode));
	if (err)
		return translate_error(fs, ino, err);

	memcpy(&fakedev, fs->super->s_uuid, sizeof(fakedev));
	statbuf->st_dev = fakedev;
	statbuf->st_ino = ino;
	statbuf->st_mode = inode.i_mode;
	statbuf->st_nlink = inode.i_links_count;
	statbuf->st_uid = inode_uid(inode);
	statbuf->st_gid = inode_gid(inode);
	statbuf->st_size = EXT2_I_SIZE(&inode);
	statbuf->st_blksize = fs->blocksize;
	statbuf->st_blocks = ext2fs_get_stat_i_blocks(fs,
						(struct ext2_inode *)&inode);
	EXT4_INODE_GET_XTIME(i_atime, &tv, &inode);
	statbuf->st_atime = tv.tv_sec;
	EXT4_INODE_GET_XTIME(i_mtime, &tv, &inode);
	statbuf->st_mtime = tv.tv_sec;
	EXT4_INODE_GET_XTIME(i_ctime, &tv, &inode);
	statbuf->st_ctime = tv.tv_sec;
	if (LINUX_S_ISCHR(inode.i_mode) ||
	    LINUX_S_ISBLK(inode.i_mode)) {
		if (inode.i_block[0])
			statbuf->st_rdev = inode.i_block[0];
		else
			statbuf->st_rdev = inode.i_block[1];
	}

	return ret;
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
				&struct_ufs_manager,		// io manager
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
			DEFER(ext2fs_file_close(file));
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
			DEFER(ext2fs_file_close(file));
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
		int stat(const char *path, struct stat *buf) override{
			ext2_ino_t ino = string_to_inode(fs, path, 1);
			if (!ino) {
				return -1;
			}
			return do_ext2fs_stat(fs, ino, buf);
		}
		int lstat(const char *path, struct stat *buf) override{
			ext2_ino_t ino = string_to_inode(fs, path, 0);
			if (!ino) {
				return -1;
			}
			return do_ext2fs_stat(fs, ino, buf);
		}

		IFileSystem* filesystem() {
			return this;
		}

		UNIMPLEMENTED_POINTER(IFile *creat(const char *, mode_t) override);
		UNIMPLEMENTED(ssize_t readlink(const char *filename, char *buf, size_t bufsize) override);
		UNIMPLEMENTED(int statfs(const char *path, struct statfs *buf) override);
    	UNIMPLEMENTED(int statvfs(const char *path, struct statvfs *buf) override);
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