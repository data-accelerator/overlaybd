#include "../user.h"
#include <fcntl.h>
#include <photon/photon.h>
#include <photon/fs/localfs.h>


int init_img() {
	char path[] = "/home/zhuangbowei.zbw/tmp/ext2fs/test.img";
	ufs_file = photon::fs::open_localfile_adaptor(path, O_RDWR, 0644, 0);
	if (!ufs_file) {
		LOG_ERRNO_RETURN(0, -1, "failed to open `", path);
	}
	return 0;
}

int test() {
	init_img();

	ext2_filsys fs;
	errcode_t ret = ext2fs_open(
		"lsmt-image",
		EXT2_FLAG_RW,				// flags
		0,							// superblock
		4096,						// block_size
		&struct_ufs_manager,		// io manager
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

	ext2_file_t file = (ext2_file_t) do_ext2fs_open_file(fs, "/toodir/yy", O_CREAT | O_RDWR, 0644);
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

int main(int argc, char **argv) {
	photon::init(photon::INIT_EVENT_DEFAULT, photon::INIT_IO_DEFAULT);
	set_log_output_level(1);

	test();

	return 0;
}