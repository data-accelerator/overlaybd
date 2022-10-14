#include "../user.h"
#include <fcntl.h>
#include <photon/photon.h>
#include <photon/fs/localfs.h>

void print_stat(struct stat *st) {
	LOG_INFO(VALUE(st->st_ino), VALUE(st->st_size), VALUE(st->st_nlink));
	char st_mode[10];
	sprintf(st_mode, "%07o", st->st_mode);
	LOG_INFO(VALUE(st_mode));
	LOG_INFO("atime: `", asctime(localtime(&(st->st_atim.tv_sec))));
	LOG_INFO("ctime: `", asctime(localtime(&(st->st_ctim.tv_sec))));
	LOG_INFO("mtime: `", asctime(localtime(&(st->st_mtim.tv_sec))));
}

int test() {
	char path[] = "/home/zhuangbowei.zbw/tmp/ext2fs/test.img";
	photon::fs::IFile *image_file = photon::fs::open_localfile_adaptor(path, O_RDWR, 0644, 0);
	if (!image_file) {
		LOG_ERRNO_RETURN(0, -1, "failed to open `", path);
	}
	photon::fs::IFileSystem *fs = new_userspace_fs(image_file);
	if (!fs) {
		LOG_ERRNO_RETURN(0, -1, "failed open fs");
	}
	DEFER({delete fs;});
	photon::fs::IFile *file = fs->open("/to", O_RDONLY);
	if (!file) {
		LOG_ERRNO_RETURN(0, -1, "failed open file");
	}
	DEFER({delete file;});
	char buf[10];
	int ret = file->pread(buf, 5, 0);
	buf[5] = '\0';
	if (ret < 0) {
		LOG_ERRNO_RETURN(-ret, -1, "failed read file");
	}
	LOG_INFO("read ` bytes: `", ret, buf);

	struct stat st;
	ret = fs->lstat("/todir", &st);
	if (ret) {
		LOG_ERRNO_RETURN(-ret, -1, "failed stat");
	}
	print_stat(&st);
	
	// ret = fs->link("/todir", "/yydir");
	// if (ret) {
	// 	LOG_ERRNO_RETURN(-ret, -1, "failed link");
	// }

	// ret = fs->mkdir("/dir-1", 0755);
	// if (ret) {
	// 	LOG_ERRNO_RETURN(-ret, -1, "failed mkdir");
	// }

	return 0;
}

int main(int argc, char **argv) {
	photon::init(photon::INIT_EVENT_DEFAULT, photon::INIT_IO_DEFAULT);
	set_log_output_level(1);

	test();

	return 0;
}