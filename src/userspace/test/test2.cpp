#include "../user.h"
#include <fcntl.h>
#include <photon/photon.h>
#include <photon/fs/localfs.h>
#include <photon/fs/subfs.h>
#include "../../overlaybd/untar/libtar.h"

photon::fs::IFile *open_file(const char *fn, int flags, mode_t mode = 0) {
    auto file = photon::fs::open_localfile_adaptor(fn, flags, mode, 0);
    if (!file) {
		LOG_ERROR("failed to open file `, `: `", fn, errno, strerror(errno));
        exit(-1);
    }
    return file;
}

int main(int argc, char **argv) {
	photon::init(photon::INIT_EVENT_DEFAULT, photon::INIT_IO_DEFAULT);
	set_log_output_level(0);

	// test();
	auto tar_file = open_file("/home/admin/developments/ufs_test/test.tar", O_RDONLY, 0666);
	auto target_file = open_file("/home/admin/developments/ufs_test/ufs_test/rootfs.img", O_RDWR, 0644);
	auto ufs = new_userspace_fs(target_file);
	if (!ufs) {
		LOG_ERRNO_RETURN(0, -1, "new ufs failed, `", strerror(errno));
	}
	auto target = photon::fs::new_subfs(ufs, "/", true);
	if (!target) {
		LOG_ERRNO_RETURN(0, -1, "new subfs failed, `", strerror(errno));
	}
	auto tar = new Tar(tar_file, target, 0);

	if (tar->extract_all() < 0) {
        LOG_ERROR("failed to extract");
    } else {
        LOG_INFO("extract all done");
    }

	delete target;
	delete target_file;
	delete tar_file;
	delete tar;

	return 0;
}