/*
**  Copyright 2000 overlaybd authors
**  Copyright 1998-2003 University of Illinois Board of Trustees
**  Copyright 1998-2003 Mark D. Roth
**  All rights reserved.
**
**  libtar.c - demo driver program for libtar
**
**  Mark D. Roth <roth@uiuc.edu>
**  Campus Information Technologies and Educational Services
**  University of Illinois at Urbana-Champaign
*/

#include "libtar.h"

#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <utime.h>
#include <set>
#include <string>
#include <photon/fs/path.h>
#include <photon/common/string_view.h>
#include <photon/fs/filesystem.h>
#include <photon/common/alog.h>
#include <photon/common/enumerable.h>
#include <photon/fs/path.h>

#define BIT_ISSET(bitmask, bit) ((bitmask) & (bit))

int Tar::read_header_internal() {
	int i;
	int num_zero_blocks = 0;

	while ((i = file->read(&header, T_BLOCKSIZE)) == T_BLOCKSIZE) {
		/* two all-zero blocks mark EOF */
		if (header.name[0] == '\0') {
			num_zero_blocks++;
			if (!BIT_ISSET(options, TAR_IGNORE_EOT)
				&& num_zero_blocks >= 2)
				return 0;	/* EOF */
			else
				continue;
		}

		/* verify magic and version */
		if (BIT_ISSET(options, TAR_CHECK_MAGIC)
			&& strncmp(header.magic, TMAGIC, TMAGLEN - 1) != 0) {
			return -2;
		}

		if (BIT_ISSET(options, TAR_CHECK_VERSION)
		    && strncmp(header.version, TVERSION, TVERSLEN) != 0) {
			return -2;
		}

		/* check chksum */
		if (!BIT_ISSET(options, TAR_IGNORE_CRC) && !header.crc_ok()) {
			return -2;
		}

		break;
	}

	return i;
}


int Tar::read_header() {
	size_t sz, j, blocks;
	char *ptr;

	if (header.gnu_longname != NULL)
		free(header.gnu_longname);
	if (header.gnu_longlink != NULL)
		free(header.gnu_longlink);
	memset(&(header), 0, sizeof(TarHeader));

	int i = read_header_internal();
	if (i == 0)
		return 1;
	else if (i != T_BLOCKSIZE) {
		if (i != -1)
			errno = EINVAL;
		return -1;
	}

	/* check for GNU long link extention */
	if (header.typeflag == GNU_LONGLINK_TYPE) {
		sz = header.get_size();
		blocks = (sz / T_BLOCKSIZE) + (sz % T_BLOCKSIZE ? 1 : 0);
		if (blocks > ((size_t)-1 / T_BLOCKSIZE)) {
			errno = E2BIG;
			return -1;
		}

		header.gnu_longlink = (char *)malloc(blocks * T_BLOCKSIZE);
		if (header.gnu_longlink == NULL)
			return -1;

		for (j = 0, ptr = header.gnu_longlink; j < blocks; j++, ptr += T_BLOCKSIZE) {
			i = file->read(ptr, T_BLOCKSIZE);
			if (i != T_BLOCKSIZE) {
				if (i != -1)
					errno = EINVAL;
				return -1;
			}
		}

		i = read_header_internal();
		if (i != T_BLOCKSIZE) {
			if (i != -1)
				errno = EINVAL;
			return -1;
		}
	}

	/* check for GNU long name extention */
	if (header.typeflag == GNU_LONGNAME_TYPE) {
		sz = header.get_size();
		blocks = (sz / T_BLOCKSIZE) + (sz % T_BLOCKSIZE ? 1 : 0);
		if (blocks > ((size_t)-1 / T_BLOCKSIZE)) {
			errno = E2BIG;
			return -1;
		}
		header.gnu_longname = (char *)malloc(blocks * T_BLOCKSIZE);
		if (header.gnu_longname == NULL)
			return -1;

		for (j = 0, ptr = header.gnu_longname; j < blocks; j++, ptr += T_BLOCKSIZE) {
			file->read(ptr, T_BLOCKSIZE);
			if (i != T_BLOCKSIZE) {
				if (i != -1)
					errno = EINVAL;
				return -1;
			}
		}

		i = read_header_internal();
		if (i != T_BLOCKSIZE) {
			if (i != -1)
				errno = EINVAL;
			return -1;
		}
	}

	return 0;
}



int Tar::extract_all() {

	char *filename;
	char buf[MAXPATHLEN];
	int i;

	std::set<std::string> unpackedPaths;
	while ((i = read_header()) == 0) {
		if (extract_file() != 0)
			return -1;
	}

	return (i == 1 ? 0 : -1);
}



int Tar::set_file_perms() {
	char *filename = get_pathname();
	mode_t mode = header.get_mode();
	uid_t uid = header.get_uid();
	gid_t gid = header.get_gid();
	struct utimbuf ut;
	ut.modtime = ut.actime = header.get_mtime();

	/* change owner/group */
	if (geteuid() == 0)
#ifdef HAVE_LCHOWN
		if (fs->lchown(filename, uid, gid) == -1) {
#else /* ! HAVE_LCHOWN */

		if (!TH_ISSYM(header) && fs->chown(filename, uid, gid) == -1) {
#endif /* HAVE_LCHOWN */
			return -1;
		}

	/* change access/modification time */
	if (!TH_ISSYM(header) && fs->utime(filename, &ut) == -1) {
		return -1;
	}

	/* change permissions */
	if (!TH_ISSYM(header) && fs->chmod(filename, mode) == -1) {
		return -1;
	}

	return 0;
}

int Tar::extract_file() {
	int i;
	auto cwres = convert_whiteout();
	if (cwres < 0) {
		return -1;
	}
	if (cwres == 1) {
		return 0;
	}

	if (options & TAR_NOOVERWRITE) {
		struct stat s;
		char *realname = get_pathname();
		if (fs->lstat(realname, &s) == 0 || errno != ENOENT) {
			errno = EEXIST;
			return -1;
		}
	}

	if (TH_ISDIR(header)) {
		i = extract_dir();
		if (i == 1)
			i = 0;
	}
	else if (TH_ISLNK(header))
		i = extract_hardlink();
	else if (TH_ISSYM(header))
		i = extract_symlink();
	else if (TH_ISCHR(header)) {
		LOG_WARN("ignore chardev");
		i = 0;
	} else if (TH_ISBLK(header)) {
		LOG_WARN("ignore blockdev");
		i = 0;
	} else if (TH_ISFIFO(header)) {
		LOG_WARN("ignore fifo");
		i = 0;
	} else /* if (TH_ISREG(t)) */
		i = extract_regfile();

	if (i != 0)
		return i;

	i = set_file_perms();
	if (i != 0)
		return i;

	unpackedPaths.insert(get_pathname());
	return 0;
}


int Tar::extract_regfile() {
	ssize_t i, k;
	char buf[T_BLOCKSIZE];
	char *filename = get_pathname();
	mode_t mode = header.get_mode();
	size_t size = header.get_size();
	uid_t uid = header.get_uid();
	gid_t gid = header.get_gid();

	photon::fs::Path p(filename);
	if (photon::fs::mkdir_recursive(p.dirname(), fs, 0777) < 0) {
		return -1;
	}

	photon::fs::IFile *fout = fs->open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (fout == nullptr) {
		return -1;
	}

#if 0
	/* change the owner.  (will only work if run as root) */
	if (fout->fchown(fdout, uid, gid) == -1 && errno != EPERM)
	{
		return -1;
	}

	/* make sure the mode isn't inheritted from a file we're overwriting */
	if (fout->fchmod(fdout, mode & 07777) == -1)
	{
		return -1;
	}
#endif

	/* extract the file */
	for (i = size; i > 0; i -= T_BLOCKSIZE) {
		auto rc = file->read(buf, T_BLOCKSIZE);
		if (rc != T_BLOCKSIZE) {
			delete fout;
			LOG_ERRNO_RETURN(0, -1, "failed to read block");
		}

		/* write block to output file */
		if (fout->write(buf, ((i > T_BLOCKSIZE) ? T_BLOCKSIZE : i)) < 0) {
			delete fout;
			LOG_ERRNO_RETURN(0, -1, "failed to write file");
		}
	}

	delete fout;
	return 0;
}


int Tar::extract_hardlink() {
	char *filename = get_pathname();
	auto mode = header.get_mode();
	photon::fs::Path p(filename);
	if (photon::fs::mkdir_recursive(p.dirname(), fs, 0777) < 0) {
		return -1;
	}
	char *linktgt = safer_name_suffix(header.get_linkname());
	if (fs->link(linktgt, filename) == -1) {
		return -1;
	}
	return 0;
}


int Tar::extract_symlink() {
	char *filename = get_pathname();
	auto mode = header.get_mode();
	photon::fs::Path p(filename);
	if (photon::fs::mkdir_recursive(p.dirname(), fs, 0777) < 0) {
		return -1;
	}

	if (fs->unlink(filename) == -1 && errno != ENOENT)
		return -1;
	char *linktgt = safer_name_suffix(header.get_linkname());
	if (fs->symlink(linktgt, filename) == -1) {
		return -1;
	}
	return 0;
}


int Tar::extract_dir() {
	char *filename = get_pathname();
	mode_t mode = header.get_mode();
	photon::fs::Path p(filename);
	if (photon::fs::mkdir_recursive(p.dirname(), fs, 0777) < 0) {
		return -1;
	}

	if (fs->mkdir(filename, mode) < 0) {
		if (errno == EEXIST) {
			if (fs->chmod(filename, mode) < 0) {
				return -1;
			} else {
				return 1;
			}
		} else {
			return -1;
		}
	}
	return 0;
}
