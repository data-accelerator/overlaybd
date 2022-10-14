/*
   Copyright The Overlaybd Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
#pragma once
#include "ufs_io_mannager.h"

ext2_file_t do_ext2fs_open_file(ext2_filsys fs, const char* path, unsigned int flags, unsigned int mode);
long do_ext2fs_read(ext2_file_t file, int flags, char *buffer, unsigned long count,	unsigned long offset);
long do_ext2fs_write(ext2_file_t file, int flags, const char *buffer, unsigned long count, unsigned long offset);
errcode_t do_ext2fs_unlink(ext2_filsys fs, const char *path);
errcode_t do_ext2fs_mkdir(ext2_filsys fs, const char *path, int mode);
errcode_t do_ext2fs_rmdir(ext2_filsys fs, const char *path);
errcode_t do_ext2fs_rename(ext2_filsys fs, const char *from, const char *to);
errcode_t do_ext2fs_link(ext2_filsys fs, const char *src, const char *dest);
int do_ext2fs_symlink(ext2_filsys fs, const char *src, const char *dest);
errcode_t do_ext2fs_chmod(ext2_file_t file, int mode);
errcode_t do_ext2fs_chown(ext2_file_t file, int uid, int gid);
errcode_t do_ext2fs_mknod(ext2_filsys fs, const char *path, unsigned int st_mode, unsigned int st_rdev);

photon::fs::IFileSystem* new_userspace_fs(photon::fs::IFile *file);