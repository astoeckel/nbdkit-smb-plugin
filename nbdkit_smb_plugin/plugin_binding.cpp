/*
 *  nbdkit-smb-plugin
 *  Copyright (C) 2020  Andreas Stöckel
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <cerrno>
#include <system_error>

#include <nbdkit_smb_plugin/plugin_binding.h>
#include <nbdkit_smb_plugin/smb.hpp>

#ifdef __cplusplus
extern "C" {
#endif

nbdkit_smb *nbdkit_smb_open(const char *url)
{
	return reinterpret_cast<nbdkit_smb *>(new SMB(url));
}

void nbdkit_smb_close(nbdkit_smb *smb)
{
	delete (reinterpret_cast<SMB *>(smb));
}

int nbdkit_smb_pread(nbdkit_smb *smb, void *buf, uint32_t count,
                     uint64_t offset)
{
	SMB *inst = reinterpret_cast<SMB *>(smb);
	try {
		inst->read_block(offset / 4096, count / 4096,
		                 static_cast<uint8_t *>(buf));
		return 0;
	}
	catch (std::system_error &e) {
		errno = e.code().value();
		return -1;
	}
}

int nbdkit_smb_pwrite(nbdkit_smb *smb, const void *buf, uint32_t count,
                      uint64_t offset)
{
	SMB *inst = reinterpret_cast<SMB *>(smb);
	try {
		inst->write_block(offset / 4096, count / 4096,
		                  static_cast<const uint8_t *>(buf));
		return 0;
	}
	catch (std::system_error &e) {
		errno = e.code().value();
		return -1;
	}
}

#ifdef __cplusplus
}
#endif