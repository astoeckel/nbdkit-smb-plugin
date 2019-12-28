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

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nbdkit_smb_ nbdkit_smb;

nbdkit_smb *nbdkit_smb_open(const char *url);

void nbdkit_smb_close(nbdkit_smb *smb);

int nbdkit_smb_pread(nbdkit_smb *smb, void *buf, uint32_t count,
                     uint64_t offset);

int nbdkit_smb_pwrite(nbdkit_smb *smb, const void *buf, uint32_t count,
                      uint64_t offset);

#ifdef __cplusplus
}
#endif
