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

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

class SMB {
private:
	class Impl;
	std::unique_ptr<Impl> m_impl;

public:
	struct URL {
		std::string workgroup;
		std::string user;
		std::string password;
		std::string host;
		std::string share;
		std::string path;

		URL() = default;
		URL(const char *url);

		std::string str(bool include_credentials = false) const;
	};

	struct SizeInfo {
		size_t size;
		size_t free;
	};

	SMB(const URL &url, size_t block_size = 4096,
	    size_t superblock_size = 256);
	~SMB();

	size_t block_size() const;
	size_t superblock_size() const;

	SizeInfo get_size_info();

	void write_block(size_t block_index, size_t block_count,
	                 const uint8_t *buf);
	void read_block(size_t block_index, size_t block_count, uint8_t *buf);
	void trim_block(size_t block_index, size_t block_count);
};