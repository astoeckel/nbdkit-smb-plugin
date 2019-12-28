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

#include <libsmbclient.h>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <vector>

#include <nbdkit_smb_plugin/smb.hpp>
#include <nbdkit_smb_plugin/url_parser.hpp>

/******************************************************************************
 * Struct SMB::Connection                                                     *
 ******************************************************************************/

// adapted from https://stackoverflow.com/a/46931770
static std::vector<std::string> split(const std::string &s, char delim)
{
	std::vector<std::string> res;
	std::stringstream ss(s);
	std::string item;
	while (std::getline(ss, item, delim)) {
		res.push_back(item);
	}
	return res;
}

template <typename Iterator>
static std::string join(Iterator begin, Iterator end, char delim)
{
	std::string res;
	for (Iterator it = begin; it != end; it++) {
		if (it != begin) {
			res += delim;
		}
		res += *it;
	}
	return res;
}

SMB::URL::URL(const char *url)
{
	// Feed the URL into the URL parser
	UrlParser parsed_url(url);

	// Fetch the protocol. Must be "smb"
	if (parsed_url.scheme() != "smb") {
		throw std::runtime_error("Unsupported protocol in URL");
	}

	// Fetch the host
	host = parsed_url.host();

	// Split the user information into the individual parts
	std::vector<std::string> user_parts = split(parsed_url.user_info(), ':');
	if (user_parts.size() == 1) {
		user = user_parts[0];
	}
	else if (user_parts.size() == 2) {
		user = user_parts[0];
		password = user_parts[1];
	}
	else if (user_parts.size() == 3) {
		workgroup = user_parts[0];
		user = user_parts[1];
		password = user_parts[2];
	}
	else if (user_parts.size() > 3) {
		throw std::runtime_error("Invalid user string in URL");
	}

	// Split the path into the share and the path
	std::vector<std::string> path_parts = split(parsed_url.path(), '/');
	if (path_parts.size() > 0) {
		share = path_parts[0];
	}
	if (path_parts.size() > 1) {
		path = join(path_parts.begin() + 1, path_parts.end(), '/');
	}
}

std::string SMB::URL::str(bool include_credentials) const
{
	std::stringstream ss;
	ss << "smb://";
	if (include_credentials) {
		if (!workgroup.empty()) {
			ss << workgroup << ':';
		}
		if (!user.empty()) {
			ss << user << (password.empty() ? '@' : ':');
		}
		if (!password.empty()) {
			ss << password << '@';
		}
	}
	ss << host << share << '/' << path;
	if (!path.empty() && path[path.size() - 1] != '/') {
		ss << '/';
	}
	return ss.str();
}

/******************************************************************************
 * Struct SMB::Impl                                                           *
 ******************************************************************************/

class SMB::Impl {
private:
	URL m_url;
	size_t m_block_size;
	size_t m_superblock_size;

	SMBCCTX *m_ctx;

	smbc_open_fn m_open;
	smbc_close_fn m_close;
	smbc_creat_fn m_creat;
	smbc_lseek_fn m_lseek;
	smbc_write_fn m_write;
	smbc_ftruncate_fn m_ftruncate;
	smbc_fstat_fn m_fstat;
	smbc_read_fn m_read;
	smbc_unlink_fn m_unlink;
	smbc_mkdir_fn m_mkdir;
	smbc_rmdir_fn m_rmdir;
	smbc_opendir_fn m_opendir;
	smbc_closedir_fn m_closedir;
	smbc_readdir_fn m_readdir;
	smbc_statvfs_fn m_statvfs;

	class File {
	private:
		Impl *m_impl;
		SMBCFILE *m_file;

		void close()
		{
			if (m_file) {
				int errno_tmp = errno; // Restore errno
				m_impl->m_close(m_impl->m_ctx, m_file);
				m_file = nullptr;
				errno = errno_tmp;
			}
		}

	public:
		File() : m_impl(nullptr), m_file(nullptr) {}

		File(Impl *impl, const char *fname, int flags, mode_t mode) noexcept
		    : m_impl(impl)
		{
			m_file = m_impl->m_open(m_impl->m_ctx, fname, flags, mode);
		}

		~File() noexcept { close(); }

		File(const File &) = delete;
		File &operator=(const File &) = delete;

		File(File &&o) noexcept : m_impl(o.m_impl), m_file(nullptr)
		{
			std::swap(m_file, o.m_file);
		}
		File &operator=(File &&o) noexcept
		{
			close();
			m_impl = o.m_impl;
			std::swap(m_file, o.m_file);
			return *this;
		}

		operator bool() const { return m_file != nullptr; }

		operator SMBCFILE *() const { return m_file; }
	};

	template <typename T>
	static T err(T status)
	{
		if (status < 0) {
			throw std::system_error(errno, std::system_category());
		}
		return status;
	}

	static void auth_data_callback(SMBCCTX *ctx, const char *server,
	                               const char *share, char *workgroup,
	                               int max_len_workgroup, char *username,
	                               int max_len_username, char *password,
	                               int max_len_password)
	{
/*		std::cerr << "SMB: Authentication request for \\\\" << server
		          << "\\" << share << std::endl;*/

		// Fetch a reference at the impl object
		Impl *self = static_cast<Impl *>(smbc_getOptionUserData(ctx));

		// Reset the workgroup, username and password
		std::memset(workgroup, 0, max_len_workgroup);
		std::memset(username, 0, max_len_username);
		std::memset(password, 0, max_len_password);

		// Copy the data from the URL into the provided memory regions
		const URL &url = self->m_url;
		if (!url.workgroup.empty()) {
			std::strncpy(workgroup, url.workgroup.c_str(), max_len_workgroup);
		}
		std::strncpy(username, url.user.c_str(), max_len_username);
		std::strncpy(password, url.password.c_str(), max_len_password);
	}

	static char nibble_to_hex(uint8_t x)
	{
		return x < 10 ? ('0' + x) : ('a' + (x - 10));
	};

	bool make_block_filename(size_t idx, char *s) const
	{
		size_t block_idx = idx / m_superblock_size;
		for (size_t i = 0; i < 8; i++) {
			(*s++) = nibble_to_hex(((block_idx >> (8 * i)) & 0x0F) >> 0);
			if (i == 1) {
				(*s++) = '/';
			}
			(*s++) = nibble_to_hex(((block_idx >> (8 * i)) & 0xF0) >> 4);
		}
		return (block_idx * m_superblock_size) == idx;
	}

	template <typename F>
	void iterate_blocks(F callback, size_t block_index, size_t block_count,
	                    int flags, mode_t mode)
	{
		const __off_t size = m_block_size * m_superblock_size;

		// Prepare a buffer containing the block filename
		std::string path = m_url.str() + "000/0000000000000.img";
		char *s = const_cast<char *>(path.c_str()) + (path.size() - 21);

		// Iterate over the individual blocks
		const bool writing = (flags & O_RDWR) || (flags & O_WRONLY);
		File file;
		size_t i0 = 0;
		for (size_t i = 0; i < block_count; i++) {
			// If this is the first index or we're at a superblock boundary,
			// open a new file
			if (((i == 0) | make_block_filename(block_index + i, s))) {
				if (i > 0) {
					callback(i0, i - i0, file);
				}
				i0 = i;

				// Try to open the file
				file = std::move(File(this, path.c_str(), flags, mode));

				// Opening the file failed.
				if (!file) {
					// The directory we're refering to does not exist.
					if (errno == ENOENT) {
						// Don't despair if we don't try to write. In this case
						// just don't open the file.
						if (writing) {
							// Otherwise, try to create the directory.
							s[3] = '\0';
							int res = m_mkdir(m_ctx, path.c_str(), 0770);
							s[3] = '/';

							// It's okay if someone else created the directory
							// for us. However, any other error is a failure.
							if (res < 0 && errno != EEXIST) {
								err(-1);
							}

							// Now that we've created the directory, try to open
							// the file.
							file = std::move(File(this, path.c_str(), flags, mode));
							if (!file) {
								err(-1);
							}
						}
					}
					else {
						err(-1);
					}
				}

				// Make sure the file has the right size
				if (writing) {
					struct stat st;
					err(m_fstat(m_ctx, file, &st));
					if (st.st_size != size) {
						err(m_ftruncate(m_ctx, file, size));
					}
				}

				// Seek to the correct location in the file
				m_lseek(m_ctx, file, ((block_index + i) * m_block_size) % size, SEEK_SET);
			}
		}
		callback(i0, block_count - i0, file);
	}


	static void log_callback(void *private_ptr, int level, const char *msg) {
		std::cerr << "libsmbclient: " << msg << std::endl;
	}

public:
	Impl(const URL &url, size_t block_size, size_t superblock_size)
	    : m_url(url),
	      m_block_size(block_size),
	      m_superblock_size(superblock_size)
	{
		// Create and initialize a new context
		m_ctx = smbc_new_context();
		if ((!m_ctx) || (smbc_init_context(m_ctx) != m_ctx)) {
			err(-1);
		}

		smbc_setOptionUserData(m_ctx, this);
		smbc_setOptionNoAutoAnonymousLogin(m_ctx, true);
		smbc_setOptionUseCCache(m_ctx, false);


		smbc_setDebug(m_ctx, 5);
		smbc_setLogCallback(m_ctx, nullptr, log_callback);


		// Fetch all required function pointers
		m_open = smbc_getFunctionOpen(m_ctx);
		m_close = smbc_getFunctionClose(m_ctx);
		m_creat = smbc_getFunctionCreat(m_ctx);
		m_lseek = smbc_getFunctionLseek(m_ctx);
		m_ftruncate = smbc_getFunctionFtruncate(m_ctx);
		m_fstat = smbc_getFunctionFstat(m_ctx);
		m_write = smbc_getFunctionWrite(m_ctx);
		m_read = smbc_getFunctionRead(m_ctx);
		m_unlink = smbc_getFunctionUnlink(m_ctx);
		m_mkdir = smbc_getFunctionMkdir(m_ctx);
		m_rmdir = smbc_getFunctionRmdir(m_ctx);
		m_opendir = smbc_getFunctionOpendir(m_ctx);
		m_closedir = smbc_getFunctionClosedir(m_ctx);
		m_readdir = smbc_getFunctionReaddir(m_ctx);
		m_statvfs = smbc_getFunctionStatVFS(m_ctx);

		// Set the auth data callback
		smbc_setFunctionAuthDataWithContext(m_ctx, auth_data_callback);
	}

	~Impl()
	{
		if (m_ctx) {
			smbc_free_context(m_ctx, true);
		}
		m_ctx = nullptr;
	}

	size_t block_size() const { return m_block_size; }

	size_t superblock_size() const { return m_superblock_size; }

	SizeInfo get_size_info()
	{
		SizeInfo res;
		struct statvfs info;

		// Use statvfs to get information about the filesystem
		const std::string path = m_url.str();
		err(m_statvfs(m_ctx, const_cast<char *>(path.c_str()), &info));

		// Copy the information to the result structure
		const size_t block_size = size_t(info.f_bsize) * size_t(info.f_frsize);
		res.size = block_size * size_t(info.f_blocks);
		res.free = block_size * size_t(info.f_bfree);

		return res;
	}

	void write_block(size_t block_index, size_t block_count, const uint8_t *buf)
	{
		iterate_blocks([&] (size_t i, size_t c, File &file) {
			if (buf) {
				m_write(m_ctx, file, &buf[m_block_size * i], m_block_size * c);
			}
		}, block_index, block_count, O_CREAT | O_WRONLY, 0770);
	}

	void read_block(size_t block_index, size_t block_count, uint8_t *buf) {
		iterate_blocks([&] (size_t i, size_t c, File &file) {
			if (file) {
				m_read(m_ctx, file, &buf[m_block_size * i], m_block_size * c);
			} else {
				memset(&buf[m_block_size * i], 0, m_block_size * c);
			}
		}, block_index, block_count, O_RDONLY, 0770);
	}
};

/******************************************************************************
 * Class SMB                                                                  *
 ******************************************************************************/

SMB::SMB(const URL &url, size_t block_size, size_t superblock_size)
    : m_impl(std::make_unique<Impl>(url, block_size, superblock_size))
{
}

SMB::~SMB()
{
	// Implicitly destroy m_impl
}

size_t SMB::block_size() const { return m_impl->block_size(); }

size_t SMB::superblock_size() const { return m_impl->superblock_size(); }

SMB::SizeInfo SMB::get_size_info() { return m_impl->get_size_info(); }

void SMB::write_block(size_t block_index, size_t block_count,
                      const uint8_t *buf)
{
	m_impl->write_block(block_index, block_count, buf);
}

void SMB::read_block(size_t block_index, size_t block_count, uint8_t *buf)
{
	m_impl->read_block(block_index, block_count, buf);
}

void SMB::trim_block(size_t block_index, size_t block_count)
{
	// TODO
}