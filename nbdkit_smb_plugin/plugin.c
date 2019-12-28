/* nbdkit
 * Copyright (C) 2013 Red Hat Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * * Neither the name of Red Hat nor the names of its contributors may be
 * used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY RED HAT AND CONTRIBUTORS ''AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL RED HAT OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* example1:
 *
 * This is (almost) the most minimal nbdkit plugin possible.  It
 * serves, readonly, from memory, a static blob of data.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nbdkit-plugin.h>

#include <nbdkit_smb_plugin/plugin_binding.h>

#define THREAD_MODEL NBDKIT_THREAD_MODEL_SERIALIZE_ALL_REQUESTS

static char *url = NULL;
static uint64_t size = 1 * 1024 * 1024 * 1024;  // Default disk size, 1GiB

static void plugin_unload(void) { free(url); }

static void *plugin_open(int readonly) { return nbdkit_smb_open(url); }

static void plugin_close(void *handle)
{
	nbdkit_smb_close((nbdkit_smb *)handle);
}

static int64_t plugin_get_size(void *handle)
{
	return size;
}

static void plugin_dump_plugin(void)
{
	printf(
	    "url=smb://[[WORKGROUP:][USER][:PASSWORD]@]HOST/SHARE/PATH/\n"
	    "size=1G\n");
}

static int plugin_config(const char *key, const char *value)
{
	if (strcmp(key, "url") == 0) {
		url = malloc(strlen(value) + 1);
		strcpy(url, value);
	}
	else if (strcmp(key, "size") == 0) {
		int64_t r = nbdkit_parse_size(value);
		if (r == -1)
			return -1;
		size = (uint64_t)r;
	}
	else {
		nbdkit_error("unknown parameter '%s'", key);
		return -1;
	}

	return 0;
}

static int plugin_config_complete(void)
{
	if (url == NULL) {
		nbdkit_error(
		    "you must supply the url parameter after the plugin name on the "
		    "command line");
		return -1;
	}

	return 0;
}

#define plugin_config_help                                         \
	"url=smb://[[WORKGROUP:][USER][:PASSWORD]@]HOST/SHARE/PATH/\n" \
	"    The SAMBA URL at which the disk should be stored"         \
	"size=1G\n"                                                    \
	"    The size of the disk"

static int plugin_pread(void *handle, void *buf, uint32_t count,
                        uint64_t offset)
{
	return nbdkit_smb_pread((nbdkit_smb *)handle, buf, count, offset);
}

static int plugin_pwrite(void *handle, const void *buf, uint32_t count,
                         uint64_t offset)
{
	return nbdkit_smb_pwrite((nbdkit_smb *)handle, buf, count, offset);
}

static struct nbdkit_plugin plugin = {
    .name = "smb",
    .version = "1.0",
    .unload = plugin_unload,
    .dump_plugin = plugin_dump_plugin,
    .config = plugin_config,
    .config_complete = plugin_config_complete,
    .config_help = plugin_config_help,
    .open = plugin_open,
    .close = plugin_close,
    .get_size = plugin_get_size,
    .pread = plugin_pread,
    .pwrite = plugin_pwrite,
    .errno_is_preserved = 1,
};

NBDKIT_REGISTER_PLUGIN(plugin)
