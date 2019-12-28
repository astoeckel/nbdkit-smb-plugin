project('nbdkit-smb-plugin', ['c', 'cpp'], default_options: ['b_lundef=false'])

dep_nbdkit = dependency('nbdkit', required: true)
dep_smbclient = dependency('smbclient', required: true)

lib_nbdkit_smb = library(
	'nbdkit_smb',
	[
		'nbdkit_smb_plugin/plugin_binding.cpp',
		'nbdkit_smb_plugin/smb.cpp',
		'nbdkit_smb_plugin/url_parser.cpp',
	],
	dependencies: [dep_smbclient],
)

lib_nbdkit_smb_plugin = library(
	'nbdkit_smb_plugin',
	[
		'nbdkit_smb_plugin/plugin.c',
	],
	dependencies: [dep_nbdkit],
	link_with: [lib_nbdkit_smb],
)

exe_test_get_space_info = executable(
	'test_get_space_info',
	[
		'test/test_get_space_info.cpp',
	],
	link_with: [lib_nbdkit_smb],
)