#include <iostream>

#include <nbdkit_smb_plugin/smb.hpp>

int main(int argc, const char* argv[]) {
	if (argc != 2) {
		std::cout << "Usage: " << argv[0] << " <SMB SHARE>" << std::endl;
		return 1;
	}
	SMB smb(argv[1]);
	const auto info = smb.get_size_info();
	std::cout << "Total size: " << (info.size / (1024 * 1024 * 1024)) << " GiB"  <<std::endl;
	std::cout << "Free size: " << (info.free / (1024 * 1024 * 1024)) << " GiB"  <<std::endl;

	smb.get_size_info();

	smb.write_block(0xafafbc00, 1024, nullptr);
}