# nbdkit-smb-plugin
**CIFS/SAMBA Plugin for nbdkit (Network Block Device Kit)**

This *nbdkit* plugin facilitates using a CIFS/SAMBA share as a network block device (NBD). The block level device is represented as a collection of 1MiB super-block files that are placed into folders corresponding to the block addresses.

**Note:** *nbdkit-smb-plugin* assumes that there is no concurrent read/write access to the share.

## Usage

```sh
# Install prerequisites
sudo dnf install nbdkit-devel libsmbclient-devel nbd

# Clone the repository
git clone https://github.com/astoeckel/nbdkit-smb-plugin
cd nbdkit-smb-plugin

# Build the code
mkdir build; cd build
meson ..
ninja

# Run the nbdkit server with the plugin
nbdkit --foreground ./libnbdkit_smb_plugin.so url=smb://user:password@host/Share/path/to/folder_representing_the_disk/

# Now, in a separate terminal...

# Connect /dev/nbd0 to the server
sudo modprobe nbd
sudo nbd-client 127.0.0.1 /dev/nbd0 -b 4096

# Create a partition
sudo fdisk /dev/nbd0
# Type g, n, w (confirm everything by pressin enter multiple times)

# Optional: setup encryption using cryptsetup/LUKS

# Create a filesystem
sudo mkfs.ext4 /dev/nbd0p1

# Mount the filesystme
mkdir test
sudo mount /dev/nbd0p1 test

# Use the disk on the SMB share as if it was a normal Linux filesystem

# Unmount the filesystem
sudo umount test

# Disconnect the nbd0 device
sudo nbd-client -d /dev/nbd0

# Stop the server by pressing CTRL+C
```
