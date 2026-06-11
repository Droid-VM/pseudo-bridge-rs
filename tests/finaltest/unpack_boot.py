#!/usr/bin/env python3
"""Minimal Android boot.img unpacker: extract the kernel and decompress to a raw arm64 Image.

Handles header v0-v2 (page_size at off 36) and v3/v4 (fixed 4096 page).
header_version is at offset 40 in both layouts.
"""
import struct, sys, gzip, subprocess, os

def u32(b, off): return struct.unpack_from("<I", b, off)[0]

def main(boot_path, out_kernel):
    with open(boot_path, "rb") as f:
        data = f.read()
    assert data[:8] == b"ANDROID!", "not an Android boot image"
    hdr_ver = u32(data, 40)
    kernel_size = u32(data, 8)
    if hdr_ver >= 3:
        page = 4096
        koff = page                      # header occupies 1 page
    else:
        page = u32(data, 36)
        koff = page
    kernel = data[koff:koff + kernel_size]
    print(f"header_version={hdr_ver} page={page} kernel_size={kernel_size} koff={koff}")
    magic = kernel[:4]
    print("kernel first bytes:", magic.hex())
    # decompress to raw Image
    if magic[:2] == b"\x1f\x8b":                       # gzip
        print("kernel is gzip -> decompressing")
        kernel = gzip.decompress(kernel)
    elif magic == b"\x04\x22\x4d\x18" or magic == b"\x02\x21\x4c\x18":  # lz4 frame/legacy
        print("kernel is lz4 -> decompressing")
        kernel = subprocess.run(["lz4", "-d", "-c", "-"], input=kernel,
                                stdout=subprocess.PIPE, check=True).stdout
    else:
        # raw arm64 Image has magic 'ARM\x64' (0x644d5241) at offset 56
        arm64 = struct.unpack_from("<I", kernel, 56)[0] if len(kernel) > 60 else 0
        if arm64 == 0x644d5241:
            print("kernel is raw arm64 Image")
        else:
            print("WARN: unknown kernel format, writing as-is")
    with open(out_kernel, "wb") as f:
        f.write(kernel)
    # confirm arm64 Image magic in final
    if len(kernel) > 60:
        m = struct.unpack_from("<I", kernel, 56)[0]
        print("final arm64 magic @0x38:", hex(m), "(expect 0x644d5241)" )
    print(f"wrote {out_kernel} ({len(kernel)} bytes)")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
