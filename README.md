## LibLinuxEvents

This is a **proof-of-concept** for a container-aware process and network event publisher library with no runtime dependencies (i.e. kernel headers).

It works by using LLVM/Clang, the BTF debug information ([btfparse](https://github.com/trailofbits/btfparse)) and our C++ BPF utilities ([ebpf-common](https://github.com/trailofbits/ebpf-common)).

## Build instructions

1. Download and extract the [osquery-toolchain](https://github.com/osquery/osquery-toolchain)
2. Clone the repository: `git clone --recursive https://github.com/trailofbits/linuxevents`
3. Install the following dependencies: LLVM libraries, Clang libraries, Ninja, CMake
4. Configure the project: `cmake -S linuxevents -B build-linuxevents -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain.cmake -G Ninja -DCMAKE_BUILD_TYPE=Release`
5. Build the project: `cmake --build build-linuxevents`
6. Run the `execsnoop` sample: `sudo build-linuxevents/examples/execsnoop/execsnoop`

## Runtime requirements

Since this library uses BTF, you need a kernel that is recent enough to support it. You can quickly check if your system is supported by checking for the existance of the following file: `/sys/kernel/btf/vmlinux`
