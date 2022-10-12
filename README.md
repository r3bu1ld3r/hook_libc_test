## Intercepting libc calls with rust 

### Requirements
This solution is based on frida tool. Two frida-dev libraries should be installed before building project. 
Shell scipt `frida-install.sh` will install it for linux x86_64.

### Build 
Runs this command from project root directory.
`cargo build --release`

### Usage
Currently implemented only interception of `open` call. Timestamps of system calls will be saved in `log.txt` file. Example of usage:
`LD_PRELOAD=target/release/liblibc_call_logger.so /bin/cat Cargo.toml`

