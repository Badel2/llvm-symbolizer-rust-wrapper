# llvm-symbolizer-rust-wrapper

This binary will pretend to be `llvm-symbolizer`, except that it will demangle Rust function names using the
`rustc_demangle` crate instead of the builtin llvm demangler.
It needs a real `llvm-symbolizer` binary to be already installed.

## Installation

First, make sure you have the real llvm-symbolizer installed. Open a terminal, type `llvm-symbolizer`, and press tab
twice. The autocomplete should display a list of the installed llvm-symbolizer binaries. If you see something like this,
great!

```
llvm-symbolizer-11  llvm-symbolizer-12  llvm-symbolizer-13  
```

If not, install the newest version of llvm using your package manager.

Make sure that the `llvm-symbolizer` command does not exist, if it does you will need to remove it or rename it to
`llvm-symbolizer-14` or whatever version it is.

After some version of `llvm-symbolizer-*` is properly installed and in PATH, use cargo install to install this wrapper:

```
cargo install llvm-symbolizer-rust-wrapper
```

This will install the binary to `$HOME/.cargo/bin`. Try executing `llvm-symbolizer-rust-wrapper --help`. If that works,
great. If it doesn't, you probably need to add `$HOME/.cargo/bin/` to the `PATH` environment variable.

Once you made sure the wrapper is working correctly, you will need to set this as the default `llvm-symbolizer`. That
can be easily done by creating a symbolic link:

```
ln -s $HOME/.cargo/bin/llvm-symbolizer-rust-wrapper $HOME/.cargo/bin/llvm-symbolizer
```

To verify it works:

```
llvm-symbolizer --help
```

This will print the help of `llvm-symbolizer-xx`, where `xx` is the newest installed version of `llvm-symbolizer`.

You can also manually specify which version of `llvm-symbolizer` to use by setting the enviroment variable:

```
export LSRW_REAL_EXE=/usr/bin/llvm-symbolizer-14
```

## Troubleshooting

Since this is a wrapper, we cannot log to stderr, we log to a file instead. Logging is disabled
by default, can be enabled by setting the env variable `LSRW_LOG_FILE=/tmp/lsrw_log.txt`.

