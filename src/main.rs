//! # llvm-symbolizer-rust-wrapper
//!
//! This binary will pretend to be `llvm-symbolizer`, with the only difference being that rust
//! function names are properly demangled, using the `rustc_demangle` crate. It needs a real
//! `llvm-symbolizer` binary to be installed, by default it will try to use the newest
//! `llvm-symbolizer-*`, but that can be overriden using the env variable
//! `LSRW_REAL_EXE=/usr/bin/llvm-symbolizer-14`.
//!
//! Since this is a wrapper, we cannot log to stderr, we log to a file instead. Logging is disabled
//! by default, can be enabled by setting the env variable `LSRW_LOG_FILE=/tmp/lsrw_log.txt`.

use log::LevelFilter;
use log4rs::append::file::FileAppender;
use log4rs::config::Appender;
use log4rs::config::Logger;
use log4rs::config::Root;
use log4rs::Config;
use regex::Regex;
use std::env;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use which::which_re;

/// Find the real llvm-symbolizer executable. If multiple exist, pick the newest one.
/// The env variable `LSRW_REAL_EXE` can be used to override this.
fn find_real_exe() -> Option<String> {
    // Use the one provided via env variable if it exists
    if let Ok(real_exe) = std::env::var("LSRW_REAL_EXE") {
        return Some(real_exe);
    }

    // Find all the llvm-symbolizer* in PATH
    let exes: Vec<PathBuf> = which_re(Regex::new(r"llvm-symbolizer.*").unwrap())
        .unwrap()
        .collect();

    log::debug!("Available llvm-symbolizer executables: {:?}", exes);

    // Skip llvm-symbolizer and llvm-symbolizer-rust-wrapper because they may refer to this binary.
    // Select the newest version among the possible ones.
    let ignore_names = ["llvm-symbolizer", "llvm-symbolizer-rust-wrapper"];
    let mut best_exe = None;
    for exe_path in &exes {
        let exe_name = match exe_path.file_name().unwrap().to_str() {
            Some(x) => x,
            None => {
                log::warn!("Invalid filename: {:?}", exe_path);
                continue;
            }
        };
        if ignore_names.iter().any(|x| *x == exe_name) {
            log::debug!("Ignoring {}", exe_name);
            continue;
        }
        if let Some(version) = exe_name.strip_prefix("llvm-symbolizer-") {
            if let Ok(version_number) = version.parse::<u32>() {
                if version_number < 9 {
                    // --no-demangle flag was introduced in version 9, so we do not support older
                    // versions
                    log::warn!("Ignoring old version of llvm-symbolizer: {:?}", exe_name);
                    continue;
                }
                if best_exe.is_none() {
                    best_exe = Some((exe_path, version_number));
                } else {
                    let best_version_number = best_exe.unwrap().1;
                    if version_number > best_version_number {
                        best_exe = Some((exe_path, version_number));
                    }
                }
            }
        }
    }

    if let Some((exe_path, _version_number)) = best_exe {
        match exe_path.to_str() {
            Some(x) => Some(x.to_string()),
            None => {
                log::warn!("Invalid path: {:?}", exe_path);
                None
            }
        }
    } else {
        None
    }
}

/// Log to file instead of stderr, because we want to show stderr from the child process.
/// Logging is disabled unless the `LSRW_LOG_FILE` env variable is set.
fn setup_logging() {
    if let Ok(log_file) = std::env::var("LSRW_LOG_FILE") {
        let file_appender = FileAppender::builder().build(log_file).unwrap();
        let config = Config::builder()
            .appender(Appender::builder().build("log_file", Box::new(file_appender)))
            .logger(Logger::builder().build("app", LevelFilter::Trace))
            .build(
                Root::builder()
                    .appender("log_file")
                    .build(LevelFilter::Trace),
            )
            .unwrap();
        let _handle = log4rs::init_config(config).unwrap();

        log::info!("Loggging enabled");
    }
}

#[derive(Debug)]
enum DemangleFlag {
    None,
    Demangle,
    NoDemangle,
}

impl DemangleFlag {
    fn is_demangle(&self) -> bool {
        // The default behavior is to demangle, so `None` is the same as `Demangle`
        match self {
            DemangleFlag::None | DemangleFlag::Demangle => true,
            DemangleFlag::NoDemangle => false,
        }
    }

    fn is_no_demangle(&self) -> bool {
        !self.is_demangle()
    }
}

/// Demangle the output of `llvm-symbolizer`, one line at a time.
///
/// Note that this function will be called for every line of the stdout of the child process, even
/// the help when run with `--help`, so it will to use some heuristic to detect whether the line is
/// a Rust function name or not.
fn demangler(line: String) -> String {
    if line.starts_with("_Z") {
        // Assume rust function and demangle
        let demangled = rustc_demangle::demangle(&line).to_string();
        log::debug!("Demangled as: {}", demangled);
        demangled
    } else {
        line
    }
}

fn main() -> io::Result<()> {
    setup_logging();
    let real_args = env::args().skip(1).collect::<Vec<_>>();
    log::debug!("Real args: {:?}", real_args);
    let real_exe = find_real_exe().unwrap();

    let mut real_demangle = DemangleFlag::None;
    let mut modified_args = real_args;
    // Check args for any mention of demangle and no-demangle.
    // The default behavior is to demangle. We want to disable that because it doesn't work with
    // Rust function names, we will demangle them ourselves. So append "--no-demangle".
    // Edge cases:
    // If the user requested --no-demangle, there is no point in using this wrapper,
    // if this was a bash script it would call "exec" to become the child process.
    // If the user requested --demangle, we remove it before passing the arguments to the child
    // process, but the user will see the demangled names.
    // If the user requested both demangle and no-demangle, the last one takes precedence.
    for arg in &modified_args {
        match arg.as_str() {
            "-demangle=true" | "--demangle" | "-C" => {
                real_demangle = DemangleFlag::Demangle;
            }
            "--no-demangle" | "-demangle=false" => {
                real_demangle = DemangleFlag::NoDemangle;
            }
            _ => (),
        }
    }
    if !real_demangle.is_no_demangle() {
        modified_args.push("--no-demangle".to_string());
    }

    let mut child = Command::new(&real_exe)
        .args(&modified_args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to spawn child process");

    {
        log::info!(
            "spawning {} with args {:?}, real_demangle: {:?}",
            real_exe,
            modified_args,
            real_demangle
        );
    }

    // Spawn a thread to handle stdin
    // Not needed since we don't need to intercept stdin, we use `Stdio::inherit()` instead, but
    // may be needed in the future.
    /*
    let mut child_stdin = child.stdin.take().expect("Failed to take child stdin");

    thread::spawn(move || {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(line) => {
                    if let Err(e) = writeln!(child_stdin, "{}", line) {
                        log::error!("Failed to write to child stdin: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    log::error!("Failed to read stdin line: {}", e);
                    break;
                }
            }
        }
    });
    */

    let child_stdout = child.stdout.take().expect("Failed to take child stdout");
    let reader = BufReader::new(child_stdout);

    // Handle stdout in the main thread
    let stdout = io::stdout();
    let mut stdout_lock = stdout.lock();
    for line in reader.lines() {
        match line {
            Ok(line) => {
                log::debug!("Child output: {}", line);
                if real_demangle.is_demangle() {
                    let demangled = demangler(line);
                    writeln!(stdout_lock, "{}", demangled).expect("Failed to write to stdout");
                } else {
                    writeln!(stdout_lock, "{}", line).expect("Failed to write to stdout");
                }
            }
            Err(e) => {
                log::error!("Error reading child stdout: {}", e);
                // TODO: panic? exit?
            }
        }
    }

    // Wait for the child process to finish
    // TODO: fail with the same exit code as the child
    child.wait()?;
    Ok(())
}
