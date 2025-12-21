// Copyright (c) 2025 Denys Fedoryshchenko <denys.f@collabora.com>
// SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-Proprietary

use chrono::Local;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use crate::Result;

pub struct Logger {
    file: Option<Mutex<File>>,
}

impl Logger {
    pub fn new(path: Option<&Path>) -> Result<Self> {
        if let Some(path) = path {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent).map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("failed to create log directory {}: {}", parent.display(), e),
                    )
                })?;
            }
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("failed to open log file {}: {}", path.display(), e),
                    )
                })?;
            Ok(Self {
                file: Some(Mutex::new(file)),
            })
        } else {
            Ok(Self { file: None })
        }
    }

    pub fn log(&self, level: &str, msg: &str) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
        let line = format!("[{} {}] {}", timestamp, level, msg);
        println!("{}", line);
        if let Some(file) = &self.file
            && let Ok(mut file) = file.lock()
        {
            let _ = writeln!(file, "{}", line);
        }
    }

    pub fn debug(&self, enabled: bool, msg: &str) {
        if enabled {
            self.log("DEBUG", msg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_path() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!("nanoradius-log-{}.log", nanos));
        path
    }

    #[test]
    fn creates_missing_parent_directories() {
        let mut path = unique_path();
        path.pop();
        path.push("nested");
        path.push("logfile.log");
        let logger = Logger::new(Some(&path)).expect("logger created");
        logger.log("INFO", "hello");
        let contents = fs::read_to_string(&path).expect("log file read");
        assert!(contents.contains("hello"));
    }

    #[test]
    fn skips_file_write_when_no_path() {
        let logger = Logger::new(None).expect("logger created");
        logger.log("INFO", "stdout-only");
        // No panic means success; nothing to assert on stdout here.
    }
}
