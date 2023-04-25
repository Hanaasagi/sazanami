use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use anyhow::Result;
use tracing::info;

// system default resolv.conf path
pub const DEFAULT_RESOVLV_CONF_PATH: &str = "/etc/resolv.conf";

/// ResolvConfig is a wrapper for resolv.conf, for update and restore
pub struct ResolvConfig<'a> {
    config_path: Box<dyn AsRef<Path> + 'a>,
    // back user's original resolv.conf
    original_content: Vec<u8>,
    restore_when_drop: bool,
}

impl<'a> ResolvConfig<'a> {
    /// Create a new ResolvConfig
    pub fn new<P: AsRef<Path> + 'a>(file_path: P, restore_when_drop: bool) -> Self {
        // just panic if meet a fatal error
        let data = fs::read(&file_path).expect("Failed to open resovle config file for read");

        ResolvConfig {
            config_path: Box::new(file_path),
            original_content: data,
            restore_when_drop,
        }
    }

    fn gen_config(dns: &[String]) -> Vec<u8> {
        let mut data = vec![];
        for item in dns.iter() {
            if !item.is_empty() {
                data.extend_from_slice(format!("nameserver {}\n", item).as_bytes());
            }
        }
        data
    }

    /// Update resolv.conf
    pub fn update(&self, servers: &[String]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(self.config_path.as_ref())?;

        // file.set_len(0)?;
        // file.rewind()?;

        let buf = Self::gen_config(servers);
        file.write_all(&buf)?;

        Ok(())
    }

    /// Restore original resolv.conf
    pub fn restore(&self) {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(self.config_path.as_ref())
            .expect("Failed to open resovle config file {} for write");

        file.write_all(&self.original_content)
            .expect("Failed to write resovle config file");
    }
}

impl<'a> Drop for ResolvConfig<'a> {
    fn drop(&mut self) {
        if self.restore_when_drop {
            info!("Auto restore user's original dns");
            self.restore();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::ResolvConfig;

    #[test]
    fn test_read() {
        let mut fake_file = NamedTempFile::new().expect("Failed to create tempfile");
        let content = b"nameserver 8.8.8.8\nnameserver 1.1.1.1\n";
        fake_file
            .write_all(content)
            .expect("Failed to write tempfile");

        let config = ResolvConfig::new(&fake_file, true);
        assert_eq!(config.original_content, content);
    }

    #[test]
    fn test_update() {
        let mut fake_file = NamedTempFile::new().expect("Failed to create tempfile");
        let content = b"nameserver 114.114.114.114\n";
        fake_file
            .write_all(content)
            .expect("Failed to write tempfile");

        let config = ResolvConfig::new(&fake_file, true);
        config
            .update(&["8.8.8.8".to_string(), "1.1.1.1".to_string()])
            .unwrap();

        let new_content = fs::read(&fake_file).unwrap();
        assert_eq!(new_content, b"nameserver 8.8.8.8\nnameserver 1.1.1.1\n");

        drop(config);

        let new_content = fs::read(&fake_file).unwrap();
        assert_eq!(new_content, b"nameserver 114.114.114.114\n");
    }

    #[test]
    fn test_restore_when_drop() {
        let mut fake_file = NamedTempFile::new().expect("Failed to create tempfile");
        let buf = b"nameserver 8.8.8.8\nnameserver 1.1.1.1\n";
        fake_file.write_all(buf).expect("Failed to write tempfile");

        let config = ResolvConfig::new(&fake_file, true);

        drop(config);

        let new_content = fs::read(&fake_file).unwrap();
        assert_eq!(new_content, b"nameserver 8.8.8.8\nnameserver 1.1.1.1\n");
    }
}
