use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn data_directory() -> Result<PathBuf, String> {
    let base = std::env::var_os("LOCALAPPDATA")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "LOCALAPPDATA is unavailable".to_owned())?;
    let directory = PathBuf::from(base).join("nancywebdebug");
    fs::create_dir_all(&directory)
        .map_err(|error| format!("unable to create {}: {error}", directory.display()))?;
    Ok(directory)
}

pub(crate) fn read_json_with_backup<T, F>(
    filename: &str,
    max_bytes: usize,
    validate: F,
) -> Result<(T, bool), String>
where
    T: DeserializeOwned,
    F: Fn(&T) -> Result<(), String>,
{
    let directory = data_directory()?;
    let primary = directory.join(filename);
    let backup = backup_path(&primary);
    let primary_result = read_validated_json(&primary, max_bytes, &validate);
    match primary_result {
        Ok(value) => Ok((value, false)),
        Err(primary_error) => match read_validated_json(&backup, max_bytes, &validate) {
            Ok(value) => Ok((value, true)),
            Err(backup_error) => Err(format!(
                "primary cache unavailable ({primary_error}); backup cache unavailable ({backup_error})"
            )),
        },
    }
}

pub(crate) fn write_json_with_backup<T: Serialize>(
    filename: &str,
    value: &T,
    max_bytes: usize,
) -> Result<(), String> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| format!("unable to serialize cache: {error}"))?;
    if bytes.len() > max_bytes {
        return Err(format!(
            "serialized cache is {} bytes, exceeding the {} byte limit",
            bytes.len(),
            max_bytes
        ));
    }
    let directory = data_directory()?;
    let primary = directory.join(filename);
    let backup = backup_path(&primary);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = directory.join(format!(".{filename}.{}.{}.tmp", std::process::id(), nonce));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("unable to create temporary cache: {error}"))?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("unable to write temporary cache: {error}"))?;
        drop(file);
        if primary.exists() {
            if backup.exists() {
                fs::remove_file(&backup)
                    .map_err(|error| format!("unable to replace cache backup: {error}"))?;
            }
            fs::rename(&primary, &backup)
                .map_err(|error| format!("unable to back up existing cache: {error}"))?;
        }
        if let Err(error) = fs::rename(&temporary, &primary) {
            if !primary.exists() && backup.exists() {
                let _ = fs::rename(&backup, &primary);
            }
            return Err(format!("unable to install cache: {error}"));
        }
        Ok(())
    })();
    if temporary.exists() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_validated_json<T, F>(path: &Path, max_bytes: usize, validate: &F) -> Result<T, String>
where
    T: DeserializeOwned,
    F: Fn(&T) -> Result<(), String>,
{
    let file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if metadata.len() > max_bytes as u64 {
        return Err(format!("{} exceeds the size limit", path.display()));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if bytes.len() > max_bytes {
        return Err(format!("{} exceeds the size limit", path.display()));
    }
    let value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("{} contains invalid JSON: {error}", path.display()))?;
    validate(&value)?;
    Ok(value)
}

fn backup_path(primary: &Path) -> PathBuf {
    PathBuf::from(format!("{}.bak", primary.display()))
}
