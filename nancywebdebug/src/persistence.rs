use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn data_directory() -> Result<PathBuf, String> {
    #[cfg(target_os = "linux")]
    let directory = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .map(|path| path.join(".local").join("nancywebdebug"))
        .ok_or_else(|| "HOME is unavailable".to_owned())?;
    #[cfg(not(target_os = "linux"))]
    let directory = {
        let base = std::env::var_os("LOCALAPPDATA")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "LOCALAPPDATA is unavailable".to_owned())?;
        PathBuf::from(base).join("nancywebdebug")
    };
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
    let backup = {
        let (primary,): (&Path,) = (&primary,);
        let inlined_result: PathBuf = { PathBuf::from(format!("{}.bak", primary.display())) };
        inlined_result
    };
    let primary_result = {
        let (path, max_bytes, validate): (&Path, usize, &F) = (&primary, max_bytes, &validate);
        let inlined_result: Result<T, String> = {
            'inlined_read_validated_json: {
                let file = match File::open(path)
                    .map_err(|error| format!("{}: {error}", path.display()))
                {
                    Ok(value) => value,
                    Err(error) => {
                        break 'inlined_read_validated_json Err(::core::convert::From::from(error));
                    }
                };
                let metadata = match file
                    .metadata()
                    .map_err(|error| format!("{}: {error}", path.display()))
                {
                    Ok(value) => value,
                    Err(error) => {
                        break 'inlined_read_validated_json Err(::core::convert::From::from(error));
                    }
                };
                if metadata.len() > max_bytes as u64 {
                    break 'inlined_read_validated_json Err(format!(
                        "{} exceeds the size limit",
                        path.display()
                    ));
                }
                let mut bytes = Vec::with_capacity(metadata.len() as usize);
                match file
                    .take(max_bytes as u64 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|error| format!("{}: {error}", path.display()))
                {
                    Ok(value) => value,
                    Err(error) => {
                        break 'inlined_read_validated_json Err(::core::convert::From::from(error));
                    }
                };
                if bytes.len() > max_bytes {
                    break 'inlined_read_validated_json Err(format!(
                        "{} exceeds the size limit",
                        path.display()
                    ));
                }
                let value = match serde_json::from_slice(&bytes)
                    .map_err(|error| format!("{} contains invalid JSON: {error}", path.display()))
                {
                    Ok(value) => value,
                    Err(error) => {
                        break 'inlined_read_validated_json Err(::core::convert::From::from(error));
                    }
                };
                match validate(&value) {
                    Ok(value) => value,
                    Err(error) => {
                        break 'inlined_read_validated_json Err(::core::convert::From::from(error));
                    }
                };
                Ok(value)
            }
        };
        inlined_result
    };
    match primary_result {
        Ok(value) => Ok((value, false)),
        Err(primary_error) => match {
            let (path, max_bytes, validate): (&Path, usize, &F) = (&backup, max_bytes, &validate);
            let inlined_result: Result<T, String> = {
                'inlined_read_validated_json: {
                    let file = match File::open(path)
                        .map_err(|error| format!("{}: {error}", path.display()))
                    {
                        Ok(value) => value,
                        Err(error) => {
                            break 'inlined_read_validated_json Err(::core::convert::From::from(
                                error,
                            ));
                        }
                    };
                    let metadata = match file
                        .metadata()
                        .map_err(|error| format!("{}: {error}", path.display()))
                    {
                        Ok(value) => value,
                        Err(error) => {
                            break 'inlined_read_validated_json Err(::core::convert::From::from(
                                error,
                            ));
                        }
                    };
                    if metadata.len() > max_bytes as u64 {
                        break 'inlined_read_validated_json Err(format!(
                            "{} exceeds the size limit",
                            path.display()
                        ));
                    }
                    let mut bytes = Vec::with_capacity(metadata.len() as usize);
                    match file
                        .take(max_bytes as u64 + 1)
                        .read_to_end(&mut bytes)
                        .map_err(|error| format!("{}: {error}", path.display()))
                    {
                        Ok(value) => value,
                        Err(error) => {
                            break 'inlined_read_validated_json Err(::core::convert::From::from(
                                error,
                            ));
                        }
                    };
                    if bytes.len() > max_bytes {
                        break 'inlined_read_validated_json Err(format!(
                            "{} exceeds the size limit",
                            path.display()
                        ));
                    }
                    let value = match serde_json::from_slice(&bytes).map_err(|error| {
                        format!("{} contains invalid JSON: {error}", path.display())
                    }) {
                        Ok(value) => value,
                        Err(error) => {
                            break 'inlined_read_validated_json Err(::core::convert::From::from(
                                error,
                            ));
                        }
                    };
                    match validate(&value) {
                        Ok(value) => value,
                        Err(error) => {
                            break 'inlined_read_validated_json Err(::core::convert::From::from(
                                error,
                            ));
                        }
                    };
                    Ok(value)
                }
            };
            inlined_result
        } {
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
    let backup = {
        let (primary,): (&Path,) = (&primary,);
        let inlined_result: PathBuf = { PathBuf::from(format!("{}.bak", primary.display())) };
        inlined_result
    };
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
