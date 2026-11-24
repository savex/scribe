//! The operating system secret stores behind `keychain:`, `dpapi:` and `secret-service:`.
//! Each is compiled only on its own system; elsewhere the reference is `Unsupported`.

/// macOS keychain: a generic password item (`service`, `account`). A daemon running as root
/// finds items in the System keychain.
#[cfg(target_os = "macos")]
pub mod keychain {
    use security_framework::passwords;

    use crate::{Secret, SecretError};

    /// `errSecItemNotFound`.
    const NOT_FOUND: i32 = -25300;

    fn reference(service: &str, account: &str) -> String {
        format!("keychain:{service}/{account}")
    }

    pub fn read(service: &str, account: &str) -> Result<Secret, SecretError> {
        match passwords::get_generic_password(service, account) {
            Ok(bytes) if bytes.is_empty() => Err(SecretError::Store {
                reference: reference(service, account),
                why: "the item is empty".into(),
            }),
            Ok(bytes) => Ok(Secret(bytes)),
            Err(e) if e.code() == NOT_FOUND => {
                Err(SecretError::NotFound(reference(service, account)))
            }
            Err(e) => Err(SecretError::Store {
                reference: reference(service, account),
                why: e.to_string(),
            }),
        }
    }

    /// Create or replace the item.
    pub fn store(service: &str, account: &str, value: &[u8]) -> Result<(), SecretError> {
        passwords::set_generic_password(service, account, value).map_err(|e| SecretError::Store {
            reference: reference(service, account),
            why: e.to_string(),
        })
    }

    pub fn delete(service: &str, account: &str) -> Result<(), SecretError> {
        match passwords::delete_generic_password(service, account) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == NOT_FOUND => Ok(()),
            Err(e) => Err(SecretError::Store {
                reference: reference(service, account),
                why: e.to_string(),
            }),
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub mod keychain {
    use crate::{Secret, SecretError};

    pub fn read(_: &str, _: &str) -> Result<Secret, SecretError> {
        Err(SecretError::Unsupported("keychain"))
    }
    pub fn store(_: &str, _: &str, _: &[u8]) -> Result<(), SecretError> {
        Err(SecretError::Unsupported("keychain"))
    }
    pub fn delete(_: &str, _: &str) -> Result<(), SecretError> {
        Err(SecretError::Unsupported("keychain"))
    }
}

/// Windows DPAPI: the file holds a blob from `CryptProtectData` with machine scope, so the
/// service (LocalSystem or its service SID) and administrators can open it; the file's ACL keeps
/// everyone else away (installer, phase 13).
#[cfg(windows)]
pub mod dpapi {
    use std::path::Path;
    use std::ptr;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE,
        CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    use crate::{Secret, SecretError};

    fn failed(path: &Path, what: &str) -> SecretError {
        SecretError::Store {
            reference: format!("dpapi:{}", path.display()),
            why: format!("{what}: {}", std::io::Error::last_os_error()),
        }
    }

    /// Copy a blob DPAPI allocated, then free it.
    fn take(blob: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        // SAFETY: DPAPI returned `cbData` bytes at `pbData`, allocated with LocalAlloc.
        let bytes =
            unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize) }.to_vec();
        // SAFETY: the pointer came from DPAPI and is freed once.
        unsafe { LocalFree(blob.pbData.cast()) };
        bytes
    }

    pub fn read(path: &Path) -> Result<Secret, SecretError> {
        let sealed = std::fs::read(path).map_err(crate::io_err(path))?;
        let input = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(sealed.len()).map_err(|_| failed(path, "too large"))?,
            pbData: sealed.as_ptr().cast_mut(),
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };
        // SAFETY: input points at `sealed`, which outlives the call; output is written by DPAPI.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(failed(path, "cannot unprotect"));
        }
        let bytes = take(output);
        if bytes.is_empty() {
            return Err(SecretError::Insecure {
                path: path.to_owned(),
                why: "empty secret".into(),
            });
        }
        Ok(Secret(bytes))
    }

    /// Seal `value` and write it to `path`, replacing what was there.
    pub fn store(path: &Path, value: &[u8]) -> Result<(), SecretError> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(value.len()).map_err(|_| failed(path, "too large"))?,
            pbData: value.as_ptr().cast_mut(),
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };
        let description: Vec<u16> = "scribe secret\0".encode_utf16().collect();
        // SAFETY: input points at `value`, which outlives the call; output is written by DPAPI.
        let ok = unsafe {
            CryptProtectData(
                &input,
                description.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(failed(path, "cannot protect"));
        }
        crate::replace_file(path, &take(output))
    }
}

#[cfg(not(windows))]
pub mod dpapi {
    use std::path::Path;

    use crate::{Secret, SecretError};

    pub fn read(_: &Path) -> Result<Secret, SecretError> {
        Err(SecretError::Unsupported("dpapi"))
    }
    pub fn store(_: &Path, _: &[u8]) -> Result<(), SecretError> {
        Err(SecretError::Unsupported("dpapi"))
    }
}

/// Linux Secret Service (GNOME Keyring, KWallet) on the session bus, through `secret-service`
/// (pure-Rust D-Bus). Items carry the attributes `application = scribe` and
/// `scribe-secret = <label>`. Needs a session bus with an unlocked keyring, so it suits a desktop
/// user more than a system service.
#[cfg(target_os = "linux")]
pub mod secret_service {
    use std::collections::HashMap;

    use secret_service::blocking::SecretService;
    use secret_service::{EncryptionType, Error};

    use crate::{Secret, SecretError};

    fn failed(label: &str, e: Error) -> SecretError {
        let why = match e {
            Error::Unavailable => {
                "no Secret Service on the session bus (is a keyring running for this user?)"
                    .to_owned()
            }
            Error::Locked => "the keyring is locked".to_owned(),
            Error::Prompt | Error::PromptDisconnected => {
                "the keyring asked for a password, which a service can't give".to_owned()
            }
            other => other.to_string(),
        };
        SecretError::Store {
            reference: format!("secret-service:{label}"),
            why,
        }
    }

    fn attributes(label: &str) -> HashMap<&str, &str> {
        HashMap::from([("application", "scribe"), ("scribe-secret", label)])
    }

    pub fn read(label: &str) -> Result<Secret, SecretError> {
        let ss = SecretService::connect(EncryptionType::Dh).map_err(|e| failed(label, e))?;
        let found = ss
            .search_items(attributes(label))
            .map_err(|e| failed(label, e))?;
        let item = match (found.unlocked.first(), found.locked.first()) {
            (Some(item), _) => item,
            (None, Some(_)) => return Err(failed(label, Error::Locked)),
            (None, None) => return Err(SecretError::NotFound(format!("secret-service:{label}"))),
        };
        let bytes = item.get_secret().map_err(|e| failed(label, e))?;
        if bytes.is_empty() {
            return Err(failed(label, Error::NoResult));
        }
        Ok(Secret(bytes))
    }

    pub fn store(label: &str, value: &[u8]) -> Result<(), SecretError> {
        let ss = SecretService::connect(EncryptionType::Dh).map_err(|e| failed(label, e))?;
        let collection = ss.get_default_collection().map_err(|e| failed(label, e))?;
        collection.ensure_unlocked().map_err(|e| failed(label, e))?;
        collection
            .create_item(
                &format!("scribe: {label}"),
                attributes(label),
                value,
                true,
                "text/plain",
            )
            .map(drop)
            .map_err(|e| failed(label, e))
    }
}

#[cfg(not(target_os = "linux"))]
pub mod secret_service {
    use crate::{Secret, SecretError};

    pub fn read(_: &str) -> Result<Secret, SecretError> {
        Err(SecretError::Unsupported("secret-service"))
    }
    pub fn store(_: &str, _: &[u8]) -> Result<(), SecretError> {
        Err(SecretError::Unsupported("secret-service"))
    }
}
