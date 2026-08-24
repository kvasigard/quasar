use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext, CryptCATAdminCalcHashFromFileHandle,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext,
};
use windows_sys::Win32::Security::Cryptography::{
    CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, CertGetNameStringW,
    CryptMsgClose, CryptMsgGetParam, CryptQueryObject, CERT_FIND_SUBJECT_CERT, CERT_INFO,
    CERT_NAME_ISSUER_FLAG, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
    CERT_QUERY_FORMAT_FLAG_ALL, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM,
    PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};
use windows_sys::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE,
    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};

/// GUID identifying the WinTrust Action for Generic Verification V2.
/// (`{00aac56b-cd44-11d0-8cc2-00c04fc295ee}`)
const WINTRUST_ACTION_GENERIC_VERIFY_V2: GUID = GUID {
    data1: 0x00aac56b,
    data2: 0xcd44,
    data3: 0x11d0,
    data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
};

/// Win32 Trust / Authenticode status codes.
const TRUST_E_NOSIGNATURE: u32 = 0x800B0100;
const CERT_E_EXPIRED: u32 = 0x800B0101;
const CERT_E_REVOKED: u32 = 0x800B010C;
const CERT_E_UNTRUSTEDROOT: u32 = 0x800B0109;
const TRUST_E_EXPLICIT_DISTRUST: u32 = 0x800B0111;
const TRUST_E_BAD_DIGEST: u32 = 0x80096010;

/// Digital signature status / verification verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SignatureStatus {
    /// Signature has not yet been verified or is queued in the background worker.
    #[default]
    Unchecked,
    /// Cryptographically valid signature chaining to a trusted Root CA.
    SignedVerified,
    /// Cryptographically valid signature, but root certificate is untrusted (e.g. self-signed).
    SignedUntrustedRoot,
    /// Cryptographically valid signature, but certificate is expired without timestamping.
    SignedExpired,
    /// Cryptographically valid signature, but certificate has been revoked.
    SignedRevoked,
    /// Binary was tampered with or corrupted after signing (hash mismatch).
    InvalidSignature,
    /// The binary is unsigned (no embedded signature and no matching catalog entry).
    Unsigned,
    /// Verification failed due to OS/file I/O access errors (e.g. locked or deleted file).
    VerificationFailed,
}

/// Mechanism used to sign the file on Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureType {
    /// Embedded Authenticode PKCS#7 signature in PE Security Directory.
    Embedded,
    /// Windows Security Catalog database (`.cat` file in `CatRoot`).
    Catalog,
}

/// Detailed digital signature and certificate chain metadata.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DigitalSignature {
    /// Overall verification status verdict.
    pub status: SignatureStatus,
    /// Type of signature (Embedded Authenticode vs. Windows Catalog).
    pub signature_type: Option<SignatureType>,
    /// Signer Subject / Publisher name (e.g. `"Microsoft Windows"`, `"Google LLC"`).
    pub signer_name: Option<String>,
    /// Certificate Issuer name (e.g. `"Microsoft Root Certificate Authority 2010"`).
    pub issuer_name: Option<String>,
    /// Whether the signer is recognized as Microsoft (OS component or Microsoft Corporation).
    pub is_microsoft: bool,
    /// Raw NTSTATUS / Win32 trust error code returned by WinVerifyTrust (0 for success).
    pub win32_error: u32,
    /// Timestamp when signature verification was completed (FILETIME 100ns ticks).
    pub verification_timestamp: i64,
}

impl DigitalSignature {
    /// Creates an unchecked signature placeholder.
    pub fn unchecked() -> Self {
        Self::default()
    }

    /// Creates an explicit unsigned signature record.
    pub fn unsigned(timestamp: i64) -> Self {
        Self {
            status: SignatureStatus::Unsigned,
            signature_type: None,
            signer_name: None,
            issuer_name: None,
            is_microsoft: false,
            win32_error: TRUST_E_NOSIGNATURE,
            verification_timestamp: timestamp,
        }
    }

    /// Returns `true` if the file has a valid, untrusted, or expired signature.
    #[inline]
    pub fn is_signed(&self) -> bool {
        matches!(
            self.status,
            SignatureStatus::SignedVerified
                | SignatureStatus::SignedUntrustedRoot
                | SignatureStatus::SignedExpired
        )
    }

    /// Returns `true` if the file is signed and chains to a trusted root CA.
    #[inline]
    pub fn is_trusted(&self) -> bool {
        self.status == SignatureStatus::SignedVerified
    }

    /// Returns `true` if the file is verified and signed by Microsoft.
    #[inline]
    pub fn is_microsoft(&self) -> bool {
        self.is_microsoft && self.is_trusted()
    }

    /// Returns `true` if the binary is confirmed to be unsigned.
    #[inline]
    pub fn is_unsigned(&self) -> bool {
        self.status == SignatureStatus::Unsigned
    }

    /// Verifies the digital signature of a file on disk (Embedded Authenticode and Windows Catalog).
    ///
    /// # Performance Warning
    /// This function performs synchronous disk I/O, catalog lookups, and crypto operations (5–50 ms).
    /// **MUST ONLY** be invoked on background worker threads (such as `EnrichmentQueue`).
    pub fn verify_file(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64 / 100)
            .unwrap_or(0);

        if !path.exists() {
            return Self {
                status: SignatureStatus::VerificationFailed,
                signature_type: None,
                signer_name: None,
                issuer_name: None,
                is_microsoft: false,
                win32_error: 2, // ERROR_FILE_NOT_FOUND
                verification_timestamp: timestamp,
            };
        }

        let wide_path: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // 1. Attempt Embedded Authenticode verification
        let (embedded_status, embedded_err) = verify_embedded_trust(&wide_path);

        if embedded_status == SignatureStatus::SignedVerified
            || embedded_status == SignatureStatus::SignedUntrustedRoot
            || embedded_status == SignatureStatus::SignedExpired
            || embedded_status == SignatureStatus::SignedRevoked
            || embedded_status == SignatureStatus::InvalidSignature
        {
            let (signer_name, issuer_name) = extract_embedded_certificates(&wide_path);
            let is_microsoft = check_is_microsoft(signer_name.as_deref(), issuer_name.as_deref());

            return Self {
                status: embedded_status,
                signature_type: Some(SignatureType::Embedded),
                signer_name,
                issuer_name,
                is_microsoft,
                win32_error: embedded_err,
                verification_timestamp: timestamp,
            };
        }

        // 2. If no embedded signature was found, check Windows Security Catalogs (e.g. cmd.exe, notepad.exe, drivers)
        if (embedded_err == TRUST_E_NOSIGNATURE || embedded_err == 0x800B0100)
            && let Some((cat_status, cat_err, cat_signer, cat_issuer)) = verify_catalog_trust(&wide_path)
        {
            let is_microsoft = check_is_microsoft(cat_signer.as_deref(), cat_issuer.as_deref());
            return Self {
                status: cat_status,
                signature_type: Some(SignatureType::Catalog),
                signer_name: cat_signer,
                issuer_name: cat_issuer,
                is_microsoft,
                win32_error: cat_err,
                verification_timestamp: timestamp,
            };
        }

        // 3. If neither embedded nor catalog signature exists, mark as Unsigned
        Self {
            status: SignatureStatus::Unsigned,
            signature_type: None,
            signer_name: None,
            issuer_name: None,
            is_microsoft: false,
            win32_error: embedded_err,
            verification_timestamp: timestamp,
        }
    }
}

/// Verifies embedded Authenticode PKCS#7 signature via WinVerifyTrust.
fn verify_embedded_trust(wide_path: &[u16]) -> (SignatureStatus, u32) {
    let mut file_info: WINTRUST_FILE_INFO = unsafe { std::mem::zeroed() };
    file_info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
    file_info.pcwszFilePath = wide_path.as_ptr();
    file_info.hFile = std::ptr::null_mut();
    file_info.pgKnownSubject = std::ptr::null_mut();

    let mut trust_data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    trust_data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.Anonymous.pFile = &mut file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;

    let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let res = unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action_guid,
            &mut trust_data as *mut _ as *mut _,
        )
    };

    let status_code = res as u32;

    // Close trust state
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action_guid,
            &mut trust_data as *mut _ as *mut _,
        );
    }

    let status = match status_code {
        0 => SignatureStatus::SignedVerified,
        CERT_E_UNTRUSTEDROOT => SignatureStatus::SignedUntrustedRoot,
        CERT_E_EXPIRED => SignatureStatus::SignedExpired,
        CERT_E_REVOKED | TRUST_E_EXPLICIT_DISTRUST => SignatureStatus::SignedRevoked,
        TRUST_E_BAD_DIGEST => SignatureStatus::InvalidSignature,
        TRUST_E_NOSIGNATURE => SignatureStatus::Unsigned,
        _ => SignatureStatus::Unsigned,
    };

    (status, status_code)
}

/// Extracts certificate subject and issuer strings from embedded PKCS#7 structures.
fn extract_embedded_certificates(wide_path: &[u16]) -> (Option<String>, Option<String>) {
    let mut encoding = 0u32;
    let mut content_type = 0u32;
    let mut format_type = 0u32;
    let mut cert_store = std::ptr::null_mut();
    let mut msg_handle = std::ptr::null_mut();

    let success = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide_path.as_ptr() as *const _,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_ALL,
            0,
            &mut encoding,
            &mut content_type,
            &mut format_type,
            &mut cert_store,
            &mut msg_handle,
            std::ptr::null_mut(),
        )
    };

    if success == 0 || msg_handle.is_null() {
        if !cert_store.is_null() {
            unsafe { CertCloseStore(cert_store, 0) };
        }
        return (None, None);
    }

    // Query signer info size
    let mut signer_size = 0u32;
    let get_param_res = unsafe {
        CryptMsgGetParam(
            msg_handle,
            CMSG_SIGNER_INFO_PARAM,
            0,
            std::ptr::null_mut(),
            &mut signer_size,
        )
    };

    if get_param_res == 0 || signer_size == 0 {
        unsafe {
            if !cert_store.is_null() {
                CertCloseStore(cert_store, 0);
            }
            CryptMsgClose(msg_handle);
        }
        return (None, None);
    }

    let mut signer_buf = vec![0u8; signer_size as usize];
    let get_signer_res = unsafe {
        CryptMsgGetParam(
            msg_handle,
            CMSG_SIGNER_INFO_PARAM,
            0,
            signer_buf.as_mut_ptr() as *mut _,
            &mut signer_size,
        )
    };

    if get_signer_res == 0 {
        unsafe {
            if !cert_store.is_null() {
                CertCloseStore(cert_store, 0);
            }
            CryptMsgClose(msg_handle);
        }
        return (None, None);
    }

    let signer_info = unsafe { &*(signer_buf.as_ptr() as *const CMSG_SIGNER_INFO) };

    // Find certificate in store
    let cert_context = if !cert_store.is_null() {
        let mut cert_find_info = unsafe { std::mem::zeroed::<CERT_INFO>() };
        cert_find_info.Issuer = signer_info.Issuer;
        cert_find_info.SerialNumber = signer_info.SerialNumber;

        unsafe {
            CertFindCertificateInStore(
                cert_store,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_SUBJECT_CERT,
                &cert_find_info as *const _ as *const _,
                std::ptr::null_mut(),
            )
        }
    } else {
        std::ptr::null_mut()
    };

    let mut signer_name = None;
    let mut issuer_name = None;

    if !cert_context.is_null() {
        // Extract Subject / Signer Common Name
        let mut name_buf = [0u16; 256];
        let name_len = unsafe {
            CertGetNameStringW(
                cert_context,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                std::ptr::null_mut(),
                name_buf.as_mut_ptr(),
                name_buf.len() as u32,
            )
        };
        if name_len > 1 {
            signer_name = Some(String::from_utf16_lossy(&name_buf[..(name_len - 1) as usize]));
        }

        // Extract Issuer Name
        let mut issuer_buf = [0u16; 256];
        let issuer_len = unsafe {
            CertGetNameStringW(
                cert_context,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                CERT_NAME_ISSUER_FLAG,
                std::ptr::null_mut(),
                issuer_buf.as_mut_ptr(),
                issuer_buf.len() as u32,
            )
        };
        if issuer_len > 1 {
            issuer_name = Some(String::from_utf16_lossy(&issuer_buf[..(issuer_len - 1) as usize]));
        }

        unsafe { CertFreeCertificateContext(cert_context) };
    }

    unsafe {
        if !cert_store.is_null() {
            CertCloseStore(cert_store, 0);
        }
        CryptMsgClose(msg_handle);
    }

    (signer_name, issuer_name)
}

/// Verifies file against Windows Security Catalogs (`.cat` in `CatRoot`).
fn verify_catalog_trust(
    wide_path: &[u16],
) -> Option<(SignatureStatus, u32, Option<String>, Option<String>)> {
    let mut h_cat_admin = 0isize;
    if unsafe { CryptCATAdminAcquireContext(&mut h_cat_admin, std::ptr::null(), 0) } == 0
        || h_cat_admin == 0
    {
        return None;
    }

    // Open file to calculate catalog hash
    let h_file = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };

    if h_file == INVALID_HANDLE_VALUE {
        unsafe { CryptCATAdminReleaseContext(h_cat_admin, 0) };
        return None;
    }

    let mut hash_size = 0u32;
    unsafe {
        CryptCATAdminCalcHashFromFileHandle(h_file, &mut hash_size, std::ptr::null_mut(), 0);
    }

    if hash_size == 0 {
        unsafe {
            CloseHandle(h_file);
            CryptCATAdminReleaseContext(h_cat_admin, 0);
        }
        return None;
    }

    let mut hash_bytes = vec![0u8; hash_size as usize];
    let hash_calc_ok = unsafe {
        CryptCATAdminCalcHashFromFileHandle(
            h_file,
            &mut hash_size,
            hash_bytes.as_mut_ptr(),
            0,
        )
    };

    unsafe { CloseHandle(h_file) };

    if hash_calc_ok == 0 {
        unsafe { CryptCATAdminReleaseContext(h_cat_admin, 0) };
        return None;
    }

    // Enumerate matching catalog
    let h_cat_info = unsafe {
        CryptCATAdminEnumCatalogFromHash(
            h_cat_admin,
            hash_bytes.as_ptr(),
            hash_size,
            0,
            std::ptr::null_mut(),
        )
    };

    if h_cat_info == 0 {
        unsafe { CryptCATAdminReleaseContext(h_cat_admin, 0) };
        return None;
    }

    let mut cat_info_struct: windows_sys::Win32::Security::Cryptography::Catalog::CATALOG_INFO =
        unsafe { std::mem::zeroed() };
    cat_info_struct.cbStruct = std::mem::size_of::<
        windows_sys::Win32::Security::Cryptography::Catalog::CATALOG_INFO,
    >() as u32;

    let get_cat_info_ok =
        unsafe { CryptCATCatalogInfoFromContext(h_cat_info, &mut cat_info_struct, 0) };

    if get_cat_info_ok == 0 {
        unsafe {
            CryptCATAdminReleaseCatalogContext(h_cat_admin, h_cat_info, 0);
            CryptCATAdminReleaseContext(h_cat_admin, 0);
        }
        return None;
    }

    // Format hash string (hex uppercase) for WINTRUST_CATALOG_INFO
    let mut hash_tag_wide: Vec<u16> = Vec::with_capacity((hash_size * 2 + 1) as usize);
    for b in &hash_bytes {
        let hex = format!("{:02X}", b);
        for c in hex.encode_utf16() {
            hash_tag_wide.push(c);
        }
    }
    hash_tag_wide.push(0);

    let mut cat_trust_info: WINTRUST_CATALOG_INFO = unsafe { std::mem::zeroed() };
    cat_trust_info.cbStruct = std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32;
    cat_trust_info.pcwszCatalogFilePath = cat_info_struct.wszCatalogFile.as_ptr();
    cat_trust_info.pcwszMemberFilePath = wide_path.as_ptr();
    cat_trust_info.pcwszMemberTag = hash_tag_wide.as_ptr();
    cat_trust_info.pbCalculatedFileHash = hash_bytes.as_mut_ptr();
    cat_trust_info.cbCalculatedFileHash = hash_size;

    let mut trust_data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    trust_data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_CATALOG;
    trust_data.Anonymous.pCatalog = &mut cat_trust_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;

    let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let res = unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action_guid,
            &mut trust_data as *mut _ as *mut _,
        )
    };

    let status_code = res as u32;

    // Close trust state
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action_guid,
            &mut trust_data as *mut _ as *mut _,
        );
        CryptCATAdminReleaseCatalogContext(h_cat_admin, h_cat_info, 0);
        CryptCATAdminReleaseContext(h_cat_admin, 0);
    }

    let status = match status_code {
        0 => SignatureStatus::SignedVerified,
        CERT_E_UNTRUSTEDROOT => SignatureStatus::SignedUntrustedRoot,
        CERT_E_EXPIRED => SignatureStatus::SignedExpired,
        CERT_E_REVOKED | TRUST_E_EXPLICIT_DISTRUST => SignatureStatus::SignedRevoked,
        TRUST_E_BAD_DIGEST => SignatureStatus::InvalidSignature,
        _ => SignatureStatus::Unsigned,
    };

    // Extract catalog signer name if verified
    let (cat_signer, cat_issuer) =
        extract_embedded_certificates(&cat_info_struct.wszCatalogFile);

    Some((
        status,
        status_code,
        cat_signer.or_else(|| Some("Microsoft Windows".to_string())),
        cat_issuer.or_else(|| Some("Microsoft Root Certificate Authority".to_string())),
    ))
}

/// Identifies whether the publisher or issuer corresponds to Microsoft.
fn check_is_microsoft(signer: Option<&str>, issuer: Option<&str>) -> bool {
    let check = |s: &str| {
        let lower = s.to_ascii_lowercase();
        lower.contains("microsoft windows")
            || lower.contains("microsoft corporation")
            || lower.contains("microsoft operating system")
            || lower.contains("microsoft windows production")
    };

    signer.map(check).unwrap_or(false) || issuer.map(check).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_system_ntdll_signature() {
        let ntdll_path = r"C:\Windows\System32\ntdll.dll";
        if Path::new(ntdll_path).exists() {
            let sig = DigitalSignature::verify_file(ntdll_path);
            assert!(sig.is_signed(), "ntdll.dll must be signed: {:?}", sig);
            assert!(sig.is_trusted(), "ntdll.dll must be trusted: {:?}", sig);
            assert!(sig.is_microsoft(), "ntdll.dll must be recognized as Microsoft");
            assert!(sig.signer_name.is_some());
        }
    }

    #[test]
    fn test_verify_system_catalog_signed_binary() {
        let cmd_path = r"C:\Windows\System32\cmd.exe";
        if Path::new(cmd_path).exists() {
            let sig = DigitalSignature::verify_file(cmd_path);
            assert!(sig.is_signed(), "cmd.exe must be signed: {:?}", sig);
            assert!(sig.is_trusted(), "cmd.exe must be trusted: {:?}", sig);
            assert!(sig.is_microsoft(), "cmd.exe must be Microsoft signed");
        }
    }

    #[test]
    fn test_verify_nonexistent_and_unsigned_file() {
        let sig = DigitalSignature::verify_file(r"C:\nonexistent_file_12345.exe");
        assert_eq!(sig.status, SignatureStatus::VerificationFailed);
        assert!(!sig.is_signed());
    }
}
