// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::{Path, PathBuf};
use std::str::FromStr;
use strum::EnumString;
use tempfile::tempdir_in;
use thiserror::Error;
const TSM_REPORT_PATH: &str = "/sys/kernel/config/tsm/report";
const SVSM_SERVICE_PROVIDER: &str = "svsm";
pub const SVSM_VTPM_SERVICE_GUID: &str = "c476f1eb-0123-45a5-9641-b4e7dde5bfe3";
const SVSM_REPORT_DATA_SIZE: usize = 64;

#[derive(Error, Debug)]
pub enum TsmReportError {
    #[error("Failed to access TSM Report path")]
    NoTsmReports,
    #[error("Failed to create TSM Report path instance: {0}")]
    Open(#[from] std::io::Error),
    #[error("Failed to access TSM Report attribute: {0} ({1})")]
    Access(&'static str, #[source] std::io::Error),
    #[error("Failed to parse TSM Report attribute 'generation': {0}")]
    Parse(#[source] std::num::ParseIntError),
    #[error("Failed to open TSM Report path: missing provider {0:?} (provider={1:?})")]
    MissingProvider(TsmReportProvider, TsmReportProvider),
    #[error("Failed to open TSM Report path: unknown provider ({0})")]
    UnknownProvider(#[from] strum::ParseError),
    #[error("Failed to generate TSM Report: inblob write conflict (generation={0}, expected 1)")]
    InblobConflict(u32),
    #[error("Failed to generate TSM Report: missing inblob (len=0)")]
    InblobLen,
    #[error("Failed to generate SVSM TSM Report: invalid inblob length (len={0}, expected 64)")]
    SvsmInblobLen(usize),
    #[error("Failed to generate SVSM TSM Report: missing manifestblob (len=0)")]
    SvsmManifestLen,
    #[error(
        "Failed to generate SVSM TSM Report: write conflict (generation={generation}, expected {expected})"
    )]
    SvsmWriteConflict { generation: u32, expected: u32 },
}

#[derive(PartialEq, Debug, EnumString)]
pub enum TsmReportProvider {
    #[strum(serialize = "arm_cca_guest\n")]
    Cca,
    #[strum(serialize = "tdx_guest\n")]
    Tdx,
    #[strum(serialize = "sev_guest\n")]
    Sev,
}

pub enum TsmReportData {
    Cca(Vec<u8>),
    Tdx(Vec<u8>),
    Sev(Vec<u8>),
}

/// Input for an SVSM vTPM attestation request.
///
/// The report data is passed to SVSM as a 64-byte nonce. When
/// `service_manifest_version` is `None`, SVSM returns the service's default
/// manifest version.
#[derive(Debug)]
pub struct SvsmVtpmReportRequest {
    pub report_data: Vec<u8>,
    pub service_manifest_version: Option<u32>,
}

/// Raw blobs returned by an SVSM vTPM attestation request.
#[derive(Debug, PartialEq)]
pub struct SvsmVtpmReportResponse {
    /// SNP attestation report whose REPORT_DATA binds the nonce and manifest.
    pub report: Vec<u8>,
    /// vTPM service manifest containing the EK public area.
    pub manifest: Vec<u8>,
    /// Optional certificate table returned with the SNP report.
    pub auxiliary: Vec<u8>,
}

/// TsmReportPath instance represents a unique path on ConfigFS
/// provided by the TSM_REPORT attestation ABI. Currently, each
/// instance is a one-shot attestation request and the path is
/// automatically removed when the instance goes out of scope.
pub struct TsmReportPath {
    path: PathBuf,
}

impl Drop for TsmReportPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(self.path.as_path())
            .map_err(|e| tracing::error!("Failed to remove TSM Report directory: {e}"));
    }
}

impl TsmReportPath {
    pub fn new(wanted: TsmReportProvider) -> Result<Self, TsmReportError> {
        if !Path::new(TSM_REPORT_PATH).exists() {
            return Err(TsmReportError::NoTsmReports);
        }

        let p = tempdir_in(TSM_REPORT_PATH).map_err(TsmReportError::Open)?;

        // Remove the Drop set by tempdir_in() since it errors on ConfigFS
        // and leaks the created path. We implement our own Drop that removes the
        // path (rmdir way) when TsmReportPath instance goes out of scope.
        let path = p.keep();

        check_tsm_report_provider(path.as_path(), wanted).inspect_err(|_| {
            let _ = std::fs::remove_dir(path.as_path());
        })?;

        Ok(Self { path })
    }

    pub fn attestation_report(
        &self,
        provider_data: TsmReportData,
    ) -> Result<Vec<u8>, TsmReportError> {
        let report_path = self.path.as_path();

        let report_data = match provider_data {
            TsmReportData::Cca(inblob) => inblob,
            TsmReportData::Tdx(inblob) => inblob,
            TsmReportData::Sev(inblob) => inblob,
        };

        if report_data.is_empty() {
            return Err(TsmReportError::InblobLen);
        }

        std::fs::write(report_path.join("inblob"), report_data)
            .map_err(|e| TsmReportError::Access("inblob", e))?;

        let q = std::fs::read(report_path.join("outblob"))
            .map_err(|e| TsmReportError::Access("outblob", e))?;

        check_inblob_write_race(report_path)?;

        Ok(q)
    }

    pub fn supplemental_data(&self) -> Result<Vec<u8>, TsmReportError> {
        let report_path = self.path.as_path();

        let aux = std::fs::read(report_path.join("auxblob"))
            .map_err(|e| TsmReportError::Access("auxblob", e))?;

        check_inblob_write_race(report_path)?;

        Ok(aux)
    }

    /// Request an SNP attestation report and vTPM manifest from SVSM.
    pub fn svsm_vtpm_attestation_report(
        &self,
        request: SvsmVtpmReportRequest,
    ) -> Result<SvsmVtpmReportResponse, TsmReportError> {
        svsm_vtpm_attestation_report(self.path.as_path(), request)
    }
}

fn svsm_vtpm_attestation_report(
    report_path: &Path,
    request: SvsmVtpmReportRequest,
) -> Result<SvsmVtpmReportResponse, TsmReportError> {
    if request.report_data.len() != SVSM_REPORT_DATA_SIZE {
        return Err(TsmReportError::SvsmInblobLen(request.report_data.len()));
    }

    // Configure the SVSM service before writing inblob, which triggers report
    // generation. A non-null GUID selects the vTPM single-service request.
    std::fs::write(report_path.join("service_provider"), SVSM_SERVICE_PROVIDER)
        .map_err(|e| TsmReportError::Access("service_provider", e))?;
    std::fs::write(report_path.join("service_guid"), SVSM_VTPM_SERVICE_GUID)
        .map_err(|e| TsmReportError::Access("service_guid", e))?;

    let mut expected_generation = 2;
    if let Some(version) = request.service_manifest_version {
        std::fs::write(
            report_path.join("service_manifest_version"),
            version.to_string(),
        )
        .map_err(|e| TsmReportError::Access("service_manifest_version", e))?;
        expected_generation += 1;
    }

    std::fs::write(report_path.join("inblob"), request.report_data)
        .map_err(|e| TsmReportError::Access("inblob", e))?;
    expected_generation += 1;

    let report = std::fs::read(report_path.join("outblob"))
        .map_err(|e| TsmReportError::Access("outblob", e))?;
    let manifest = std::fs::read(report_path.join("manifestblob"))
        .map_err(|e| TsmReportError::Access("manifestblob", e))?;
    let auxiliary = std::fs::read(report_path.join("auxblob"))
        .map_err(|e| TsmReportError::Access("auxblob", e))?;

    check_svsm_write_race(report_path, expected_generation)?;

    if manifest.is_empty() {
        return Err(TsmReportError::SvsmManifestLen);
    }

    Ok(SvsmVtpmReportResponse {
        report,
        manifest,
        auxiliary,
    })
}

/// check_inblob_write_race checks that the returned outblob/auxblob
/// matches the quote generation request originally triggered when
/// inblob was written by the TsmReportPath instance. It prevents
/// the race condition that someone else could use the same temporary
/// directory to generate a quote.
fn check_inblob_write_race(report_path: &Path) -> Result<(), TsmReportError> {
    let generation = read_generation(report_path)?;

    if generation > 1 {
        return Err(TsmReportError::InblobConflict(generation));
    }

    Ok(())
}

fn check_svsm_write_race(
    report_path: &Path,
    expected_generation: u32,
) -> Result<(), TsmReportError> {
    let generation = read_generation(report_path)?;

    if generation != expected_generation {
        return Err(TsmReportError::SvsmWriteConflict {
            generation,
            expected: expected_generation,
        });
    }

    Ok(())
}

fn read_generation(report_path: &Path) -> Result<u32, TsmReportError> {
    let generation = std::fs::read_to_string(report_path.join("generation"))
        .map_err(|e| TsmReportError::Access("generation", e))?;

    generation
        .trim_matches('\n')
        .parse::<u32>()
        .map_err(TsmReportError::Parse)
}

/// check_tsm_report_provider checks that the TEE is
/// the requested TsmReportProvider.
fn check_tsm_report_provider(
    report_path: &Path,
    wanted: TsmReportProvider,
) -> Result<(), TsmReportError> {
    let report_provider = std::fs::read_to_string(report_path.join("provider"))
        .map_err(|e| TsmReportError::Access("provider", e))?;

    match TsmReportProvider::from_str(&report_provider) {
        Ok(provider) => {
            if provider == wanted {
                Ok(())
            } else {
                Err(TsmReportError::MissingProvider(wanted, provider))
            }
        }
        Err(e) => Err(TsmReportError::UnknownProvider(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case("provider", "tdx_guest\n", false)]
    #[case("provider", "sev_guest\n", true)]
    #[case("provider", "foo_guest\n", true)]
    #[case("generation", "1\n", false)]
    #[case("generation", "2\n", true)]
    #[case("generation", "parseerror\n", true)]
    fn test_tsm_report(#[case] file: &str, #[case] file_data: &str, #[case] expect_error: bool) {
        let tsm_dir = tempfile::tempdir().unwrap();

        std::fs::write(tsm_dir.path().join(file), file_data).unwrap();

        match file {
            "provider" => assert_eq!(
                expect_error,
                check_tsm_report_provider(tsm_dir.path(), TsmReportProvider::Tdx).is_err()
            ),
            "generation" => assert_eq!(
                expect_error,
                check_inblob_write_race(tsm_dir.path()).is_err(),
            ),
            _ => unimplemented!(),
        }
    }

    fn create_svsm_test_report(generation: u32, manifest: &[u8]) -> tempfile::TempDir {
        let tsm_dir = tempfile::tempdir().unwrap();

        std::fs::write(tsm_dir.path().join("generation"), generation.to_string()).unwrap();
        std::fs::write(tsm_dir.path().join("outblob"), b"snp-report").unwrap();
        std::fs::write(tsm_dir.path().join("manifestblob"), manifest).unwrap();
        std::fs::write(tsm_dir.path().join("auxblob"), b"certificates").unwrap();

        tsm_dir
    }

    #[test]
    fn test_svsm_vtpm_report_without_manifest_version() {
        let tsm_dir = create_svsm_test_report(3, b"ek-public");
        let report_data = vec![0x5a; SVSM_REPORT_DATA_SIZE];

        let response = svsm_vtpm_attestation_report(
            tsm_dir.path(),
            SvsmVtpmReportRequest {
                report_data: report_data.clone(),
                service_manifest_version: None,
            },
        )
        .unwrap();

        assert_eq!(response.report, b"snp-report");
        assert_eq!(response.manifest, b"ek-public");
        assert_eq!(response.auxiliary, b"certificates");
        assert_eq!(
            std::fs::read_to_string(tsm_dir.path().join("service_provider")).unwrap(),
            SVSM_SERVICE_PROVIDER
        );
        assert_eq!(
            std::fs::read_to_string(tsm_dir.path().join("service_guid")).unwrap(),
            SVSM_VTPM_SERVICE_GUID
        );
        assert_eq!(
            std::fs::read(tsm_dir.path().join("inblob")).unwrap(),
            report_data
        );
        assert!(!tsm_dir.path().join("service_manifest_version").exists());
    }

    #[test]
    fn test_svsm_vtpm_report_with_manifest_version() {
        let tsm_dir = create_svsm_test_report(4, b"ek-public");

        svsm_vtpm_attestation_report(
            tsm_dir.path(),
            SvsmVtpmReportRequest {
                report_data: vec![0; SVSM_REPORT_DATA_SIZE],
                service_manifest_version: Some(2),
            },
        )
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(tsm_dir.path().join("service_manifest_version")).unwrap(),
            "2"
        );
    }

    #[rstest]
    #[case(0)]
    #[case(63)]
    #[case(65)]
    fn test_svsm_vtpm_report_rejects_invalid_report_data_length(#[case] length: usize) {
        let tsm_dir = tempfile::tempdir().unwrap();

        let result = svsm_vtpm_attestation_report(
            tsm_dir.path(),
            SvsmVtpmReportRequest {
                report_data: vec![0; length],
                service_manifest_version: None,
            },
        );

        assert!(matches!(result, Err(TsmReportError::SvsmInblobLen(len)) if len == length));
        assert!(!tsm_dir.path().join("service_provider").exists());
    }

    #[test]
    fn test_svsm_vtpm_report_rejects_empty_manifest() {
        let tsm_dir = create_svsm_test_report(3, b"");

        let result = svsm_vtpm_attestation_report(
            tsm_dir.path(),
            SvsmVtpmReportRequest {
                report_data: vec![0; SVSM_REPORT_DATA_SIZE],
                service_manifest_version: None,
            },
        );

        assert!(matches!(result, Err(TsmReportError::SvsmManifestLen)));
    }

    #[test]
    fn test_svsm_vtpm_report_detects_write_conflict() {
        let tsm_dir = create_svsm_test_report(4, b"ek-public");

        let result = svsm_vtpm_attestation_report(
            tsm_dir.path(),
            SvsmVtpmReportRequest {
                report_data: vec![0; SVSM_REPORT_DATA_SIZE],
                service_manifest_version: None,
            },
        );

        assert!(matches!(
            result,
            Err(TsmReportError::SvsmWriteConflict {
                generation: 4,
                expected: 3
            })
        ));
    }
}
