// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use csv_rs::api::dcu::{verify_reports, AttestationReport};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{instrument, warn};

use crate::{
    regularize_data, InitDataHash, ReportData, TeeClass, TeeEvidence, TeeEvidenceParsedClaim,
    Verifier,
};

#[derive(Serialize, Deserialize)]
struct DcuEvidence {
    attestation_reports: Vec<AttestationReport>,
}

pub const HYGON_DCU_TEE_CLASS: &str = "dcu";

#[derive(Debug, Default)]
pub struct HygonDcuVerifier {}

#[async_trait]
impl Verifier for HygonDcuVerifier {
    #[instrument(skip_all, name = "Hygon DCU")]
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<Vec<(TeeEvidenceParsedClaim, TeeClass)>> {
        let tee_evidence = serde_json::from_value::<DcuEvidence>(evidence)?;

        let expected_report_data = match expected_report_data {
            ReportData::Value(expected_report_data) => {
                let user_data_slice =
                    regularize_data(expected_report_data, 64, "REPORT_DATA", "Hygon DCU");
                let mut user_data = [0u8; 64];
                user_data.copy_from_slice(&user_data_slice[..64]);
                user_data
            }
            ReportData::NotProvided => bail!("DCU must check report data"),
        };

        verify_reports(&tee_evidence.attestation_reports, &expected_report_data).await?;

        if let InitDataHash::Value(_) = expected_init_data_hash {
            warn!("DCU does not support init data hash mechanism. skip.");
        }

        let claims = tee_evidence
            .attestation_reports
            .iter()
            .map(|report| (report_claims(report), HYGON_DCU_TEE_CLASS.to_string()))
            .collect();
        Ok(claims)
    }
}

fn report_claims(report: &AttestationReport) -> serde_json::Value {
    let mut body = json!({
        "version": report.body.version,
        "chip_id": String::from_utf8_lossy(&report.body.chip_id)
            .trim_end_matches('\0')
            .to_string(),
        "user_data": STANDARD.encode(report.body.user_data),
        "measure": STANDARD.encode(report.body.measure),
        "reserved": STANDARD.encode(report.body.reserved_bytes()),
        "sig_usage": report.body.sig_usage,
        "sig_algo": report.body.sig_algo,
    });

    // ccmode only exists from report version 2 onwards.
    if let Some(ccmode) = report.body.cc_mode() {
        body.as_object_mut()
            .expect("claim body is a JSON object")
            .insert("ccmode".to_string(), json!(ccmode));
    }

    json!({
        "body": body,
        "report_data": STANDARD.encode(report.body.user_data),
    })
}

#[cfg(test)]
mod tests {
    use super::{report_claims, AttestationReport, DcuEvidence};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde_json::{json, Value};

    fn report_json(
        version: u32,
        reserved_len: usize,
        ccmode: Option<u32>,
        sig_algo: u32,
        sig_usage: u32,
    ) -> Value {
        let mut body = json!({
            "version": version,
            "chip_id": vec![0u8; 16],
            "user_data": vec![0u8; 64],
            "measure": vec![0u8; 32],
            "reserved": vec![0u8; reserved_len],
            "sig_algo": sig_algo,
            "sig_usage": sig_usage,
        });
        if let Some(ccmode) = ccmode {
            body.as_object_mut()
                .unwrap()
                .insert("ccmode".to_string(), json!(ccmode));
        }
        json!({
            "body": body,
            "sig": {
                "r": vec![0u8; 72],
                "s": vec![0u8; 72],
            },
        })
    }

    fn claim_reserved(claims: &Value) -> Vec<u8> {
        STANDARD
            .decode(claims["body"]["reserved"].as_str().unwrap())
            .unwrap()
    }

    #[test]
    fn legacy_reports_omit_ccmode_and_keep_128_byte_reserved() {
        for version in [0u32, 1] {
            let report: AttestationReport =
                serde_json::from_value(report_json(version, 128, None, 0x55667788, 0x11223344))
                    .unwrap();
            let claims = report_claims(&report);

            assert!(claims["body"].get("ccmode").is_none());
            assert_eq!(claim_reserved(&claims).len(), 128);
            // Legacy JSON named the firmware offsets the other way round.
            assert_eq!(claims["body"]["sig_algo"], json!(0x11223344u32));
            assert_eq!(claims["body"]["sig_usage"], json!(0x55667788u32));
        }
    }

    #[test]
    fn version_two_reports_include_ccmode_and_124_byte_reserved() {
        let report: AttestationReport =
            serde_json::from_value(report_json(2, 124, Some(1), 0xaabbccdd, 0xeeff0011)).unwrap();
        let claims = report_claims(&report);

        assert_eq!(claims["body"]["ccmode"], json!(1));
        assert_eq!(claim_reserved(&claims).len(), 124);
        assert_eq!(claims["body"]["sig_algo"], json!(0xaabbccddu32));
        assert_eq!(claims["body"]["sig_usage"], json!(0xeeff0011u32));
    }

    #[test]
    fn mixed_report_shapes_use_version_for_ccmode() {
        // Old producer + new firmware: 128-byte reserved, version 2.
        let legacy_v2: AttestationReport =
            serde_json::from_value(report_json(2, 128, None, 1, 2)).unwrap();
        let claims = report_claims(&legacy_v2);
        assert!(claims["body"].get("ccmode").is_some());
        assert_eq!(claim_reserved(&claims).len(), 124);

        // New producer + old firmware: ccmode present, version 1.
        let current_v1: AttestationReport =
            serde_json::from_value(report_json(1, 124, Some(1), 3, 4)).unwrap();
        let claims = report_claims(&current_v1);
        assert!(claims["body"].get("ccmode").is_none());
        assert_eq!(claim_reserved(&claims).len(), 128);
    }

    #[test]
    fn legacy_evidence_deserializes() {
        let evidence = json!({
            "attestation_reports": [report_json(1, 128, None, 1, 2)],
        });
        let parsed: DcuEvidence = serde_json::from_value(evidence).unwrap();
        assert_eq!(parsed.attestation_reports.len(), 1);
    }
}
