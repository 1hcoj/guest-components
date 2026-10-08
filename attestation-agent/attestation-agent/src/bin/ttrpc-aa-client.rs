// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use base64::Engine;
use clap::{Args, Parser, Subcommand};
use const_format::concatcp;
use protos::ttrpc::aa::{
    attestation_agent::{
        ExtendRuntimeMeasurementRequest, GetEvidenceRequest, GetTeeTypeRequest, GetTokenRequest,
        RuntimeMeasurementResult,
    },
    attestation_agent_ttrpc::AttestationAgentServiceClient,
};
use ttrpc::context;

mod ttrpc_dep;

const TIMEOUT: i64 = 5 * 1000 * 1000 * 1000;

const DEFAULT_UNIX_SOCKET_DIR: &str = "/run/confidential-containers/attestation-agent/";
const UNIX_SOCKET_PREFIX: &str = "unix://";
const DEFAULT_ATTESTATION_SOCKET_ADDR: &str = concatcp!(
    UNIX_SOCKET_PREFIX,
    DEFAULT_UNIX_SOCKET_DIR,
    "attestation-agent.sock"
);

#[derive(Parser)]
#[command(author)]
struct Cli {
    /// Attestation ttRPC Unix socket addr.
    ///
    /// This Unix socket address which the Attestation ttRPC service
    /// will listen to, for example:
    ///
    /// `--attestation_sock unix:///tmp/attestation`
    #[arg(default_value_t = DEFAULT_ATTESTATION_SOCKET_ADDR.to_string(), short, long = "attestation_sock")]
    attestation_sock: String,

    #[command(subcommand)]
    operation: Operation,
}

#[derive(Subcommand)]
#[command(author, version, about, long_about = None)]
enum Operation {
    /// Get the tee type
    GetTee,

    /// Get evidence
    GetEvidence(GetEvidenceArgs),

    /// Get attestation token
    GetToken(GetTokenArgs),

    /// Extend runtime measurement
    ExtendRuntimeMeasurement(ExtendRuntimeMeasurementArgs),
}

#[derive(Clone, Debug)]
struct RuntimeData(Vec<u8>);

fn parse_runtime_data(value: &str) -> Result<RuntimeData, String> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map(RuntimeData)
        .map_err(|err| format!("runtime data must be valid standard Base64: {err}"))
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct GetEvidenceArgs {
    /// Base64-encoded runtime data
    #[arg(short, long, value_parser = parse_runtime_data)]
    runtime_data: RuntimeData,
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct GetTokenArgs {
    /// token type
    #[arg(short, long)]
    token_type: String,
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct ExtendRuntimeMeasurementArgs {
    /// domain name
    #[arg(short, long)]
    domain: String,

    /// operation name
    #[arg(short, long)]
    operation: String,

    /// content name
    #[arg(short, long)]
    content: String,

    /// PCR index
    #[arg(short, long)]
    pcr: Option<u64>,
}

#[tokio::main]
pub async fn main() {
    let args = Cli::parse();
    let inner = ttrpc::asynchronous::Client::connect(&args.attestation_sock)
        .await
        .expect("connect ttrpc socket");
    let client = AttestationAgentServiceClient::new(inner);
    match args.operation {
        Operation::GetTee => {
            let req = GetTeeTypeRequest {
                ..Default::default()
            };
            let res = client
                .get_tee_type(context::with_timeout(TIMEOUT), &req)
                .await
                .expect("request to AA");
            println!("{}", res.tee);
        }
        Operation::GetEvidence(args) => {
            let req = GetEvidenceRequest {
                RuntimeData: args.runtime_data.0,
                ..Default::default()
            };
            let res = client
                .get_evidence(context::with_timeout(TIMEOUT), &req)
                .await
                .expect("request to AA");
            let evidence = String::from_utf8(res.Evidence).unwrap();
            println!("{evidence}");
        }
        Operation::GetToken(get_token_args) => {
            let req = GetTokenRequest {
                TokenType: get_token_args.token_type,
                ..Default::default()
            };
            let res = client
                .get_token(context::with_timeout(TIMEOUT), &req)
                .await
                .expect("request to AA");
            let token = String::from_utf8(res.Token).unwrap();
            println!("{token}");
        }
        Operation::ExtendRuntimeMeasurement(extend_runtime_measurement_args) => {
            let req = ExtendRuntimeMeasurementRequest {
                Domain: extend_runtime_measurement_args.domain,
                Operation: extend_runtime_measurement_args.operation,
                Content: extend_runtime_measurement_args.content,
                RegisterIndex: extend_runtime_measurement_args.pcr,
                ..Default::default()
            };

            let res = client
                .extend_runtime_measurement(context::with_timeout(TIMEOUT), &req)
                .await
                .expect("request to AA");
            match res
                .Result
                .enum_value()
                .expect("failed to get runtime measurement result")
            {
                RuntimeMeasurementResult::OK => println!("Extended."),
                RuntimeMeasurementResult::NOT_SUPPORTED => {
                    println!("Current platform does not support runtime measurement.")
                }
                RuntimeMeasurementResult::NOT_ENABLED => println!(
                    "Runtime measurement is not enabled in Attestation Agent configuration."
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_runtime_data_during_cli_parsing() {
        for value in ["12345", "!!!!"] {
            let err =
                Cli::try_parse_from(["ttrpc-aa-client", "get-evidence", "--runtime-data", value])
                    .err()
                    .expect("invalid Base64 must be rejected");
            assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
            assert_eq!(err.exit_code(), 2);
        }
    }

    #[test]
    fn preserves_decoded_runtime_data_bytes() {
        for (value, expected) in [
            ("MTIzNDU=", b"12345".as_slice()),
            ("/w==", &[255][..]),
            ("", &[][..]),
        ] {
            let cli =
                Cli::try_parse_from(["ttrpc-aa-client", "get-evidence", "--runtime-data", value])
                    .expect("valid Base64 must be accepted");
            let Operation::GetEvidence(args) = cli.operation else {
                panic!("expected GetEvidence");
            };
            assert_eq!(args.runtime_data.0, expected);
        }
    }
}
