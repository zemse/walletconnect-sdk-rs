use alloy::primitives::{Address, Bytes, Signature};
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::message_types::AuthPayload;
use std::fmt::Write;

#[derive(Debug, Serialize, Deserialize)]
pub struct Cacao {
    pub header: CacaoHeader,
    pub payload: CacaoPayload,
    pub signature: Option<CacaoSignature>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CacaoHeader {
    pub header_type: String, // "caip122"
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CacaoPayload {
    pub domain: String,
    pub account_address: Address,
    pub uri: String,
    pub version: String,
    pub statement: Option<String>,
    pub nonce: Option<String>,
    pub issued_at: Option<String>,
    pub expiration_time: Option<String>,
    pub not_before: Option<String>,
    pub request_id: Option<String>,
    pub chain_id: usize,
    pub resources: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CacaoSignature {
    pub signature_type: String, // "eip191"
    pub signature: String,      // signature
}

impl CacaoPayload {
    pub fn caip122_message(&self, chain_name: &str) -> Result<String> {
        let mut message = format!(
            "{} wants you to sign in with your {} account:\n{}\n\n",
            self.domain, chain_name, self.account_address
        );

        if let Some(statement) = &self.statement {
            writeln!(message, "{statement}")?;
        }

        write!(
            message,
            "URI: {}\nVersion: {}\nChain ID: {}",
            self.uri, self.version, self.chain_id,
        )?;

        if let Some(nonce) = &self.nonce {
            write!(message, "\nNonce: {nonce}")?;
        }

        if let Some(issued_at) = &self.issued_at {
            write!(message, "\nIssued At: {issued_at}")?;
        }

        if let Some(expiration_time) = &self.expiration_time {
            write!(message, "\nExpiration Time: {expiration_time}")?;
        }

        if let Some(not_before) = &self.not_before {
            write!(message, "\nNot Before: {not_before}")?;
        }

        if let Some(request_id) = &self.request_id {
            write!(message, "\nRequest ID: {request_id}")?;
        }

        if !self.resources.is_empty() {
            write!(message, "\nResources:")?;
            for resource in &self.resources {
                write!(message, "\n- {resource}")?;
            }
        }

        Ok(message)
    }
}
