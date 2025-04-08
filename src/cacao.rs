use alloy::primitives::Address;
use alloy::signers::Signature;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};

use std::fmt::{Display, Write};
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize)]
pub struct Cacao {
    #[serde(rename = "h")]
    pub header: CacaoHeader,
    #[serde(rename = "p")]
    pub payload: CacaoPayload,
    #[serde(rename = "s")]
    pub signature: Option<CacaoSignature>,
}

impl Cacao {
    pub fn verify(&self) -> Result<()> {
        let message = self.payload.caip122_message()?;
        println!("\nmessage: {message}\n");
        if let Some(signature) = &self.signature {
            let address = signature
                .into_alloy_signature()?
                .recover_address_from_msg(message)?;
            println!("address: {address}");
            if address == self.payload.iss.account_address {
                Ok(())
            } else {
                Err(Error::InternalError(format!(
                    "Signature does not match the address: {}",
                    address
                )))
            }
        } else {
            Err(Error::InternalError(
                "Cannot verify, signature is missing".to_string(),
            ))
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CacaoHeader {
    #[serde(rename = "t")]
    pub header_type: String, // "caip122"
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CacaoPayload {
    pub domain: String,
    #[serde(rename = "aud")]
    pub uri: String,
    pub version: String,
    pub statement: Option<String>,
    pub nonce: Option<String>,
    #[serde(rename = "iat")]
    pub issued_at: Option<String>,
    #[serde(rename = "exp")]
    pub expiration_time: Option<String>,
    #[serde(rename = "nbf")]
    pub not_before: Option<String>,
    pub request_id: Option<String>,
    pub resources: Vec<String>,
    pub iss: DID,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CacaoSignature {
    #[serde(rename = "t")]
    pub signature_type: String, // "eip191"
    #[serde(rename = "s")]
    pub signature: String,
}

impl CacaoSignature {
    pub fn into_alloy_signature(&self) -> Result<Signature> {
        Ok(Signature::from_str(&self.signature)?)
    }
}

impl CacaoPayload {
    pub fn caip122_message(&self) -> Result<String> {
        let chain_name = "Ethereum";

        let mut message = format!(
            "{} wants you to sign in with your {} account:\n{}\n\n",
            self.domain, chain_name, self.iss.account_address
        );

        if let Some(statement) = &self.statement {
            writeln!(message, "{statement}\n")?;
        }

        write!(
            message,
            "URI: {}\nVersion: {}\nChain ID: {}",
            self.uri, self.version, self.iss.chain_id,
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

#[derive(Debug)]
pub struct DID {
    pub chain_id: String,
    pub account_address: Address,
}

impl Display for DID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "did:pkh:eip155:{}:{}",
            self.chain_id, self.account_address
        )
    }
}

impl Serialize for DID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for DID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 5
            || parts[0] != "did"
            || parts[1] != "pkh"
            || parts[2] != "eip155"
        {
            return Err(serde::de::Error::custom("Invalid DID format"));
        }

        let chain_id = parts[3].to_string();
        let account_address = Address::from_str(parts[4]).map_err(|_| {
            serde::de::Error::custom("Invalid Ethereum address")
        })?;

        Ok(DID {
            chain_id,
            account_address,
        })
    }
}
