use alloy::primitives::Address;
use alloy::signers::Signature;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};
use crate::types::AuthPayload;
use crate::utils::str_timestamp;

use std::fmt::{Display, Write};
use std::str::FromStr;

// https://specs.walletconnect.com/2.0/specs/clients/core/identity/identity-keys#cacao-format
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
    // https://github.com/WalletConnect/walletconnect-monorepo/blob/b39a5d4e62f5517ef47a70b5b93f27585b7132e8/packages/utils/src/cacao.ts#L97
    pub fn from_auth_request(
        auth_request: &AuthPayload,
        account_address: Address,
        chain_id: u64,
    ) -> Result<Self> {
        let payload = CacaoPayload {
            domain: auth_request.domain.clone(),
            uri: auth_request.aud.clone(),
            version: auth_request.version.clone(),
            statement: Some(auth_request.statement.clone()),
            nonce: Some(auth_request.nonce.clone()),
            issued_at: Some(str_timestamp()?),
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: auth_request.resources.clone(),
            iss: DID {
                chain_id: chain_id.to_string(),
                account_address,
            },
        };

        Ok(Cacao {
            header: CacaoHeader {
                header_type: "caip122".to_string(),
            },
            payload,
            signature: None,
        })
    }

    // https://github.com/WalletConnect/walletconnect-monorepo/blob/b39a5d4e62f5517ef47a70b5b93f27585b7132e8/packages/utils/src/cacao.ts#L33
    pub fn verify(&self) -> Result<()> {
        let message = self.payload.caip122_message()?;
        if let Some(signature) = &self.signature {
            let address = signature
                .into_alloy_signature()?
                .recover_address_from_msg(message)?;
            if address == self.payload.iss.account_address {
                Ok(())
            } else {
                Err(Error::InternalError(format!(
                    "Signature does not match the address: {address}"
                )))
            }
        } else {
            Err(Error::InternalError(
                "Cannot verify, signature is missing".to_string(),
            ))
        }
    }

    pub fn caip122_message(&self) -> Result<String> {
        self.payload.caip122_message()
    }

    pub fn insert_signature(&mut self, signature: Signature) -> Result<()> {
        if self.signature.is_none() {
            self.signature = Some(CacaoSignature {
                signature_type: "eip191".to_string(),
                signature: signature.to_string(),
            });
            Ok(())
        } else {
            Err(Error::InternalError("Signature already exists".to_string()))
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
    // https://github.com/WalletConnect/walletconnect-monorepo/blob/b39a5d4e62f5517ef47a70b5b93f27585b7132e8/packages/utils/src/cacao.ts#L49
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
