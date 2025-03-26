use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use rand::Rng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::runtime::Runtime;

use crate::relay_auth::sign_jwt;

struct Connection {
    rpc: String,
    id: usize,
    jwt: String,
}

impl Connection {
    pub fn new(rpc: String) -> Self {
        let initial: u16 = rand::thread_rng().r#gen();
        let jwt = sign_jwt("https://relay.walletconnect.org");
        Self {
            rpc,
            id: initial as usize,
            jwt,
        }
    }

    fn get_id(&self) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards");

        let date_ns = now.as_millis() * 1_000_000;
        let extra = self.id as u128;

        (date_ns + extra).to_string()
    }

    pub fn ping(&self) {
        send_request(
            &self.rpc,
            JsonRpcRequest {
                id: self.get_id(),
                jsonrpc: "2.0",
                method: "irn_publish".to_string(),
                params: Some(json!({
                    "topic":"399de3bd2499b8fe10647e3c3ce4bb96d6fa1db18ee6f3fec4042167509e0a49",
                    "message":"ACwGLx2vdQZg6dVj9eswLqBJL4jvNsy5NR9lavO2tb6+h7ll+HRgWYrx/XaJgov4KYeq0I31duzgcDWmBz9JtP0snPo5ZVYr5NZf4/Ylyo8wkrnRGq6i8d8/fRx0pHW4nTF6mTXBBDVEa4mJVrkMukx71gfKGluxhGdRL9AsMoFLffvGcyDCLvs/bKePFd7mUNp9rNzEa47vJzj79HhTqs/BH/IOKnHngzBHkfQjg6OI8Dx1E1gQLEqZyBPDY5CzihKYbJIkiLpabZ/klTZikfssfA8bGzYyNdpnQqf3itq5f3Y5dC17QZDVntNxNjJ+ymRAgGdAZZKV6kaiZZoc87G+GoRmq17Zdx1nzOpi+q+05jvFyN6pbJYOdmqdqXyHCz96bAENlfZV3oVlqdCi1FT/YuOayfWfMza6jm5qb4naQ+YHPyYRWXHhB9lAHX96XdyhJ8BgPZrLNS8/yBjkBSqL9wAKfrh9KLOlUYk4XcVjqdXE9MA=",
                    "ttl":300,
                    "prompt":false,
                    "tag":1109
                })),
            },
           & self.jwt
        )
        .unwrap();
    }
}

/// A basic JSON-RPC 2.0 request.
#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Value>, // Could be array or object
    id: String,
}

/// A basic JSON-RPC 2.0 response with either a result or an error.
#[derive(Deserialize, Debug)]
struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<JsonRpcError>,
    #[serde(default)]
    id: Option<u64>,
}

/// A JSON-RPC error object (code, message, and optional data).
#[derive(Deserialize, Debug)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<Value>,
}

fn send_request(url: &str, rpc_request: JsonRpcRequest, jwt: &str) -> Result<()> {
    let client = Client::new();

    let rt = Runtime::new().expect("runtime failed");

    let response = rt.block_on(
        rt.block_on(
            client
                .post(url)
                .query(&[("projectId", "35d44d49c2dee217a3eb24bb4410acc7")])
                .bearer_auth(jwt)
                .json(&rpc_request)
                .send()
                .into_future(),
        )?
        .json::<JsonRpcResponse>()
        .into_future(),
    )?;

    println!("RawResponse: {:?}", response);

    // 4. Check for success or error.
    if let Some(result) = response.result {
        println!("Success! Result: {}", result);
    } else if let Some(error) = response.error {
        eprintln!("JSON-RPC Error {}: {}", error.code, error.message);
        if let Some(data) = error.data {
            eprintln!("Error data: {}", data);
        }
    } else {
        eprintln!("Unexpected response: {:?}", response);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping() {
        let conn = Connection::new("https://relay.walletconnect.org/rpc".to_string());
        conn.ping();
    }
}
