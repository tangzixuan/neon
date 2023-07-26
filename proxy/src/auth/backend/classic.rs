use std::ops::ControlFlow;

use super::AuthSuccess;
use crate::{
    auth::{self, AuthFlow, ClientCredentials},
    compute,
    console::{self, AuthInfo, CachedNodeInfo, ConsoleReqExtra},
    proxy::{try_wake, NUM_RETRIES_CONNECT},
    sasl, scram,
    stream::PqStream,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

pub(super) async fn authenticate(
    api: &impl console::Api,
    extra: &ConsoleReqExtra<'_>,
    creds: &ClientCredentials<'_>,
    client: &mut PqStream<impl AsyncRead + AsyncWrite + Unpin>,
) -> auth::Result<AuthSuccess<CachedNodeInfo>> {
    info!("fetching user's authentication info");
    let info = api.get_auth_info(extra, creds).await?.unwrap_or_else(|| {
        // If we don't have an authentication secret, we mock one to
        // prevent malicious probing (possible due to missing protocol steps).
        // This mocked secret will never lead to successful authentication.
        info!("authentication info not found, mocking it");
        AuthInfo::Scram(scram::ServerSecret::mock(creds.user, rand::random()))
    });

    let flow = AuthFlow::new(client);
    let scram_keys = match info {
        AuthInfo::Md5(_) => {
            info!("auth endpoint chooses MD5");
            return Err(auth::AuthError::bad_auth_method("MD5"));
        }
        AuthInfo::Scram(secret) => {
            info!("auth endpoint chooses SCRAM");
            let scram = auth::Scram(&secret);
            let client_key = match flow.begin(scram).await?.authenticate().await? {
                sasl::Outcome::Success(key) => key,
                sasl::Outcome::Failure(reason) => {
                    info!("auth backend failed with an error: {reason}");
                    return Err(auth::AuthError::auth_failed(creds.user));
                }
            };

            Some(compute::ScramKeys {
                client_key: client_key.as_bytes(),
                server_key: secret.server_key.as_bytes(),
            })
        }
    };

    let mut num_retries = 0;
    let mut node = loop {
        num_retries += 1;
        match try_wake(api, extra, creds).await? {
            ControlFlow::Break(n) => break n,
            ControlFlow::Continue(_) if num_retries < NUM_RETRIES_CONNECT => continue,
            ControlFlow::Continue(e) => return Err(e.into()),
        }
    };
    if let Some(keys) = scram_keys {
        use tokio_postgres::config::AuthKeys;
        node.config.auth_keys(AuthKeys::ScramSha256(keys));
    }

    Ok(AuthSuccess {
        reported_auth_ok: false,
        value: node,
    })
}
