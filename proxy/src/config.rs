use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, ensure, Context, Ok};
use clap::ValueEnum;
use itertools::Itertools;
use remote_storage::RemoteStorageConfig;
use rustls::crypto::ring::{self, sign};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use tracing::{error, info};
use x509_parser::oid_registry;

use crate::auth::backend::jwt::JwkCache;
use crate::auth::backend::AuthRateLimiter;
use crate::control_plane::locks::ApiLocks;
use crate::rate_limiter::{RateBucketInfo, RateLimitAlgorithm, RateLimiterConfig};
use crate::scram::threadpool::ThreadPool;
use crate::serverless::cancel_set::CancelSet;
use crate::serverless::GlobalConnPoolOptions;
use crate::types::Host;

pub struct ProxyConfig {
    pub tls_config: Option<TlsConfig>,
    pub metric_collection: Option<MetricCollectionConfig>,
    pub http_config: HttpConfig,
    pub authentication_config: AuthenticationConfig,
    pub proxy_protocol_v2: ProxyProtocolV2,
    pub region: String,
    pub handshake_timeout: Duration,
    pub wake_compute_retry_config: RetryConfig,
    pub connect_compute_locks: ApiLocks<Host>,
    pub connect_to_compute: ComputeConfig,
}

pub struct ComputeConfig {
    pub retry: RetryConfig,
    pub tls: Arc<rustls::ClientConfig>,
    pub timeout: Duration,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq)]
pub enum ProxyProtocolV2 {
    /// Connection will error if PROXY protocol v2 header is missing
    Required,
    /// Connection will parse PROXY protocol v2 header, but accept the connection if it's missing.
    Supported,
    /// Connection will error if PROXY protocol v2 header is provided
    Rejected,
}

#[derive(Debug)]
pub struct MetricCollectionConfig {
    pub endpoint: reqwest::Url,
    pub interval: Duration,
    pub backup_metric_collection_config: MetricBackupCollectionConfig,
}

pub struct TlsConfig {
    pub config: Arc<rustls::ServerConfig>,
    pub common_names: HashSet<String>,
    pub cert_resolver: Arc<CertResolver>,
}

pub struct HttpConfig {
    pub accept_websockets: bool,
    pub pool_options: GlobalConnPoolOptions,
    pub cancel_set: CancelSet,
    pub client_conn_threshold: u64,
    pub max_request_size_bytes: usize,
    pub max_response_size_bytes: usize,
}

pub struct AuthenticationConfig {
    pub thread_pool: Arc<ThreadPool>,
    pub scram_protocol_timeout: tokio::time::Duration,
    pub rate_limiter_enabled: bool,
    pub rate_limiter: AuthRateLimiter,
    pub rate_limit_ip_subnet: u8,
    pub ip_allowlist_check_enabled: bool,
    pub jwks_cache: JwkCache,
    pub is_auth_broker: bool,
    pub accept_jwts: bool,
    pub console_redirect_confirmation_timeout: tokio::time::Duration,
}

impl TlsConfig {
    pub fn to_server_config(&self) -> Arc<rustls::ServerConfig> {
        self.config.clone()
    }
}

/// <https://github.com/postgres/postgres/blob/ca481d3c9ab7bf69ff0c8d71ad3951d407f6a33c/src/include/libpq/pqcomm.h#L159>
pub const PG_ALPN_PROTOCOL: &[u8] = b"postgresql";

/// Configure TLS for the main endpoint.
pub fn configure_tls(
    key_path: &str,
    cert_path: &str,
    certs_dir: Option<&String>,
    allow_tls_keylogfile: bool,
) -> anyhow::Result<TlsConfig> {
    let mut cert_resolver = CertResolver::new();

    // add default certificate
    cert_resolver.add_cert_path(key_path, cert_path, true)?;

    // add extra certificates
    if let Some(certs_dir) = certs_dir {
        for entry in std::fs::read_dir(certs_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                // file names aligned with default cert-manager names
                let key_path = path.join("tls.key");
                let cert_path = path.join("tls.crt");
                if key_path.exists() && cert_path.exists() {
                    cert_resolver.add_cert_path(
                        &key_path.to_string_lossy(),
                        &cert_path.to_string_lossy(),
                        false,
                    )?;
                }
            }
        }
    }

    let common_names = cert_resolver.get_common_names();

    let cert_resolver = Arc::new(cert_resolver);

    // allow TLS 1.2 to be compatible with older client libraries
    let mut config =
        rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .context("ring should support TLS1.2 and TLS1.3")?
            .with_no_client_auth()
            .with_cert_resolver(cert_resolver.clone());

    config.alpn_protocols = vec![PG_ALPN_PROTOCOL.to_vec()];

    if allow_tls_keylogfile {
        // KeyLogFile will check for the SSLKEYLOGFILE environment variable.
        config.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    Ok(TlsConfig {
        config: Arc::new(config),
        common_names,
        cert_resolver,
    })
}

/// Channel binding parameter
///
/// <https://www.rfc-editor.org/rfc/rfc5929#section-4>
/// Description: The hash of the TLS server's certificate as it
/// appears, octet for octet, in the server's Certificate message.  Note
/// that the Certificate message contains a certificate_list, in which
/// the first element is the server's certificate.
///
/// The hash function is to be selected as follows:
///
/// * if the certificate's signatureAlgorithm uses a single hash
///   function, and that hash function is either MD5 or SHA-1, then use SHA-256;
///
/// * if the certificate's signatureAlgorithm uses a single hash
///   function and that hash function neither MD5 nor SHA-1, then use
///   the hash function associated with the certificate's
///   signatureAlgorithm;
///
/// * if the certificate's signatureAlgorithm uses no hash functions or
///   uses multiple hash functions, then this channel binding type's
///   channel bindings are undefined at this time (updates to is channel
///   binding type may occur to address this issue if it ever arises).
#[derive(Debug, Clone, Copy)]
pub enum TlsServerEndPoint {
    Sha256([u8; 32]),
    Undefined,
}

impl TlsServerEndPoint {
    pub fn new(cert: &CertificateDer<'_>) -> anyhow::Result<Self> {
        let sha256_oids = [
            // I'm explicitly not adding MD5 or SHA1 here... They're bad.
            oid_registry::OID_SIG_ECDSA_WITH_SHA256,
            oid_registry::OID_PKCS1_SHA256WITHRSA,
        ];

        let pem = x509_parser::parse_x509_certificate(cert)
            .context("Failed to parse PEM object from cerficiate")?
            .1;

        info!(subject = %pem.subject, "parsing TLS certificate");

        let reg = oid_registry::OidRegistry::default().with_all_crypto();
        let oid = pem.signature_algorithm.oid();
        let alg = reg.get(oid);
        if sha256_oids.contains(oid) {
            let tls_server_end_point: [u8; 32] = Sha256::new().chain_update(cert).finalize().into();
            info!(subject = %pem.subject, signature_algorithm = alg.map(|a| a.description()), tls_server_end_point = %base64::encode(tls_server_end_point), "determined channel binding");
            Ok(Self::Sha256(tls_server_end_point))
        } else {
            error!(subject = %pem.subject, signature_algorithm = alg.map(|a| a.description()), "unknown channel binding");
            Ok(Self::Undefined)
        }
    }

    pub fn supported(&self) -> bool {
        !matches!(self, TlsServerEndPoint::Undefined)
    }
}

#[derive(Default, Debug)]
pub struct CertResolver {
    certs: HashMap<String, (Arc<rustls::sign::CertifiedKey>, TlsServerEndPoint)>,
    default: Option<(Arc<rustls::sign::CertifiedKey>, TlsServerEndPoint)>,
}

impl CertResolver {
    pub fn new() -> Self {
        Self::default()
    }

    fn add_cert_path(
        &mut self,
        key_path: &str,
        cert_path: &str,
        is_default: bool,
    ) -> anyhow::Result<()> {
        let priv_key = {
            let key_bytes = std::fs::read(key_path)
                .with_context(|| format!("Failed to read TLS keys at '{key_path}'"))?;
            rustls_pemfile::private_key(&mut &key_bytes[..])
                .with_context(|| format!("Failed to parse TLS keys at '{key_path}'"))?
                .with_context(|| format!("Failed to parse TLS keys at '{key_path}'"))?
        };

        let cert_chain_bytes = std::fs::read(cert_path)
            .context(format!("Failed to read TLS cert file at '{cert_path}.'"))?;

        let cert_chain = {
            rustls_pemfile::certs(&mut &cert_chain_bytes[..])
                .try_collect()
                .with_context(|| {
                    format!("Failed to read TLS certificate chain from bytes from file at '{cert_path}'.")
                })?
        };

        self.add_cert(priv_key, cert_chain, is_default)
    }

    pub fn add_cert(
        &mut self,
        priv_key: PrivateKeyDer<'static>,
        cert_chain: Vec<CertificateDer<'static>>,
        is_default: bool,
    ) -> anyhow::Result<()> {
        let key = sign::any_supported_type(&priv_key).context("invalid private key")?;

        let first_cert = &cert_chain[0];
        let tls_server_end_point = TlsServerEndPoint::new(first_cert)?;
        let pem = x509_parser::parse_x509_certificate(first_cert)
            .context("Failed to parse PEM object from cerficiate")?
            .1;

        let common_name = pem.subject().to_string();

        // We need to get the canonical name for this certificate so we can match them against any domain names
        // seen within the proxy codebase.
        //
        // In scram-proxy we use wildcard certificates only, with the database endpoint as the wildcard subdomain, taken from SNI.
        // We need to remove the wildcard prefix for the purposes of certificate selection.
        //
        // auth-broker does not use SNI and instead uses the Neon-Connection-String header.
        // Auth broker has the subdomain `apiauth` we need to remove for the purposes of validating the Neon-Connection-String.
        //
        // Console Redirect proxy does not use any wildcard domains and does not need any certificate selection or conn string
        // validation, so let's we can continue with any common-name
        let common_name = if let Some(s) = common_name.strip_prefix("CN=*.") {
            s.to_string()
        } else if let Some(s) = common_name.strip_prefix("CN=apiauth.") {
            s.to_string()
        } else if let Some(s) = common_name.strip_prefix("CN=") {
            s.to_string()
        } else {
            bail!("Failed to parse common name from certificate")
        };

        let cert = Arc::new(rustls::sign::CertifiedKey::new(cert_chain, key));

        if is_default {
            self.default = Some((cert.clone(), tls_server_end_point));
        }

        self.certs.insert(common_name, (cert, tls_server_end_point));

        Ok(())
    }

    pub fn get_common_names(&self) -> HashSet<String> {
        self.certs.keys().map(|s| s.to_string()).collect()
    }
}

impl rustls::server::ResolvesServerCert for CertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.resolve(client_hello.server_name()).map(|x| x.0)
    }
}

impl CertResolver {
    pub fn resolve(
        &self,
        server_name: Option<&str>,
    ) -> Option<(Arc<rustls::sign::CertifiedKey>, TlsServerEndPoint)> {
        // loop here and cut off more and more subdomains until we find
        // a match to get a proper wildcard support. OTOH, we now do not
        // use nested domains, so keep this simple for now.
        //
        // With the current coding foo.com will match *.foo.com and that
        // repeats behavior of the old code.
        if let Some(mut sni_name) = server_name {
            loop {
                if let Some(cert) = self.certs.get(sni_name) {
                    return Some(cert.clone());
                }
                if let Some((_, rest)) = sni_name.split_once('.') {
                    sni_name = rest;
                } else {
                    return None;
                }
            }
        } else {
            // No SNI, use the default certificate, otherwise we can't get to
            // options parameter which can be used to set endpoint name too.
            // That means that non-SNI flow will not work for CNAME domains in
            // verify-full mode.
            //
            // If that will be a problem we can:
            //
            // a) Instead of multi-cert approach use single cert with extra
            //    domains listed in Subject Alternative Name (SAN).
            // b) Deploy separate proxy instances for extra domains.
            self.default.clone()
        }
    }
}

#[derive(Debug)]
pub struct EndpointCacheConfig {
    /// Batch size to receive all endpoints on the startup.
    pub initial_batch_size: usize,
    /// Batch size to receive endpoints.
    pub default_batch_size: usize,
    /// Timeouts for the stream read operation.
    pub xread_timeout: Duration,
    /// Stream name to read from.
    pub stream_name: String,
    /// Limiter info (to distinguish when to enable cache).
    pub limiter_info: Vec<RateBucketInfo>,
    /// Disable cache.
    /// If true, cache is ignored, but reports all statistics.
    pub disable_cache: bool,
    /// Retry interval for the stream read operation.
    pub retry_interval: Duration,
}

impl EndpointCacheConfig {
    /// Default options for [`crate::control_plane::NodeInfoCache`].
    /// Notice that by default the limiter is empty, which means that cache is disabled.
    pub const CACHE_DEFAULT_OPTIONS: &'static str =
        "initial_batch_size=1000,default_batch_size=10,xread_timeout=5m,stream_name=controlPlane,disable_cache=true,limiter_info=1000@1s,retry_interval=1s";

    /// Parse cache options passed via cmdline.
    /// Example: [`Self::CACHE_DEFAULT_OPTIONS`].
    fn parse(options: &str) -> anyhow::Result<Self> {
        let mut initial_batch_size = None;
        let mut default_batch_size = None;
        let mut xread_timeout = None;
        let mut stream_name = None;
        let mut limiter_info = vec![];
        let mut disable_cache = false;
        let mut retry_interval = None;

        for option in options.split(',') {
            let (key, value) = option
                .split_once('=')
                .with_context(|| format!("bad key-value pair: {option}"))?;

            match key {
                "initial_batch_size" => initial_batch_size = Some(value.parse()?),
                "default_batch_size" => default_batch_size = Some(value.parse()?),
                "xread_timeout" => xread_timeout = Some(humantime::parse_duration(value)?),
                "stream_name" => stream_name = Some(value.to_string()),
                "limiter_info" => limiter_info.push(RateBucketInfo::from_str(value)?),
                "disable_cache" => disable_cache = value.parse()?,
                "retry_interval" => retry_interval = Some(humantime::parse_duration(value)?),
                unknown => bail!("unknown key: {unknown}"),
            }
        }
        RateBucketInfo::validate(&mut limiter_info)?;

        Ok(Self {
            initial_batch_size: initial_batch_size.context("missing `initial_batch_size`")?,
            default_batch_size: default_batch_size.context("missing `default_batch_size`")?,
            xread_timeout: xread_timeout.context("missing `xread_timeout`")?,
            stream_name: stream_name.context("missing `stream_name`")?,
            disable_cache,
            limiter_info,
            retry_interval: retry_interval.context("missing `retry_interval`")?,
        })
    }
}

impl FromStr for EndpointCacheConfig {
    type Err = anyhow::Error;

    fn from_str(options: &str) -> Result<Self, Self::Err> {
        let error = || format!("failed to parse endpoint cache options '{options}'");
        Self::parse(options).with_context(error)
    }
}
#[derive(Debug)]
pub struct MetricBackupCollectionConfig {
    pub interval: Duration,
    pub remote_storage_config: Option<RemoteStorageConfig>,
    pub chunk_size: usize,
}

pub fn remote_storage_from_toml(s: &str) -> anyhow::Result<RemoteStorageConfig> {
    RemoteStorageConfig::from_toml(&s.parse()?)
}

/// Helper for cmdline cache options parsing.
#[derive(Debug)]
pub struct CacheOptions {
    /// Max number of entries.
    pub size: usize,
    /// Entry's time-to-live.
    pub ttl: Duration,
}

impl CacheOptions {
    /// Default options for [`crate::control_plane::NodeInfoCache`].
    pub const CACHE_DEFAULT_OPTIONS: &'static str = "size=4000,ttl=4m";

    /// Parse cache options passed via cmdline.
    /// Example: [`Self::CACHE_DEFAULT_OPTIONS`].
    fn parse(options: &str) -> anyhow::Result<Self> {
        let mut size = None;
        let mut ttl = None;

        for option in options.split(',') {
            let (key, value) = option
                .split_once('=')
                .with_context(|| format!("bad key-value pair: {option}"))?;

            match key {
                "size" => size = Some(value.parse()?),
                "ttl" => ttl = Some(humantime::parse_duration(value)?),
                unknown => bail!("unknown key: {unknown}"),
            }
        }

        // TTL doesn't matter if cache is always empty.
        if let Some(0) = size {
            ttl.get_or_insert(Duration::default());
        }

        Ok(Self {
            size: size.context("missing `size`")?,
            ttl: ttl.context("missing `ttl`")?,
        })
    }
}

impl FromStr for CacheOptions {
    type Err = anyhow::Error;

    fn from_str(options: &str) -> Result<Self, Self::Err> {
        let error = || format!("failed to parse cache options '{options}'");
        Self::parse(options).with_context(error)
    }
}

/// Helper for cmdline cache options parsing.
#[derive(Debug)]
pub struct ProjectInfoCacheOptions {
    /// Max number of entries.
    pub size: usize,
    /// Entry's time-to-live.
    pub ttl: Duration,
    /// Max number of roles per endpoint.
    pub max_roles: usize,
    /// Gc interval.
    pub gc_interval: Duration,
}

impl ProjectInfoCacheOptions {
    /// Default options for [`crate::control_plane::NodeInfoCache`].
    pub const CACHE_DEFAULT_OPTIONS: &'static str =
        "size=10000,ttl=4m,max_roles=10,gc_interval=60m";

    /// Parse cache options passed via cmdline.
    /// Example: [`Self::CACHE_DEFAULT_OPTIONS`].
    fn parse(options: &str) -> anyhow::Result<Self> {
        let mut size = None;
        let mut ttl = None;
        let mut max_roles = None;
        let mut gc_interval = None;

        for option in options.split(',') {
            let (key, value) = option
                .split_once('=')
                .with_context(|| format!("bad key-value pair: {option}"))?;

            match key {
                "size" => size = Some(value.parse()?),
                "ttl" => ttl = Some(humantime::parse_duration(value)?),
                "max_roles" => max_roles = Some(value.parse()?),
                "gc_interval" => gc_interval = Some(humantime::parse_duration(value)?),
                unknown => bail!("unknown key: {unknown}"),
            }
        }

        // TTL doesn't matter if cache is always empty.
        if let Some(0) = size {
            ttl.get_or_insert(Duration::default());
        }

        Ok(Self {
            size: size.context("missing `size`")?,
            ttl: ttl.context("missing `ttl`")?,
            max_roles: max_roles.context("missing `max_roles`")?,
            gc_interval: gc_interval.context("missing `gc_interval`")?,
        })
    }
}

impl FromStr for ProjectInfoCacheOptions {
    type Err = anyhow::Error;

    fn from_str(options: &str) -> Result<Self, Self::Err> {
        let error = || format!("failed to parse cache options '{options}'");
        Self::parse(options).with_context(error)
    }
}

/// This is a config for connect to compute and wake compute.
#[derive(Clone, Copy, Debug)]
pub struct RetryConfig {
    /// Number of times we should retry.
    pub max_retries: u32,
    /// Retry duration is base_delay * backoff_factor ^ n, where n starts at 0
    pub base_delay: tokio::time::Duration,
    /// Exponential base for retry wait duration
    pub backoff_factor: f64,
}

impl RetryConfig {
    // Default options for RetryConfig.

    /// Total delay for 5 retries with 200ms base delay and 2 backoff factor is about 6s.
    pub const CONNECT_TO_COMPUTE_DEFAULT_VALUES: &'static str =
        "num_retries=5,base_retry_wait_duration=200ms,retry_wait_exponent_base=2";
    /// Total delay for 8 retries with 100ms base delay and 1.6 backoff factor is about 7s.
    /// Cplane has timeout of 60s on each request. 8m7s in total.
    pub const WAKE_COMPUTE_DEFAULT_VALUES: &'static str =
        "num_retries=8,base_retry_wait_duration=100ms,retry_wait_exponent_base=1.6";

    /// Parse retry options passed via cmdline.
    /// Example: [`Self::CONNECT_TO_COMPUTE_DEFAULT_VALUES`].
    pub fn parse(options: &str) -> anyhow::Result<Self> {
        let mut num_retries = None;
        let mut base_retry_wait_duration = None;
        let mut retry_wait_exponent_base = None;

        for option in options.split(',') {
            let (key, value) = option
                .split_once('=')
                .with_context(|| format!("bad key-value pair: {option}"))?;

            match key {
                "num_retries" => num_retries = Some(value.parse()?),
                "base_retry_wait_duration" => {
                    base_retry_wait_duration = Some(humantime::parse_duration(value)?);
                }
                "retry_wait_exponent_base" => retry_wait_exponent_base = Some(value.parse()?),
                unknown => bail!("unknown key: {unknown}"),
            }
        }

        Ok(Self {
            max_retries: num_retries.context("missing `num_retries`")?,
            base_delay: base_retry_wait_duration.context("missing `base_retry_wait_duration`")?,
            backoff_factor: retry_wait_exponent_base
                .context("missing `retry_wait_exponent_base`")?,
        })
    }
}

/// Helper for cmdline cache options parsing.
#[derive(serde::Deserialize)]
pub struct ConcurrencyLockOptions {
    /// The number of shards the lock map should have
    pub shards: usize,
    /// The number of allowed concurrent requests for each endpoitn
    #[serde(flatten)]
    pub limiter: RateLimiterConfig,
    /// Garbage collection epoch
    #[serde(deserialize_with = "humantime_serde::deserialize")]
    pub epoch: Duration,
    /// Lock timeout
    #[serde(deserialize_with = "humantime_serde::deserialize")]
    pub timeout: Duration,
}

impl ConcurrencyLockOptions {
    /// Default options for [`crate::control_plane::client::ApiLocks`].
    pub const DEFAULT_OPTIONS_WAKE_COMPUTE_LOCK: &'static str = "permits=0";
    /// Default options for [`crate::control_plane::client::ApiLocks`].
    pub const DEFAULT_OPTIONS_CONNECT_COMPUTE_LOCK: &'static str =
        "shards=64,permits=100,epoch=10m,timeout=10ms";

    // pub const DEFAULT_OPTIONS_WAKE_COMPUTE_LOCK: &'static str = "shards=32,permits=4,epoch=10m,timeout=1s";

    /// Parse lock options passed via cmdline.
    /// Example: [`Self::DEFAULT_OPTIONS_WAKE_COMPUTE_LOCK`].
    fn parse(options: &str) -> anyhow::Result<Self> {
        let options = options.trim();
        if options.starts_with('{') && options.ends_with('}') {
            return Ok(serde_json::from_str(options)?);
        }

        let mut shards = None;
        let mut permits = None;
        let mut epoch = None;
        let mut timeout = None;

        for option in options.split(',') {
            let (key, value) = option
                .split_once('=')
                .with_context(|| format!("bad key-value pair: {option}"))?;

            match key {
                "shards" => shards = Some(value.parse()?),
                "permits" => permits = Some(value.parse()?),
                "epoch" => epoch = Some(humantime::parse_duration(value)?),
                "timeout" => timeout = Some(humantime::parse_duration(value)?),
                unknown => bail!("unknown key: {unknown}"),
            }
        }

        // these dont matter if lock is disabled
        if let Some(0) = permits {
            timeout = Some(Duration::default());
            epoch = Some(Duration::default());
            shards = Some(2);
        }

        let permits = permits.context("missing `permits`")?;
        let out = Self {
            shards: shards.context("missing `shards`")?,
            limiter: RateLimiterConfig {
                algorithm: RateLimitAlgorithm::Fixed,
                initial_limit: permits,
            },
            epoch: epoch.context("missing `epoch`")?,
            timeout: timeout.context("missing `timeout`")?,
        };

        ensure!(out.shards > 1, "shard count must be > 1");
        ensure!(
            out.shards.is_power_of_two(),
            "shard count must be a power of two"
        );

        Ok(out)
    }
}

impl FromStr for ConcurrencyLockOptions {
    type Err = anyhow::Error;

    fn from_str(options: &str) -> Result<Self, Self::Err> {
        let error = || format!("failed to parse cache lock options '{options}'");
        Self::parse(options).with_context(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limiter::Aimd;

    #[test]
    fn test_parse_cache_options() -> anyhow::Result<()> {
        let CacheOptions { size, ttl } = "size=4096,ttl=5min".parse()?;
        assert_eq!(size, 4096);
        assert_eq!(ttl, Duration::from_secs(5 * 60));

        let CacheOptions { size, ttl } = "ttl=4m,size=2".parse()?;
        assert_eq!(size, 2);
        assert_eq!(ttl, Duration::from_secs(4 * 60));

        let CacheOptions { size, ttl } = "size=0,ttl=1s".parse()?;
        assert_eq!(size, 0);
        assert_eq!(ttl, Duration::from_secs(1));

        let CacheOptions { size, ttl } = "size=0".parse()?;
        assert_eq!(size, 0);
        assert_eq!(ttl, Duration::default());

        Ok(())
    }

    #[test]
    fn test_parse_lock_options() -> anyhow::Result<()> {
        let ConcurrencyLockOptions {
            epoch,
            limiter,
            shards,
            timeout,
        } = "shards=32,permits=4,epoch=10m,timeout=1s".parse()?;
        assert_eq!(epoch, Duration::from_secs(10 * 60));
        assert_eq!(timeout, Duration::from_secs(1));
        assert_eq!(shards, 32);
        assert_eq!(limiter.initial_limit, 4);
        assert_eq!(limiter.algorithm, RateLimitAlgorithm::Fixed);

        let ConcurrencyLockOptions {
            epoch,
            limiter,
            shards,
            timeout,
        } = "epoch=60s,shards=16,timeout=100ms,permits=8".parse()?;
        assert_eq!(epoch, Duration::from_secs(60));
        assert_eq!(timeout, Duration::from_millis(100));
        assert_eq!(shards, 16);
        assert_eq!(limiter.initial_limit, 8);
        assert_eq!(limiter.algorithm, RateLimitAlgorithm::Fixed);

        let ConcurrencyLockOptions {
            epoch,
            limiter,
            shards,
            timeout,
        } = "permits=0".parse()?;
        assert_eq!(epoch, Duration::ZERO);
        assert_eq!(timeout, Duration::ZERO);
        assert_eq!(shards, 2);
        assert_eq!(limiter.initial_limit, 0);
        assert_eq!(limiter.algorithm, RateLimitAlgorithm::Fixed);

        Ok(())
    }

    #[test]
    fn test_parse_json_lock_options() -> anyhow::Result<()> {
        let ConcurrencyLockOptions {
            epoch,
            limiter,
            shards,
            timeout,
        } = r#"{"shards":32,"initial_limit":44,"aimd":{"min":5,"max":500,"inc":10,"dec":0.9,"utilisation":0.8},"epoch":"10m","timeout":"1s"}"#
            .parse()?;
        assert_eq!(epoch, Duration::from_secs(10 * 60));
        assert_eq!(timeout, Duration::from_secs(1));
        assert_eq!(shards, 32);
        assert_eq!(limiter.initial_limit, 44);
        assert_eq!(
            limiter.algorithm,
            RateLimitAlgorithm::Aimd {
                conf: Aimd {
                    min: 5,
                    max: 500,
                    dec: 0.9,
                    inc: 10,
                    utilisation: 0.8
                }
            },
        );

        Ok(())
    }
}
