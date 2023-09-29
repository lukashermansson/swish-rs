pub mod refunds;
mod test_util;
pub mod payment_requests;

use std::error::Error;
use std::fmt::{Display};
use crate::CallbackUrlError::{UrlParseError, UrlSchemeNotHttps};
use reqwest::{Client};
use rustls::{Certificate, PrivateKey};
use serde::{Deserialize, Serialize};
use url::{ParseError, Url};

/// The swish client, can be constructed using the [`Self::build`] function
///
/// It verifies the server signature on each request against the provided server certificate.
/// It encapsulates an authentication method and the `payee_alias`, letting you configure it once
/// and reusing the client to perform multiple requests before disposing of the client
pub struct Swish {
    base: String,
    client: Client,
    payee_alias: String,
}

/// Represents the client certificate to be sent to swish,
/// its set up in a way where you decide for yourself how you load the certificates.
/// One approach is to load them from disk using the `rustls-pemfile` crate.
pub struct SwishCertificate {
    certs: Vec<Certificate>,
    key: PrivateKey,
}
impl SwishCertificate {
    pub fn from_der(key: PrivateKey, chain: Vec<Certificate>) -> Self {
        Self { certs: chain, key }
    }
}

impl Swish {
    /// builds a swish client
    ///
    /// This shows how you can build a client.
    ///
    /// ```
    /// # use rustls::{Certificate, PrivateKey};
    /// #   fn load_certs(filename: &str) -> Vec<Certificate> {
    /// #     let certfile = std::fs::File::open(filename).expect("cannot open certificate file");
    /// #     let mut reader = std::io::BufReader::new(certfile);
    /// #     rustls_pemfile::certs(&mut reader)
    /// #         .unwrap()
    /// #         .iter()
    /// #         .map(|v| Certificate(v.clone()))
    /// #         .collect()
    /// #   }
    /// #
    /// #   fn load_private_key(filename: &str) -> PrivateKey {
    /// #     let keyfile = std::fs::File::open(filename).expect("cannot open private key file");
    /// #     let mut reader = std::io::BufReader::new(keyfile);
    /// #
    /// #     loop {
    /// #         match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
    /// #             Some(rustls_pemfile::Item::RSAKey(key)) => return PrivateKey(key),
    /// #             Some(rustls_pemfile::Item::PKCS8Key(key)) => return PrivateKey(key),
    /// #             Some(rustls_pemfile::Item::ECKey(key)) => return PrivateKey(key),
    /// #             None => break,
    /// #             _ => {}
    /// #         }
    /// #     }
    /// #
    /// #     panic!(
    /// #         "no keys found in {:?} (encrypted keys not supported)",
    /// #         filename);
    /// #     }
    /// #
    /// #     async fn load_cert_from_disk() -> swish::SwishCertificate {
    /// #         swish::SwishCertificate::from_der(load_private_key("Swish_Merchant_TestCertificate_1234679304.key"), load_certs("Swish_Merchant_TestCertificate_1234679304.pem"))
    /// #     }
    /// #     let server_cert = load_certs("Swish_TLS_RootCA.pem").into_iter().next().expect("The provided root ca should have a cert");
    /// # tokio_test::block_on(async {
    /// let private_cert = load_cert_from_disk().await; // load your certs in your own way, its not included in this lib
    /// let swish_client = swish::Swish::build("https://mss.cpc.getswish.net/swish-cpcapi",
    ///                 private_cert,
    ///                 &server_cert,
    ///                 "1234679304");
    /// # });
    /// ```
    pub fn build(
        api_url_base: impl Into<String>,
        cert: SwishCertificate,
        swish_server_cert: &Certificate,
        payee_alias: impl Into<String>,
    ) -> Self {
        let mut root_cert_store = rustls::RootCertStore::empty();
        root_cert_store.add(swish_server_cert).unwrap();

        let tls = rustls::ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_cert_store)
            .with_client_auth_cert(cert.certs, cert.key)
            .unwrap();

        let client = reqwest::ClientBuilder::new()
            .use_preconfigured_tls(tls)
            .build()
            .unwrap();
        Self {
            base: api_url_base.into(),
            client,
            payee_alias: payee_alias.into(),
        }
    }

}

/// Because Swish is super picky about the payment id format, a helper method is optionality provided to use
/// uses `uuid` under the hood to generate a sting in the format:`11A86BE70EA346E4B1C39C874173F088`
/// ```
/// use swish::generate_payment_reference;
/// let swish_compatible_id = generate_payment_reference();
/// ```
#[cfg(feature = "gen_pay_ref")]
pub fn generate_payment_reference() -> String {
    uuid::Uuid::new_v4()
        .to_string()
        .replace('-', "")
        .to_uppercase()
}


/// A callback url, only supports HTTPS based urls.
#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub struct CallbackUrl(Url);

impl CallbackUrl {
    pub fn new(value: impl AsRef<str>) -> Result<CallbackUrl, CallbackUrlError> {
        let url = Url::parse(value.as_ref()).map_err(UrlParseError)?;

        if url.scheme() != "https" {
            return Err(UrlSchemeNotHttps);
        }
        Ok(CallbackUrl(url))
    }
}
#[derive(Debug)]
pub enum CallbackUrlError {
    UrlSchemeNotHttps,
    UrlParseError(ParseError),
}
/// A payment amount in the range 0.01..1000000000000
#[derive(Deserialize, Serialize, Debug, PartialEq, Clone, PartialOrd)]
#[serde(transparent)]
pub struct PaymentAmount(f64);

impl PaymentAmount {
    pub fn from(integer: u64, fraction: u8) -> Option<PaymentAmount> {
        if fraction > 99 {
            return None;
        }
        if integer > 999999999999 {
            return None;
        }
        if integer == 0 && fraction == 0 {
            return None;
        }
        Some(PaymentAmount(
            ((integer * 100 + fraction as u64) / 100) as f64,
        ))
    }
}

/// Supported currencies for swish
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Currency {
    Sek,
}

