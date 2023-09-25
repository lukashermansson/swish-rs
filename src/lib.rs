use reqwest::{Client, StatusCode};
use rustls::{Certificate, PrivateKey};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime };
use url::{ParseError, Url};
use crate::CallbackUrlError::{UrlParseError, UrlSchemeNotHttps};

/// The swish client, can be constructed using the [`Self::build`] function
///
/// It verifies the server signature on each request against the provided server certificate.
/// It encapsulates an authentication method and the `payee_alias`, letting you configure it once
/// and reusing the client to perform multiple requests before disposing of the client
pub struct Swish {
    base: String,
    client: Client,
    payee_alias: String
}

/// Represents the client certificate to be sent to swish,
/// its set up in a way where you decide for yourself how you load the certificates.
/// One approach is to load them from disk using the `rustls-pemfile` crate.
pub struct SwishCertificate {
    certs: Vec<Certificate>,
    key: PrivateKey
}
impl SwishCertificate {
    pub fn from_der(key: PrivateKey, chain: Vec<Certificate>) -> Self {
        Self {
            certs: chain,
            key
        }
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
    /// #             Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
    /// #             Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
    /// #             Some(rustls_pemfile::Item::ECKey(key)) => return rustls::PrivateKey(key),
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
    pub fn build(api_url_base: impl Into<String>, cert: SwishCertificate, swish_server_cert: &Certificate, payee_alias: impl Into<String>) -> Self {
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

    /// Creates M-Commerce payment request
    /// ```
    /// #   fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    /// #     let certfile = std::fs::File::open(filename).expect("cannot open certificate file");
    /// #     let mut reader = std::io::BufReader::new(certfile);
    /// #     rustls_pemfile::certs(&mut reader)
    /// #         .unwrap()
    /// #         .iter()
    /// #         .map(|v| rustls::Certificate(v.clone()))
    /// #         .collect()
    /// #     }
    /// #
    /// #   fn load_private_key(filename: &str) -> rustls::PrivateKey {
    /// #     let keyfile = std::fs::File::open(filename).expect("cannot open private key file");
    /// #     let mut reader = std::io::BufReader::new(keyfile);
    /// #
    /// #     loop {
    /// #         match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
    /// #             Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
    /// #             Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
    /// #             Some(rustls_pemfile::Item::ECKey(key)) => return rustls::PrivateKey(key),
    /// #             None => break,
    /// #             _ => {}
    /// #         }
    /// #      }
    /// #
    /// #      panic!(
    /// #         "no keys found in {:?} (encrypted keys not supported)",
    /// #         filename
    /// #      );
    /// #   }
    /// #
    /// #   async fn load_cert_from_disk() -> swish::SwishCertificate {
    /// #     swish::SwishCertificate::from_der(load_private_key("Swish_Merchant_TestCertificate_1234679304.key"), load_certs("Swish_Merchant_TestCertificate_1234679304.pem"))
    /// #   }
    /// # tokio_test::block_on(async {
    /// # let server_cert = load_certs("Swish_TLS_RootCA.pem").into_iter().next().expect("The provided root ca should have a cert");
    /// # let private_cert = load_cert_from_disk().await;
    /// let swish_client = swish::Swish::build("https://mss.cpc.getswish.net/swish-cpcapi",
    ///                 private_cert,
    ///                 &server_cert,
    ///                 "1234679304");
    ///
    /// let response = swish_client.create_m_commerce_payment_request("0902D12C7FAE43D3AAAC49622AA79FEF", swish::PaymentRequestMCommerceParams {
    ///     amount: swish::PaymentAmount::from(100, 00).unwrap(),
    ///     currency: swish::Currency::Sek,
    ///     callback_url: swish::CallbackUrl::new("https://myhost.net/swish-callback").unwrap(),
    ///     payee_payment_reference: None,
    ///     message: None,
    /// }).await;
    /// # })
    /// ```
    pub async fn create_m_commerce_payment_request(&self, instruction_uuid: &str, request: PaymentRequestMCommerceParams) -> Result<PaymentResponseMCommerce, CreatePaymentRequestError> {
        let req  = self.client
            .put(format!("{}/api/v2/paymentrequests/{}", self.base, instruction_uuid))
            .json(&PaymentRequest {
                payee_alias: &self.payee_alias,
                amount: request.amount,
                currency: request.currency,
                callback_url: request.callback_url,
                payee_payment_reference: request.payee_payment_reference,
                message: request.message,
            })
            .send()
            .await
            .map_err(CreatePaymentRequestError::HttpError)?;

        match req.status() {
            StatusCode::CREATED => {
                let headers = req.headers();

                return Ok(PaymentResponseMCommerce {
                    location: headers["Location"].to_str().expect("Should contain a string").to_string().parse().expect("Should contain a url"),
                    payment_request_token: headers["PaymentRequestToken"].to_str().expect("Should contain a string").to_string(),
                })
            }
            StatusCode::UNAUTHORIZED => Err(CreatePaymentRequestError::Unauthorized),
            StatusCode::FORBIDDEN => Err(CreatePaymentRequestError::CertMismatch),
            StatusCode::INTERNAL_SERVER_ERROR => Err(CreatePaymentRequestError::ServerError),
            StatusCode::UNPROCESSABLE_ENTITY => {
                let res = req.json::<Vec<CreatePaymentRequestErrorResponse>>().await.map_err(CreatePaymentRequestError::HttpError)?;
                Err(CreatePaymentRequestError::ValidationError(res.into_iter().map(|f| f.error_code).collect()))
            },
            s => panic!("unexpected status code: {}", s)
        }
    }

    /// Fetches the status of a swish order
    pub async fn fetch_payment_request(&self, instruction_uuid: &str) -> Result<SwishOrder, FetchPaymentRequestError> {
        let req  = self.client
            .get(format!("{}/api/v1/paymentrequests/{}", self.base, instruction_uuid))
            .send()
            .await
            .map_err(FetchPaymentRequestError::HttpError)?;

        match req.status() {
            StatusCode::OK => {
                return Ok(req.json::<SwishOrder>().await.map_err(FetchPaymentRequestError::HttpError)?)
            }
            StatusCode::UNAUTHORIZED => Err(FetchPaymentRequestError::Unauthorized),
            StatusCode::FORBIDDEN => Err(FetchPaymentRequestError::CertMismatch),
            StatusCode::INTERNAL_SERVER_ERROR => Err(FetchPaymentRequestError::ServerError),
            s => panic!("unexpected status code: {}", s)
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
struct CreatePaymentRequestErrorResponse {
    error_code: ApiError
}
#[derive(Debug)]
pub enum CreatePaymentRequestError {
    // represents all kind of validation errors
    ValidationError(Vec<ApiError>),
    HttpError(reqwest::Error),
    // the server does not think the cert is valid
    Unauthorized,
    // the number listed on the cert does not correspond with the number in the request
    CertMismatch,
    ServerError,
}

#[derive(Debug)]
pub enum FetchPaymentRequestError {
    HttpError(reqwest::Error),
    // the server does not think the cert is valid
    Unauthorized,
    // the number listed on the cert does not correspond with the number in the request
    CertMismatch,
    ServerError,
}
/// Because Swish is super picky about the payment id format, a helper method is optionality provided to use
/// uses `uuid` under the hood to generate a sting in the format:
/// ```
/// use swish::generate_payment_reference;
/// let swish_compatible_id = generate_payment_reference();
/// ```
#[cfg(feature = "gen_pay_ref")]
pub fn generate_payment_reference() -> String {
    uuid::Uuid::new_v4().to_string().replace('-', "").to_uppercase()
}

/// Represents the available params for initializing a payment request using the M-Commerce flow
pub struct PaymentRequestMCommerceParams {
    pub amount: PaymentAmount,
    pub currency: Currency,
    pub callback_url: CallbackUrl,
    pub payee_payment_reference: Option<String>,
    pub message: Option<String>
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PaymentRequest<'a> {
    payee_alias: &'a str,
    amount: PaymentAmount,
    currency: Currency,
    callback_url: CallbackUrl,
    payee_payment_reference: Option<String>,
    message: Option<String>
}

/// The response of [`Swish::create_m_commerce_payment_request`] when successful
/// contains the location of where the order can be fetched using the [`Swish::fetch_payment_request`]
/// and the "auto-start token" of the order
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct PaymentResponseMCommerce {
    pub location: Url,
    pub payment_request_token: String
}

/// A callback url, only supports HTTPS based urls.
#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub struct CallbackUrl(Url);

impl CallbackUrl {
    pub fn new(value: impl AsRef<str>) -> Result<CallbackUrl, CallbackUrlError> {
        let url = Url::parse(
            value.as_ref()
        ).map_err(UrlParseError)?;

        if url.scheme() != "https" {
            return Err(UrlSchemeNotHttps)
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
            return None
        }
        if integer > 999999999999 {
            return None
        }
        if integer == 0 && fraction == 0 {
            return None
        }
        Some(PaymentAmount(((integer * 100 + fraction as u64) / 100) as f64))
    }
}

/// Supported currencies for swish
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Currency {
    Sek
}
/// The status of a [`SwishOrder`]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    Paid,
    Error,
    Declined,
    Pending,
}
/// A swish order.
#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwishOrder {
    pub id: String,
    pub payee_payment_reference: String,
    pub payment_reference: String,
    pub callback_url: Url,
    pub payer_alias: String,
    pub payee_alias: String,
    pub amount: PaymentAmount,
    pub currency: Currency,
    pub message: String,
    pub status: Status,
    #[serde(with = "time::serde::iso8601")]
    pub date_created: OffsetDateTime,
    #[serde(with = "time::serde::iso8601::option")]
    pub date_paid: Option<OffsetDateTime>,
    pub error_code: Option<ApiError>,
    pub error_message: Option<String>
}

/// All possible error codes from swish that have been encountered
#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum ApiError {
    FF08,
    RP03,
    BE18,
    RP01,
    PA02,
    AM06,
    AM02,
    AM03,
    RP02,
    RP06,
    ACMT03,
    ACMT01,
    ACMT07,
    UNKW,
    VR01,
    VR02,
    PA01,
    RF07,
    BANKIDCL,
    FF10,
    TM01,
    DS24,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use axum::{extract, Router};
    use axum::routing::{post};
    use ngrok::config::TunnelBuilder;
    use ngrok::tunnel::UrlTunnel;
    use tokio::sync::mpsc::channel;
    use crate::Status::Paid;
    use super::*;

    fn load_certs(filename: &str) -> Vec<Certificate> {
        let certfile = std::fs::File::open(filename).expect("cannot open certificate file");
        let mut reader = std::io::BufReader::new(certfile);
        rustls_pemfile::certs(&mut reader)
            .unwrap()
            .iter()
            .map(|v| Certificate(v.clone()))
            .collect()
    }

    fn load_private_key(filename: &str) -> PrivateKey {
        let keyfile = std::fs::File::open(filename).expect("cannot open private key file");
        let mut reader = std::io::BufReader::new(keyfile);

        loop {
            match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
                Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
                Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
                Some(rustls_pemfile::Item::ECKey(key)) => return rustls::PrivateKey(key),
                None => break,
                _ => {}
            }
        }

        panic!(
            "no keys found in {:?} (encrypted keys not supported)",
            filename
        );
    }

    async fn load_cert_from_disk() -> SwishCertificate {
        SwishCertificate::from_der(load_private_key("Swish_Merchant_TestCertificate_1234679304.key"), load_certs("Swish_Merchant_TestCertificate_1234679304.pem"))
    }

    async fn get_client_for_test() -> Swish {
        Swish::build("https://mss.cpc.getswish.net/swish-cpcapi",
                     load_cert_from_disk().await,
                     load_certs("Swish_TLS_RootCA.pem").first().expect("The provided root ca should have a cert"),
                     "1234679304")
    }

    #[tokio::test]
    async fn payment_request_can_be_issued() {
        let uuid = generate_payment_reference();
        let swish = get_client_for_test().await;
        let res = swish.create_m_commerce_payment_request(&uuid, PaymentRequestMCommerceParams {
            amount: PaymentAmount::from(100, 00).unwrap(),
            currency: Currency::Sek,
            callback_url: CallbackUrl::new("https://localhost/test".to_string()).unwrap(),
            payee_payment_reference: Some("eee".to_string()),
            message: Some("eee".to_string()),
        }).await.unwrap();

        assert_eq!(res.location.host().unwrap().to_string(), "mss.cpc.getswish.net");
        assert!(!res.payment_request_token.is_empty());
    }

    #[tokio::test]
    async fn it_works_using_polling() {
        let uuid = generate_payment_reference();
        let swish = get_client_for_test().await;
        swish.create_m_commerce_payment_request(&uuid, PaymentRequestMCommerceParams {
            amount: PaymentAmount::from(100, 00).unwrap(),
            currency: Currency::Sek,
            callback_url: CallbackUrl::new("https://localhost/test".to_string()).unwrap(),
            payee_payment_reference: Some("ref".to_string()),
            message: Some("msg".to_string()),
        }).await.unwrap();

        tokio::time::sleep(Duration::from_secs(4)).await; // the test env takes about 4 seconds to get the status to paid

        let res = swish.fetch_payment_request(&uuid).await.expect("Should have a response");

        assert_eq!(res.error_message, None);
        assert_eq!(res.amount, PaymentAmount::from(100, 00).unwrap());
        assert_eq!(res.currency, Currency::Sek);
        assert_eq!(&res.id, &uuid);
        assert_eq!(res.payee_payment_reference, "ref");
        assert_eq!(res.status, Paid);
        assert_eq!(res.message, "msg");
    }
    // This sort of testes the simulator, but we use it to make sure we can parse the error response
    #[tokio::test]
    async fn it_errors() {
        let uuid = generate_payment_reference();
        let swish = get_client_for_test().await;
        let res = swish.create_m_commerce_payment_request(&uuid, PaymentRequestMCommerceParams {
            amount: PaymentAmount::from(100, 00).unwrap(),
            currency: Currency::Sek,
            callback_url: CallbackUrl::new("https://localhost/test".to_string()).unwrap(),
            payee_payment_reference: Some("eee".to_string()),
            message: Some("ACMT03".to_string()),
        }).await;

        let Err(CreatePaymentRequestError::ValidationError(e)) = res else { panic!("should error"); };

        assert_eq!(e.iter().next(), Some(&ApiError::ACMT03));
    }

    // this test sets up a https server, exposes it via ngrock (it seems to work without credentials too),
    // and calls the api, expecting to be called back from the server via this temp connection.
    #[tokio::test]
    async fn it_calls_back() {
        let (sender, mut receiver) = channel(100);
        let join_handle = tokio::spawn(async move {
            let (tx, mut rx) = channel(1);
            let app = Router::new().route("/", post(|extract::Json(payload) : extract::Json<SwishOrder>| async move {
                tx.send(()).await.unwrap();

                println!("{:?}", payload);
                // this will just panic a runtime thread of axum, so not ideal for asserting this stuff
                assert_eq!(payload.error_code, None);
                assert_eq!(payload.status, Paid);
                assert_eq!(payload.message, "eee");
                assert_eq!(payload.currency, Currency::Sek);
                assert_eq!(payload.payee_payment_reference, "eee");
                assert!(payload.date_paid.is_some());
                assert_eq!(payload.error_message, None);

                // just send this to swish to thank the server for all the hard work
                "good job, swish!"
            }));

            let listener = ngrok::Session::builder()
                .authtoken_from_env()
                .connect()
                .await.unwrap()
                .http_endpoint()
                .listen()
                .await.unwrap();
            sender.send(listener.url().to_string()).await.unwrap();
            axum::Server::builder(listener)
                .serve(app.into_make_service())
                .with_graceful_shutdown(async { rx.recv().await.unwrap(); })
                .await
                .unwrap();
        });
        let send_handle = tokio::spawn(async move {
            let url = receiver.recv().await;
            match url {
                None => {}
                Some(url) => {
                    let uuid = generate_payment_reference();
                    let swish = get_client_for_test().await;
                    swish.create_m_commerce_payment_request(&uuid, PaymentRequestMCommerceParams {
                        amount: PaymentAmount::from(100, 00).unwrap(),
                        currency: Currency::Sek,
                        callback_url: CallbackUrl::new(url).unwrap(),
                        payee_payment_reference: Some("eee".to_string()),
                        message: Some("eee".to_string()),
                    }).await.unwrap();
                }
            }

        });
        tokio::try_join!(join_handle, send_handle).unwrap();
    }
}
