use reqwest::{Client, StatusCode};
use rustls::{Certificate, PrivateKey};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime };
use url::{ParseError, Url};
use crate::CallbackUrlError::{UrlParseError, UrlSchemeNotHttps};
use crate::CreatePaymentRequestError::{CertMismatch, HttpError, ServerError, Unauthorized, ValidationError};

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

pub struct Swish {
    base: String,
    client: Client,
    payee_alias: String
}

pub struct SwishCertificate {
    certs: Vec<Certificate>,
    key: PrivateKey
}
/// Represents the client certificate to be sent to swish
impl SwishCertificate {
    /// given file paths, this will load the given files
    ///
    /// the files need to be in der encoded format,
    /// witch are supplied by swish, (the .key and the .pem supplied)
    pub fn from_der(key_path: &str, chain: &str) -> Self {
        Self {
            certs: load_certs(chain),
            key: load_private_key(key_path)
        }
    }
}
impl Swish {
    pub fn build(base: String, cert: SwishCertificate, payee_alias: String) -> Self {
        let mut root_cert_store = rustls::RootCertStore::empty();
        root_cert_store.add(load_certs("Swish_TLS_RootCA.pem").first().unwrap()).unwrap();


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
            base,
            client,
            payee_alias,
        }
    }

    pub async fn create_payment_request(&self, instruction_uuid: String, request: PaymentRequestMCommerceParams) -> Result<PaymentResponseMCommerce, CreatePaymentRequestError> {
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
            .map_err(HttpError)?;

        match req.status() {
            StatusCode::CREATED => {
                let headers = req.headers();

                return Ok(PaymentResponseMCommerce {
                    location: headers["Location"].to_str().unwrap().to_string().parse().unwrap(),
                    payment_request_token: headers["PaymentRequestToken"].to_str().unwrap().to_string(),
                })
            }
            StatusCode::UNAUTHORIZED => Err(Unauthorized),
            StatusCode::FORBIDDEN => Err(CertMismatch),
            StatusCode::INTERNAL_SERVER_ERROR => Err(ServerError),
            StatusCode::UNPROCESSABLE_ENTITY => {
                let res = req.json::<Vec<CreatePaymentRequestErrorResponse>>().await.map_err(HttpError)?;
                Err(ValidationError(res.into_iter().map(|f| f.error_code).collect()))
            },
            _ => panic!("unexpected status code")
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
/// Because Swish is super picky about the payment id format, a helper method is optionality provided to use
#[cfg(feature = "gen_pay_ref")]
pub fn generate_payment_reference() -> String {
    uuid::Uuid::new_v4().to_string().replace('-', "").to_uppercase()
}

pub struct PaymentRequestMCommerceParams {
    amount: PaymentAmount,
    currency: Currency,
    callback_url: CallbackUrl,
    payee_payment_reference: String,
    message: String
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PaymentRequest<'a> {
    payee_alias: &'a str,
    amount: PaymentAmount,
    currency: Currency,
    callback_url: CallbackUrl,
    payee_payment_reference: String,
    message: String
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct PaymentResponseMCommerce {
    location: Url,
    payment_request_token: String
}

#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub struct CallbackUrl(Url);

impl CallbackUrl {
    pub fn new(value: String) -> Result<CallbackUrl, CallbackUrlError> {
        let url = Url::parse(
            &value
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

#[derive(Deserialize, Serialize, Debug, PartialEq)]
#[serde(transparent)]
pub struct PaymentAmount(f64);

impl PaymentAmount {
    pub fn from(whole: u64, part: u8) -> Option<PaymentAmount> {
        if part > 99 {
            return None
        }
        if whole > 999999999999 {
            return None
        }
        if whole == 0 && part == 0 {
            return None
        }
        Some(PaymentAmount(((whole * 100 + part as u64) / 100) as f64))
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Currency {
    Sek
}
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    Paid,
    Error,
    Declined,
    Pending,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CallbackResponse {
    id: String,
    payee_payment_reference: String,
    payment_reference: String,
    callback_url: Url,
    payer_alias: String,
    payee_alias: String,
    amount: PaymentAmount,
    currency: Currency,
    message: String,
    status: Status,
    #[serde(with = "time::serde::iso8601")]
    date_created: OffsetDateTime,
    #[serde(with = "time::serde::iso8601::option")]
    date_paid: Option<OffsetDateTime>,
    error_code: Option<ApiError>,
    error_message: Option<String>
}

/// all possible error codes
#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
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
    use axum::{extract, Router};
    use axum::routing::{post};
    use ngrok::config::TunnelBuilder;
    use ngrok::tunnel::UrlTunnel;
    use tokio::sync::mpsc::channel;
    use crate::Status::Paid;
    use super::*;

    async fn get_client_for_test() -> Swish {
        Swish::build("https://mss.cpc.getswish.net/swish-cpcapi".into(),
                     SwishCertificate::from_der("Swish_Merchant_TestCertificate_1234679304.key",
                                                "Swish_Merchant_TestCertificate_1234679304.pem"),
                     "1234679304".to_string())
    }

    #[tokio::test]
    async fn it_works() {
        let uuid = generate_payment_reference();
        let swish = get_client_for_test().await;
        let res = swish.create_payment_request(uuid, PaymentRequestMCommerceParams {
            amount: PaymentAmount::from(100, 00).unwrap(),
            currency: Currency::Sek,
            callback_url: CallbackUrl::new("https://localhost/test".to_string()).unwrap(),
            payee_payment_reference: "eee".to_string(),
            message: "eee".to_string(),
        }).await.unwrap();

        assert_eq!(res.location.host().unwrap().to_string(), "mss.cpc.getswish.net");
        assert!(!res.payment_request_token.is_empty());
    }
    // This sort of testes the simulator, but we use it to make sure we can parse the error response
    #[tokio::test]
    async fn it_errors() {
        let uuid = generate_payment_reference();
        let swish = get_client_for_test().await;
        let res = swish.create_payment_request(uuid, PaymentRequestMCommerceParams {
            amount: PaymentAmount::from(100, 00).unwrap(),
            currency: Currency::Sek,
            callback_url: CallbackUrl::new("https://localhost/test".to_string()).unwrap(),
            payee_payment_reference: "eee".to_string(),
            message: "ACMT03".to_string(),
        }).await;

        let Err(ValidationError(e)) = res else { panic!("should error"); };

        assert_eq!(e.iter().next(), Some(&ApiError::ACMT03));
    }

    // this test sets up a http server, exposes it via ngrock (it seems to work without credentials too),
    // and calls the api, expecting to be called back from the server via this temp connection.
    #[tokio::test]
    async fn it_calls_back() {
        let (sender, mut receiver) = channel(100);
        let join_handle = tokio::spawn(async move {
            let (tx, mut rx) = channel(1);
            let app = Router::new().route("/", post(|extract::Json(payload) : extract::Json<CallbackResponse>| async move {
                tx.send(()).await.unwrap();

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
                    swish.create_payment_request(uuid, PaymentRequestMCommerceParams {
                        amount: PaymentAmount::from(100, 00).unwrap(),
                        currency: Currency::Sek,
                        callback_url: CallbackUrl::new(url).unwrap(),
                        payee_payment_reference: "eee".to_string(),
                        message: "eee".to_string(),
                    }).await.unwrap();
                }
            }

        });
        tokio::try_join!(join_handle, send_handle).unwrap();
    }
}
