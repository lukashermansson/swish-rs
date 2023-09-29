use std::error::Error;
use std::fmt::{Display, Formatter, Write};
use reqwest::header::{CONTENT_TYPE, ToStrError};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::{ParseError, Url};
use crate::{CallbackUrl, Currency, PaymentAmount, Swish};

impl Swish {

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
    /// let response = swish_client.create_m_commerce_payment_request("0902D12C7FAE43D3AAAC49622AA79FEF", swish::payment_requests::PaymentRequestMCommerceParams {
    ///     amount: swish::PaymentAmount::from(100, 00).unwrap(),
    ///     currency: swish::Currency::Sek,
    ///     callback_url: swish::CallbackUrl::new("https://myhost.net/swish-callback").unwrap(),
    ///     payee_payment_reference: None,
    ///     message: None,
    /// }).await;
    /// # })
    /// ```
    pub async fn create_m_commerce_payment_request(
        &self,
        instruction_uuid: &str,
        request: PaymentRequestMCommerceParams,
    ) -> Result<PaymentResponseMCommerce, CreatePaymentRequestError> {
        let req = self
            .client
            .put(format!(
                "{}/api/v2/paymentrequests/{}",
                self.base, instruction_uuid
            ))
            .json(&PaymentRequest {
                payee_alias: &self.payee_alias,
                payer_alias: None,
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
                    location: headers["Location"]
                        .to_str()
                        .map_err(|e|CreatePaymentRequestError::InvalidSwishResponse(InvalidSwishResponse::NotValidUtf8Response(e)))?
                        .to_string()
                        .parse()
                        .map_err(|e| CreatePaymentRequestError::InvalidSwishResponse(InvalidSwishResponse::LocationNotValidUrl(e)))?,
                    payment_request_token: headers["PaymentRequestToken"]
                        .to_str()
                        .map_err(|e| CreatePaymentRequestError::InvalidSwishResponse(InvalidSwishResponse::NotValidUtf8Response(e)))?
                        .to_string(),
                });
            }
            StatusCode::UNAUTHORIZED => Err(CreatePaymentRequestError::Unauthorized),
            StatusCode::FORBIDDEN => Err(CreatePaymentRequestError::CertMismatch),
            StatusCode::INTERNAL_SERVER_ERROR => Err(CreatePaymentRequestError::ServerError),
            StatusCode::UNPROCESSABLE_ENTITY => {
                let res = req
                    .json::<Vec<CreatePaymentRequestErrorResponse>>()
                    .await
                    .map_err(CreatePaymentRequestError::HttpError)?;
                Err(CreatePaymentRequestError::ValidationError(
                    res.into_iter().map(|f| f.error_code).collect(),
                ))
            }
            s => panic!("unexpected status code: {}", s),
        }
    }

    /// Creates E-Commerce payment request
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
    /// let response = swish_client.create_e_commerce_payment_request("0902D12C7FAE43D3AAAC49622AA79FEF", swish::payment_requests::PaymentRequestECommerceParams {
    ///     amount: swish::PaymentAmount::from(100, 00).unwrap(),
    ///     payer_alias: "4671234768".to_string(),
    ///     currency: swish::Currency::Sek,
    ///     callback_url: swish::CallbackUrl::new("https://myhost.net/swish-callback").unwrap(),
    ///     payee_payment_reference: None,
    ///     message: None,
    /// }).await;
    /// # })
    /// ```
    pub async fn create_e_commerce_payment_request(
        &self,
        instruction_uuid: &str,
        request: PaymentRequestECommerceParams,
    ) -> Result<PaymentResponseECommerce, CreatePaymentRequestError> {
        let req = self
            .client
            .put(format!(
                "{}/api/v2/paymentrequests/{}",
                self.base, instruction_uuid
            ))
            .json(&PaymentRequest {
                payee_alias: &self.payee_alias,
                payer_alias: Some(request.payer_alias),
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

                return Ok(PaymentResponseECommerce {
                    location: headers["Location"]
                        .to_str()
                        .map_err(|e|CreatePaymentRequestError::InvalidSwishResponse(InvalidSwishResponse::NotValidUtf8Response(e)))?
                        .to_string()
                        .parse()
                        .map_err(|e| CreatePaymentRequestError::InvalidSwishResponse(InvalidSwishResponse::LocationNotValidUrl(e)))?,
                });
            }
            StatusCode::UNAUTHORIZED => Err(CreatePaymentRequestError::Unauthorized),
            StatusCode::FORBIDDEN => Err(CreatePaymentRequestError::CertMismatch),
            StatusCode::INTERNAL_SERVER_ERROR => Err(CreatePaymentRequestError::ServerError),
            StatusCode::UNPROCESSABLE_ENTITY => {
                let res = req
                    .json::<Vec<CreatePaymentRequestErrorResponse>>()
                    .await
                    .map_err(CreatePaymentRequestError::HttpError)?;
                Err(CreatePaymentRequestError::ValidationError(
                    res.into_iter().map(|f| f.error_code).collect(),
                ))
            }
            s => panic!("unexpected status code: {}", s),
        }
    }


    /// Fetches the status of a swish order
    pub async fn fetch_payment_request(
        &self,
        instruction_uuid: &str,
    ) -> Result<SwishOrder, FetchPaymentRequestError> {
        let req = self
            .client
            .get(format!(
                "{}/api/v1/paymentrequests/{}",
                self.base, instruction_uuid
            ))
            .send()
            .await
            .map_err(FetchPaymentRequestError::HttpError)?;

        match req.status() {
            StatusCode::OK => {
                return Ok(req
                    .json::<SwishOrder>()
                    .await
                    .map_err(FetchPaymentRequestError::HttpError)?)
            }
            StatusCode::UNAUTHORIZED => Err(FetchPaymentRequestError::Unauthorized),
            StatusCode::FORBIDDEN => Err(FetchPaymentRequestError::CertMismatch),
            StatusCode::INTERNAL_SERVER_ERROR => Err(FetchPaymentRequestError::ServerError),
            s => panic!("unexpected status code: {}", s),
        }
    }
    /// cancels a pending swish order
    pub async fn cancel_payment_request(
        &self,
        instruction_uuid: &str,
    ) -> Result<SwishOrder, CancelPaymentRequestError> {
        let req = self
            .client
            .patch(format!(
                "{}/api/v1/paymentrequests/{}",
                self.base, instruction_uuid
            ))
            .body(r#"[{
    "op": "replace",
    "path": "/status",
    "value": "cancelled"
}]"#)
            .header(CONTENT_TYPE, "application/json-patch+json")
            .send()
            .await
            .map_err(CancelPaymentRequestError::HttpError)?;

        match req.status() {
            StatusCode::OK => {
                return Ok(req
                    .json::<SwishOrder>()
                    .await
                    .map_err(CancelPaymentRequestError::HttpError)?)
            }
            StatusCode::UNPROCESSABLE_ENTITY => Err(CancelPaymentRequestError::OrderNotCancellable),
            s => panic!("unexpected status code: {}, {:?}", s, req.text().await),
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
struct CreatePaymentRequestErrorResponse {
    error_code: ApiError,
}
#[derive(Debug)]
pub enum CreatePaymentRequestError {
    // represents all kind of validation errors
    ValidationError(Vec<ApiError>),
    InvalidSwishResponse(InvalidSwishResponse),
    HttpError(reqwest::Error),
    // the server does not think the cert is valid
    Unauthorized,
    // the number listed on the cert does not correspond with the number in the request
    CertMismatch,
    ServerError,
}
#[derive(Debug)]
pub enum InvalidSwishResponse {
    LocationNotValidUrl(ParseError),
    NotValidUtf8Response(ToStrError)
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

#[derive(Debug)]
pub enum CancelPaymentRequestError {
    HttpError(reqwest::Error),
    OrderNotCancellable
}
/// Represents the available params for initializing a payment request using the M-Commerce flow
pub struct PaymentRequestMCommerceParams {
    pub amount: PaymentAmount,
    pub currency: Currency,
    pub callback_url: CallbackUrl,
    pub payee_payment_reference: Option<String>,
    pub message: Option<String>,
}

/// Represents the available params for initializing a payment request using the E-Commerce flow
pub struct PaymentRequestECommerceParams {
    pub amount: PaymentAmount,
    pub payer_alias: String,
    pub currency: Currency,
    pub callback_url: CallbackUrl,
    pub payee_payment_reference: Option<String>,
    pub message: Option<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PaymentRequest<'a> {
    payee_alias: &'a str,
    payer_alias: Option<String>,
    amount: PaymentAmount,
    currency: Currency,
    callback_url: CallbackUrl,
    payee_payment_reference: Option<String>,
    message: Option<String>,
}

/// The response of [`Swish::create_m_commerce_payment_request`] when successful
/// contains the location of where the order can be fetched using the [`Swish::fetch_payment_request`]
/// and the "auto-start token" of the order
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct PaymentResponseMCommerce {
    pub location: Url,
    pub payment_request_token: String,
}

/// The response of [`Swish::create_e_commerce_payment_request`] when successful
/// contains the location of where the order can be fetched using the [`Swish::fetch_payment_request`]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct PaymentResponseECommerce {
    pub location: Url,
}

/// The status of a [`SwishOrder`]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    Paid,
    Error,
    Declined,
    Cancelled, /// this is for wehn the merchant decides to cancel the request with [`Swish::cancel_payment_request`]
    Pending,
}
/// A swish order. can be requested by [`Swish::fetch_payment_request`] for `polling` use cases
/// can also be used when deserializing callbacks from swish
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
    pub error_message: Option<String>,
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
    VR01,
    VR02,
    RP09,
    RF07,
    BANKIDCL,
    FF10,
    TM01,
    DS24,
    RP08,
}

impl Error for ApiError {}
impl Display for ApiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::FF08 => f.write_str("PaymentReference is invalid."),
            ApiError::RP03 => f.write_str("Callback URL is missing or does not use HTTPS."),
            ApiError::BE18 => f.write_str("Payer alias is invalid."),
            ApiError::RP01 => f.write_str("Missing Merchant Swish Number."),
            ApiError::PA02 => f.write_str("Amount value is missing or not a valid number."),
            ApiError::AM02 => f.write_str("Amount value is too large."),
            ApiError::AM03 => f.write_str("Invalid or missing Currency."),
            ApiError::AM06 => f.write_str("Specified transaction amount is less than agreed minimum."),
            ApiError::RP02 => f.write_str("Wrong formatted message."),
            ApiError::RP06 => f.write_str("A payment request already exists for that payer. Only applicable for Swish e-commerce."),
            ApiError::ACMT03 => f.write_str("Payer not Enrolled."),
            ApiError::ACMT01 => f.write_str("Counterpart is not activated."),
            ApiError::ACMT07 => f.write_str("Payee not Enrolled."),
            ApiError::VR01 => f.write_str("Payer does not meet age limit."),
            ApiError::VR02 => f.write_str("The payer alias in the request is not enroled in swish with the supplied ssn."),
            ApiError::RP09 => f.write_str("The given instructionUUID is not available Note: The instructionUUID already exist in the database, i.e. it is not unique."),
            ApiError::RF07 => f.write_str("Transaction declined"),
            ApiError::BANKIDCL => f.write_str("Payer cancelled BankId signing"),
            ApiError::FF10 => f.write_str("Bank system processing error"),
            ApiError::TM01 => f.write_str("Swish timed out before the payment was started"),
            ApiError::DS24 => f.write_str("Swish timed out waiting for an answer from the banks after payment was started.
            Note: If this happens Swish has no knowledge of whether the payment
            was successful or not. The Merchant should inform its consumer about this and
            recommend them to check with their bank about the status of this payment."),
            ApiError::RP08 => f.write_str("The payment request has been cancelled."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post;
    use axum::{extract, Router};
    use ngrok::config::TunnelBuilder;
    use ngrok::tunnel::UrlTunnel;
    use std::time::Duration;
    use tokio::sync::mpsc::channel;
    use crate::generate_payment_reference;
    use crate::payment_requests::Status::Paid;
    use crate::test_util::tests::{load_cert_from_disk, load_server_ca};

    async fn get_client_for_test() -> Swish {
        Swish::build(
            "https://mss.cpc.getswish.net/swish-cpcapi",
            load_cert_from_disk().await,
            &load_server_ca(),
            "1234679304",
        )
    }

    #[tokio::test]
    async fn payment_request_can_be_issued() {
        let uuid = generate_payment_reference();
        let swish = get_client_for_test().await;
        let res = swish
            .create_m_commerce_payment_request(
                &uuid,
                PaymentRequestMCommerceParams {
                    amount: PaymentAmount::from(100, 00).unwrap(),
                    currency: Currency::Sek,
                    callback_url: CallbackUrl::new("https://localhost/test".to_string()).unwrap(),
                    payee_payment_reference: Some("eee".to_string()),
                    message: Some("eee".to_string()),
                },
            )
            .await
            .unwrap();

        assert_eq!(
            res.location.host().unwrap().to_string(),
            "mss.cpc.getswish.net"
        );
        assert!(!res.payment_request_token.is_empty());
    }
    #[tokio::test]
    async fn payment_request_can_be_cancelled() {
        let uuid = generate_payment_reference();
        let swish = get_client_for_test().await;
        swish
            .create_e_commerce_payment_request(
                &uuid,
                PaymentRequestECommerceParams {
                    amount: PaymentAmount::from(100, 00).unwrap(),
                    payer_alias: "4671234768".to_string(),
                    currency: Currency::Sek,
                    callback_url: CallbackUrl::new("https://localhost/test".to_string()).unwrap(),
                    payee_payment_reference: Some("eee".to_string()),
                    message: Some("eee".to_string()),
                },
            )
            .await
            .unwrap();

        let res = swish.cancel_payment_request(&uuid).await.unwrap();

        assert_eq!(
            res.status,
            Status::Cancelled
        );
    }

    #[tokio::test]
    async fn it_works_using_polling_for_m_commerce() {
        let uuid = generate_payment_reference();
        let swish = get_client_for_test().await;
        swish
            .create_m_commerce_payment_request(
                &uuid,
                PaymentRequestMCommerceParams {
                    amount: PaymentAmount::from(100, 00).unwrap(),
                    currency: Currency::Sek,
                    callback_url: CallbackUrl::new("https://localhost/test".to_string()).unwrap(),
                    payee_payment_reference: Some("ref".to_string()),
                    message: Some("msg".to_string()),
                },
            )
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_secs(4)).await; // the test env takes about 4 seconds to get the status to paid

        let res = swish
            .fetch_payment_request(&uuid)
            .await
            .expect("Should have a response");

        assert_eq!(res.error_message, None);
        assert_eq!(res.amount, PaymentAmount::from(100, 00).unwrap());
        assert_eq!(res.currency, Currency::Sek);
        assert_eq!(&res.id, &uuid);
        assert_eq!(res.payee_payment_reference, "ref");
        assert_eq!(res.status, Paid);
        assert_eq!(res.message, "msg");
    }

    #[tokio::test]
    async fn it_works_using_polling_for_e_commerce() {
        let uuid = generate_payment_reference();
        let swish = get_client_for_test().await;
        swish
            .create_e_commerce_payment_request(
                &uuid,
                PaymentRequestECommerceParams {
                    amount: PaymentAmount::from(100, 00).unwrap(),
                    payer_alias: "4671234768".to_string(),
                    currency: Currency::Sek,
                    callback_url: CallbackUrl::new("https://localhost/test".to_string()).unwrap(),
                    payee_payment_reference: Some("ref".to_string()),
                    message: Some("msg".to_string()),
                },
            )
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_secs(4)).await; // the test env takes about 4 seconds to get the status to paid

        let res = swish
            .fetch_payment_request(&uuid)
            .await
            .expect("Should have a response");

        assert_eq!(res.error_message, None);
        assert_eq!(res.amount, PaymentAmount::from(100, 00).unwrap());
        assert_eq!(res.currency, Currency::Sek);
        assert_eq!(&res.id, &uuid);
        assert_eq!(res.payee_payment_reference, "ref");
        assert_eq!(res.payer_alias, "4671234768");
        assert_eq!(res.status, Paid);
        assert_eq!(res.message, "msg");
    }

    // This sort of testes the simulator, but we use it to make sure we can parse the error response
    #[tokio::test]
    async fn it_handles_errors() {
        let uuid = generate_payment_reference();
        let swish = get_client_for_test().await;
        let res = swish
            .create_m_commerce_payment_request(
                &uuid,
                PaymentRequestMCommerceParams {
                    amount: PaymentAmount::from(100, 00).unwrap(),
                    currency: Currency::Sek,
                    callback_url: CallbackUrl::new("https://localhost/test".to_string()).unwrap(),
                    payee_payment_reference: Some("eee".to_string()),
                    message: Some("ACMT03".to_string()),
                },
            )
            .await;

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
            let app = Router::new().route(
                "/",
                post(
                    |extract::Json(payload): extract::Json<SwishOrder>| async move {
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
                    },
                ),
            );

            let listener = ngrok::Session::builder()
                .authtoken_from_env()
                .connect()
                .await
                .unwrap()
                .http_endpoint()
                .listen()
                .await
                .unwrap();
            sender.send(listener.url().to_string()).await.unwrap();
            axum::Server::builder(listener)
                .serve(app.into_make_service())
                .with_graceful_shutdown(async {
                    rx.recv().await.unwrap();
                })
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
                    swish
                        .create_m_commerce_payment_request(
                            &uuid,
                            PaymentRequestMCommerceParams {
                                amount: PaymentAmount::from(100, 00).unwrap(),
                                currency: Currency::Sek,
                                callback_url: CallbackUrl::new(url).unwrap(),
                                payee_payment_reference: Some("eee".to_string()),
                                message: Some("eee".to_string()),
                            },
                        )
                        .await
                        .unwrap();
                }
            }
        });
        tokio::try_join!(join_handle, send_handle).unwrap();
    }
}
