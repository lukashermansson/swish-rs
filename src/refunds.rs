use reqwest::header::ToStrError;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::{ParseError, Url};
use crate::{CallbackUrl, Currency, PaymentAmount, Swish};

impl Swish {
    /// Create refund request
    pub async fn create_refund_request(
        &self,
        instruction_uuid: &str,
        request: RefundRequestParams,
    ) -> Result<PaymentResponseSuccessfullResponse, CreateRefundRequestError> {
        let req = self
            .client
            .put(format!(
                "{}/api/v2/refunds/{}",
                self.base, instruction_uuid
            ))
            .json(&RefundRequest {
                amount: request.amount,
                currency: request.currency,
                callback_url: request.callback_url,
                payer_payment_reference: None,
                message: request.message,
                original_payment_reference: request.original_payment_reference,
                payer_alias: self.payee_alias.to_string(),
            })
            .send()
            .await
            .map_err(CreateRefundRequestError::HttpError)?;

        match req.status() {
            StatusCode::CREATED => {
                let headers = req.headers();

                return Ok(PaymentResponseSuccessfullResponse {
                    location: headers["Location"]
                        .to_str()
                        .map_err(|e|CreateRefundRequestError::InvalidSwishResponse(InvalidSwishResponse::NotValidUtf8Response(e)))?
                        .to_string()
                        .parse()
                        .map_err(|e| CreateRefundRequestError::InvalidSwishResponse(InvalidSwishResponse::LocationNotValidUrl(e)))?,

                });
            }
            StatusCode::UNAUTHORIZED =>Err(CreateRefundRequestError::Unauthorized),
            StatusCode::FORBIDDEN => Err(CreateRefundRequestError::CertMismatch),
            StatusCode::INTERNAL_SERVER_ERROR => Err(CreateRefundRequestError::ServerError),
            StatusCode::UNPROCESSABLE_ENTITY => {
                let res = req
                    .json::<Vec<CreateRefundRequestErrorResponse>>()
                     .await
                     .map_err(CreateRefundRequestError::HttpError)?;
                 Err(CreateRefundRequestError::ValidationError(
                    res
                ))
            }
            s => panic!("unexpected status code: {}", s),
        }
    }
    pub async fn retrieve_refund(
        &self,
        instruction_uuid: &str,
    ) -> Result<RefundOrder, RetriveRefundRequestError> {
        let req = self
            .client
            .get(format!(
                "{}/api/v1/refunds/{}",
                self.base, instruction_uuid
            ))
            .send()
            .await
            .map_err(RetriveRefundRequestError::HttpError)?;

        match req.status() {
            StatusCode::OK => {
                return Ok(req
                    .json::<RefundOrder>()
                    .await
                    .map_err(RetriveRefundRequestError::HttpError)?)
            }
            StatusCode::UNAUTHORIZED => Err(RetriveRefundRequestError::Unauthorized),
            StatusCode::INTERNAL_SERVER_ERROR => Err(RetriveRefundRequestError::ServerError),
            StatusCode::NOT_FOUND => Err(RetriveRefundRequestError::NotFound),
            s => panic!("unexpected status code: {}", s),
        }
    }
}

#[derive(Debug)]
pub struct PaymentResponseSuccessfullResponse {
    pub location: Url,
}
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RefundRequest {
    pub amount: PaymentAmount,
    pub payer_alias: String,
    pub original_payment_reference: String,
    pub currency: Currency,
    pub callback_url: CallbackUrl,
    pub payer_payment_reference: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug)]
pub struct RefundRequestParams {
    pub amount: PaymentAmount,
    pub original_payment_reference: String,
    pub currency: Currency,
    pub callback_url: CallbackUrl,
    pub payer_payment_reference: Option<String>,
    pub message: Option<String>,
}
#[derive(Debug)]
pub enum CreateRefundRequestError {
    // represents all kind of validation errors
    ValidationError(Vec<CreateRefundRequestErrorResponse>),
    InvalidSwishResponse(InvalidSwishResponse),
    HttpError(reqwest::Error),
    // the server does not think the cert is valid
    Unauthorized,
    // the number listed on the cert does not correspond with the number in the request
    CertMismatch,
    ServerError,
}
#[derive(Debug)]
pub enum RetriveRefundRequestError {
    HttpError(reqwest::Error),
    // the server does not think the cert is valid
    Unauthorized,
    NotFound,
    ServerError,
}
#[derive(Debug)]
pub enum InvalidSwishResponse {
    LocationNotValidUrl(ParseError),
    NotValidUtf8Response(ToStrError)
}

macro_rules! api_error {
    ($($name: ident => $description: expr,)+) => {
        /// All possible error codes from swish when dealing with refunds
        #[derive(PartialEq, Eq, Clone, Copy, Debug)]
        #[derive(Deserialize)]
        #[non_exhaustive]
        pub enum PaymentRefundErrorType {
                $(
                #[doc = $description]
                $name,
                )+
        }
        impl std::error::Error for PaymentRefundErrorType {}

        impl std::fmt::Display for PaymentRefundErrorType {
            fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match *self {
                    $(
                        PaymentRefundErrorType::$name => fmt.write_str($description),
                    )+
                }
            }
        }
    }
}

api_error! {
    FF08 => "PaymentReference is invalid.",
    RP03 => "Callback URL is missing or does not use HTTPS.",
    PA02 => "Amount value is missing or not a valid number.",
    AM03 => "Invalid or missing Currency.",
    AM04 => "Insufficient funds in account.",
    AM06 => "Specified transaction amount is less than agreed minimum.",
    RP01 => "Missing Merchant Swish Number.",
    RP02 => "Wrong formatted message.",
    ACMT07 => "Payee not Enrolled.",
    ACMT01 => "Counterpart is not activated.",
    RF02 => "Original Payment not found or original payment is more than 13 months old.",
    RF03 => "Payer alias in the refund does not match the payee alias in the original payment.",
    RF04 => "Payer organization number do not match original payment payee organization number.",
    RF06 => "The Payer SSN in the original payment is not the same as the SSN for the current Payee. Note: Typically, this means that the Mobile number has been transferred to another person.",
    RF07 => "Transaction declined.",
    RF08 => "Amount value is too large, or amount exceeds the amount of the original payment minus any previous refunds. Note: the remaining available amount is put into the additional information field.",
    RF09 => "Refund already in progress.",
    RP09 => "The given instructionUUID is not available Note: The instructionUUID already exist in the database, i.e. it is not unique.",
    FF10 => "Bank system processing error.",
    BE18 => "Payer alias is invalid.",
    BANKIDCL => "Payer cancelled BankId signing",
    DS24 => "Swish timed out waiting for an answer from the banks after payment was started. Note: If this happens Swish has no knowledge of whether the payment was successful or not. The Merchant should inform its consumer about this and recommend them to check with their bank about the status of this payment.",
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct CreateRefundRequestErrorResponse {
    pub error_code: PaymentRefundErrorType,
    pub additional_information: Option<String>,
}


/// The status of a [`RefundOrder`]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum RefundStatus {
    Created,
    Validated, /// refund ongoing
    Debited, /// Money has been withdrawn from your account
    Paid, /// The payment was sucessful
    Error,
}

/// A swish order. can be requested by [`Swish::fetch_payment_request`] for `polling` use cases
/// can also be used when deserializing callbacks from swish
#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RefundOrder {
    pub id: String,
    pub payer_payment_reference: String,
    pub original_payment_reference: String,
    pub payment_reference: Option<String>,
    pub callback_url: Url,
    pub payer_alias: String,
    pub amount: RefundPaymentAmount,
    pub currency: Currency,
    pub message: Option<String>,
    pub status: RefundStatus,
    #[serde(with = "time::serde::iso8601")]
    pub date_created: OffsetDateTime,
    #[serde(with = "time::serde::iso8601::option")]
    pub date_paid: Option<OffsetDateTime>,
    pub error_code: Option<PaymentRefundErrorType>,
    pub error_message: Option<String>,
    /// only applicable for errors
    pub additional_information: Option<String>,
}

/// A payment amount in the range 1..1000000000000
#[derive(Deserialize, Serialize, Debug, PartialEq, Clone, PartialOrd)]
#[serde(transparent)]
pub struct RefundPaymentAmount(f64);

impl RefundPaymentAmount {
    pub fn from(integer: u64, fraction: u8) -> Option<Self> {
        if fraction > 99 {
            return None;
        }
        if integer > 999999999999 {
            return None;
        }
        if integer == 0 {
            return None;
        }
        Some(Self(
            ((integer * 100 + fraction as u64) / 100) as f64,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_payment_reference};
    use crate::payment_requests::PaymentRequestMCommerceParams;
    use crate::test_util::tests::{load_cert_from_disk, load_certs};


    async fn get_client_for_test() -> Swish {
        Swish::build(
            "https://mss.cpc.getswish.net/swish-cpcapi",
            load_cert_from_disk().await,
            load_certs("Swish_TLS_RootCA.pem")
                .first()
                .expect("The provided root ca should have a cert"),
            "1234679304",
        )
    }
    async fn create_payment_to_be_refunded(swish : &Swish, payment_ref: &str) {
        swish
            .create_m_commerce_payment_request(
                &payment_ref,
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
    }

    #[tokio::test]
    async fn refund_request_can_be_issued() {
        let original_payment_ref = generate_payment_reference();
        let swish = get_client_for_test().await;
        // set up an order to be refunded
        create_payment_to_be_refunded(&swish, &original_payment_ref).await;

        let refund_uuid = generate_payment_reference();
        let res = swish.create_refund_request(&refund_uuid, RefundRequestParams {
            amount: PaymentAmount::from(100, 00).unwrap(),
            original_payment_reference: original_payment_ref,
            currency: Currency::Sek,
            callback_url: CallbackUrl::new("https://localhost/test".to_string()).unwrap(),
            payer_payment_reference: None,
            message: None,
        }).await.unwrap();

        assert!(res.location.has_host())
    }
    #[tokio::test]
    async fn refund_request_can_be_fetched() {
        let original_payment_ref = generate_payment_reference();
        let swish = get_client_for_test().await;
        // set up an order to be refunded
        create_payment_to_be_refunded(&swish, &original_payment_ref).await;


        let refund_uuid = generate_payment_reference();
        swish.create_refund_request(&refund_uuid, RefundRequestParams {
            amount: PaymentAmount::from(100, 00).unwrap(),
            original_payment_reference: original_payment_ref.clone(),
            currency: Currency::Sek,
            callback_url: CallbackUrl::new("https://localhost/test".to_string()).unwrap(),
            payer_payment_reference: None,
            message: None,
        }).await.unwrap();

        let res = swish.retrieve_refund(&refund_uuid).await.unwrap();
        assert_eq!(res.original_payment_reference, original_payment_ref);
        assert_eq!(res.id, refund_uuid);
        assert_eq!(res.payer_payment_reference, "");
        assert_eq!(res.payment_reference, None);
        assert_eq!(&res.amount, &RefundPaymentAmount::from(100, 00).unwrap());
        assert_eq!(res.status, RefundStatus::Created);
        assert_eq!(res.date_paid, None);
        assert_eq!(res.error_code, None);
        assert_eq!(res.error_message, None);
        assert_eq!(res.additional_information, None);
    }
    #[tokio::test]
    async fn refund_requests_gets_errors() {
        let original_payment_ref = generate_payment_reference();
        let swish = get_client_for_test().await;
        // set up an order to be refunded
        create_payment_to_be_refunded(&swish, &original_payment_ref).await;

        let refund_uuid = generate_payment_reference();
        let res = swish.create_refund_request(&refund_uuid, RefundRequestParams {
            amount: PaymentAmount::from(100, 00).unwrap(),
            original_payment_reference: original_payment_ref,
            currency: Currency::Sek,
            callback_url: CallbackUrl::new("https://localhost/test".to_string()).unwrap(),
            payer_payment_reference: None,
            message: Some("RF08".to_string()),
        }).await;

        let vec = vec!(CreateRefundRequestErrorResponse {
            error_code: PaymentRefundErrorType::RF08,
            additional_information: None
        });
        assert!(matches!(res, Err(CreateRefundRequestError::ValidationError(vec))));
    }
}
