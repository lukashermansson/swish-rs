use reqwest::header::ToStrError;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
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
            StatusCode::UNAUTHORIZED => Err(CreateRefundRequestError::Unauthorized),
            StatusCode::FORBIDDEN => Err(CreateRefundRequestError::CertMismatch),
            StatusCode::INTERNAL_SERVER_ERROR => Err(CreateRefundRequestError::ServerError),
            StatusCode::UNPROCESSABLE_ENTITY => {
                let res = req
                    .json::<Vec<CreateRefundRequestErrorResponse>>()
                    .await
                    .map_err(CreateRefundRequestError::HttpError)?;
                Err(CreateRefundRequestError::ValidationError(
                    res.into_iter().map(|f| f.error_code).collect(),
                ))
            }
            s => panic!("unexpected status code: {}", s),
        }
    }
}

pub struct PaymentResponseSuccessfullResponse {
    pub location: Url,
}
#[derive(Serialize)]
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
    ValidationError(Vec<PaymentRefundError>),
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

macro_rules! api_error {
    ($($name: ident => $description: expr,)+) => {
        /// All possible error codes from swish when dealing with refunds
        #[derive(PartialEq, Eq, Clone, Copy, Debug)]
        #[non_exhaustive]
        pub enum PaymentRefundError {
                $(
                #[doc = $description]
                $name,
                )+
        }
        impl std::error::Error for PaymentRefundError {}

        impl std::fmt::Display for PaymentRefundError {
            fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match *self {
                    $(
                        ApiError::$name => fmt.write_str($description),
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
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
struct CreateRefundRequestErrorResponse {
    error_code: PaymentRefundError,
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

    #[tokio::test]
    async fn refund_request_can_be_issued() {
        let original_payment_ref = generate_payment_reference();
        let swish = get_client_for_test().await;
        // set up an order to be redunded
        swish
            .create_m_commerce_payment_request(
                &original_payment_ref,
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
}
