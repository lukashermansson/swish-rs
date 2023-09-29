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
#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum PaymentRefundError {

    /// PaymentReference is invalid.
    FF08,
    /// Callback URL is missing or does not use HTTPS.
    RP03,
    /// Amount value is missing or not a valid number.
    PA02,
    /// Invalid or missing Currency.
    AM03,
    /// Insufficient funds in account.
    AM04,
    /// Specified transaction amount is less than agreed minimum.
    AM06,
    /// Missing Merchant Swish Number.
    RP01,
    /// Wrong formatted message.
    RP02,
    /// Payee not Enrolled.
    ACMT07,
    /// Counterpart is not activated.
    ACMT01,
    /// Original Payment not found or original payment is more than 13 months old.
    RF02,
    /// Payer alias in the refund does not match the payee alias in the original payment.
    RF03,
    /// Payer organization number do not match original payment payee organization number.
    RF04,
    /// The Payer SSN in the original payment is not the same as the SSN for the current Payee. Note: Typically, this means that the Mobile number has been transferred to another person.
    RF06,
    /// Transaction declined.
    RF07,
    /// Amount value is too large, or amount exceeds the amount of the original payment minus any previous refunds. Note: the remaining available amount is put into the additional information field.
    RF08,
    /// Refund already in progress.
    RF09,
    /// The given instructionUUID is not available Note: The instructionUUID already exist in the database, i.e. it is not unique.
    RP09,
    /// Bank system processing error.
    FF10,
    /// Payer alias is invalid.
    BE18,
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
