![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/lukashermansson/swish-rs/rust.yml)

# Swish-rs
Swish-rs is a library for interacting with the swish payment service in **Rust**

## Testing the callback

This includes a test of the callback on payment recived, it uses axum to provide that test, but its http-server agnostic in practice

it uses ngrock to provide that functionality. 

ngrock should normally require an api-key to be used, but it works without it at the moment. (unsure why)
if you want to run the tests and may need that key, you can set up your key at [ngrock](https://ngrok.com/)

and configure an env variable `NGROK_AUTHTOKEN="{token}"`

## Implementation status
The featureset of this library is not yet complete, once its fully featured I'm lookign to release this on [crates.io](https://crates.io/)

