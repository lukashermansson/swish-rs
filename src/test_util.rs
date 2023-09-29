#[cfg(any(test, doctest))]
pub mod tests {
    use rustls::{Certificate, PrivateKey};
    use crate::SwishCertificate;

    pub fn load_certs(filename: &str) -> Vec<Certificate> {
        let certfile = std::fs::File::open(filename).expect("cannot open certificate file");
        let mut reader = std::io::BufReader::new(certfile);
        rustls_pemfile::certs(&mut reader)
            .unwrap()
            .iter()
            .map(|v| Certificate(v.clone()))
            .collect()
    }

    pub fn load_private_key(filename: &str) -> PrivateKey {
        let keyfile = std::fs::File::open(filename).expect("cannot open private key file");
        let mut reader = std::io::BufReader::new(keyfile);

        loop {
            match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file")
            {
                Some(rustls_pemfile::Item::RSAKey(key)) => return PrivateKey(key),
                Some(rustls_pemfile::Item::PKCS8Key(key)) => return PrivateKey(key),
                Some(rustls_pemfile::Item::ECKey(key)) => return PrivateKey(key),
                None => break,
                _ => {}
            }
        }

        panic!(
            "no keys found in {:?} (encrypted keys not supported)",
            filename
        );
    }

    pub async fn load_cert_from_disk() -> SwishCertificate {
        SwishCertificate::from_der(
            load_private_key("Swish_Merchant_TestCertificate_1234679304.key"),
            load_certs("Swish_Merchant_TestCertificate_1234679304.pem"),
        )
    }
    pub fn load_server_ca() -> Certificate  {
        return load_certs("Swish_TLS_RootCA.pem").into_iter().next().expect("The provided root ca should have a cert");
    }
}
