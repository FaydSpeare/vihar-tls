use std::net::TcpStream;

use vihar_tls::{
    ciphersuite::CipherSuiteId,
    client::{Certificates, TlsClient, TlsClientConfigBuilder},
};

fn parse_host_port() -> (String, String) {
    let mut args = std::env::args().skip(1);
    let host = args.next().unwrap();
    let port = args.next().unwrap();
    (host, port)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let (host, port) = parse_host_port();
    let stream = TcpStream::connect(format!("{host}:{port}"))?;

    let config = TlsClientConfigBuilder::new(host)
        .with_cipher_suites([CipherSuiteId::DhRsaWithAes128CbcSha].into())
        .with_certificates(
            Certificates::new()
                .with_rsa("testing/rsacert.pem", "testing/rsakey.pem")
                .with_dsa("testing/dsacert.pem", "testing/dsakey.pem")
                .with_dh("dh/dhcert.pem", "dh/dhkey.pem"),
        )
        .build();

    let mut client = TlsClient::new(config, stream);

    client.write(b"1st data")?;
    Ok(())
}
