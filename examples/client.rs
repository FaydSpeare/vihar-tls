use std::{net::TcpStream, thread::sleep, time::Duration};

use vihar_tls::{
    ciphersuite::CipherSuiteId,
    client::{Certificates, TlsClient, TlsConfigBuilder},
    pcs,
};

fn parse_host_port() -> (String, String) {
    let mut args = std::env::args().skip(1); // skip program name
    let host = args.next().unwrap(); // first arg
    let port = args.next().unwrap(); // second arg
    (host, port)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let (host, port) = parse_host_port();
    let tcp_stream = TcpStream::connect(format!("{host}:{port}"))?;
    let mut client = TlsClient::new(
        TlsConfigBuilder::new()
            //.with_max_fragment_length(MaxFragmentLength::Len1024)
            .with_cipher_suites([pcs!(2, CipherSuiteId::RsaWithNullMd5)].into())
            .with_certificates(
                Certificates::new()
                    .with_rsa("testing/rsacert.pem", "testing/rsakey.pem")
                    .with_dsa("testing/dsacert.pem", "testing/dsakey.pem"),
            )
            .with_server_name(&host)
            //.with_session_store("sdb")
            .build(),
        tcp_stream,
    );

    client.write(b"1st data")?;
    sleep(Duration::from_secs(2));
    // client.renegotiate()?;
    // sleep(Duration::from_secs(10));
    Ok(())
}
