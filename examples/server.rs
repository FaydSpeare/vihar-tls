use std::{net::TcpListener, thread::sleep, time::Duration};

use vihar_tls::{
    ClientAuthPolicy, ClientCertificateType, TlsPolicy,
    client::Certificates,
    server::{TlsServer, TlsServerConfigBuilder},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let config = TlsServerConfigBuilder::new("localhost")
        .with_session_store("server-sdb")
        .with_certificates(
            Certificates::new()
                .with_rsa("testing/rsacert.pem", "testing/rsakey.pem")
                .with_dsa("testing/dsacert.pem", "testing/dsakey.pem")
                .with_dh("dh/dhcert.pem", "dh/dhkey.pem"),
        )
        .with_policy(TlsPolicy {
            client_auth: ClientAuthPolicy::Auth {
                certificate_types: vec![ClientCertificateType::RsaFixedDh],
                distinguished_names: vec![],
                mandatory: true,
            },
            ..Default::default()
        })
        .build();

    let listener = TcpListener::bind("localhost:4443")?;
    let (stream, _) = listener.accept()?;
    let mut server = TlsServer::new(config, stream);

    server.serve()?;
    sleep(Duration::from_secs(10));
    Ok(())
}
