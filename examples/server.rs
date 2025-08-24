use std::{net::TcpListener, thread::sleep, time::Duration};

use vihar_tls::{
    ClientAuthPolicy, MaxFragmentLengthNegotiationPolicy, RenegotiationPolicy, TlsPolicy,
    UnrecognisedServerNamePolicy,
    ciphersuite::CipherSuiteId,
    client::{Certificates, TlsConfigBuilder},
    pcs,
    server::TlsServer,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let config = TlsConfigBuilder::new()
        .with_cipher_suites(
            CipherSuiteId::all()
                .iter()
                .map(|id| pcs!(1, *id))
                .collect::<Vec<_>>()
                .into(),
        )
        .with_session_store("server-sdb")
        .with_certificates(
            Certificates::new()
                .with_rsa("testing/rsacert.pem", "testing/rsakey.pem")
                .with_dsa("testing/dsacert.pem", "testing/dsakey.pem")
                .with_dh("dh/dhcert.pem", "dh/dhkey.pem"),
        )
        .with_policy(TlsPolicy {
            unrecognised_server_name: UnrecognisedServerNamePolicy::Ignore,
            renegotiation: RenegotiationPolicy::None,
            max_fragment_length_negotiation: MaxFragmentLengthNegotiationPolicy::Reject,
            client_auth: ClientAuthPolicy::NoAuth,
            verify_server: false,
        })
        .build();

    let listener = TcpListener::bind("localhost:4443")?;
    let (tcp_stream, _) = listener.accept()?;
    let mut server = TlsServer::new(config, tcp_stream);

    server.serve()?;
    sleep(Duration::from_secs(10));
    Ok(())
}
