use std::{net::TcpListener, thread::sleep, time::Duration};

use vihar_tls::{client::TlsConfigBuilder, server::TlsServer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let listener = TcpListener::bind("localhost:4443")?;
    let (tcp_stream, _) = listener.accept()?;

    let mut server = TlsServer::new(
        TlsConfigBuilder::new()
            .with_session_ticket_store("server-sdb")
            .with_certificate_pem("testing/rsacert.pem", "testing/rsakey.pem")
            .build(),
        tcp_stream,
    );

    server.write(b"from server")?;
    sleep(Duration::from_secs(10));
    Ok(())
}
