use std::{net::TcpListener, thread::sleep, time::Duration};

use vihar_tls::{client::TlsConfig, server::TlsServer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let listener = TcpListener::bind("localhost:4443")?;
    let (sock, _) = listener.accept()?;

    let mut server = TlsServer::new(TlsConfig::default(), sock);

    server.write(b"from server")?;
    sleep(Duration::from_secs(10));
    Ok(())
}
