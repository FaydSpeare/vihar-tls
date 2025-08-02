use std::{net::TcpStream, thread::sleep, time::Duration};

use vihar_tls::client::{TlsClient, TlsConfigBuilder};

fn get_addr_from_env() -> String {
    let mut args = std::env::args();
    args.next(); // skip the binary name

    match args.next() {
        Some(arg) => arg,
        None => {
            eprintln!("Please provide one argument [host:port]");
            std::process::exit(1);
        }
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let addr = get_addr_from_env();
    let tcp_stream = TcpStream::connect(addr)?;
    let mut client = TlsClient::new(
        TlsConfigBuilder::new()
            .with_session_ticket_store("sdb")
            .build(),
        tcp_stream,
    );

    client.write(b"first data")?;
    sleep(Duration::from_secs(10));
    Ok(())
}
