use std::{net::TcpStream, thread::sleep, time::Duration};

use vihar_tls::client::{TlsClient, TlsConfig};

fn get_addr() -> String {
    let mut args = std::env::args();
    args.next(); // skip the binary name

    match args.next() {
        Some(arg) => arg,
        None => {
            eprintln!("Please provide one argument");
            std::process::exit(1);
        }
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let mut client = TlsClient::new(TlsConfig::default(), TcpStream::connect(get_addr())?);
    client.write(b"first data")?;

    sleep(Duration::from_secs(10));
    Ok(())
}
