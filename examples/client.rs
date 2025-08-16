use std::{net::TcpStream, thread::sleep, time::Duration};

use vihar_tls::{
    ciphersuite::CipherSuiteId, client::{Certificates, TlsClient, TlsConfigBuilder}, pcs, MaxFragmentLength
};

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
            .with_max_fragment_length(MaxFragmentLength::Len1024)
            .with_cipher_suites([pcs!(2, CipherSuiteId::RsaAes128CbcSha)].into())
            .with_certificates(
                Certificates::new()
                    .with_rsa("testing/rsacert.pem", "testing/rsakey.pem")
                    .with_dsa("testing/dsacert.pem", "testing/dsakey.pem"),
            )
            //.with_server_name("google.com")
            .with_session_store("sdb")
            .build(),
        tcp_stream,
    );

    client.write(b"1st data")?;
    sleep(Duration::from_secs(2));
    // client.renegotiate()?;
    // sleep(Duration::from_secs(10));
    Ok(())
}
