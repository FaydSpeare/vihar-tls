use std::{net::TcpListener, thread::sleep, time::Duration};

use vihar_tls::{
    RenegotiationPolicy, UnrecognisedServerNamePolicy, ValidationPolicy, client::TlsConfigBuilder,
    server::TlsServer,
};

// Ctrl-i tab
// ctrl-e insert char found below
// ctrl-y inster char found above (but this is also accept, so it auto completes)
// ctrl-h delete char
// ctrl-w delete word
// ctrl-o 1 normal mode command, then back to insert
// ctrl-t tab current line
// ctrl-d untab current line
// ctrl-m insert new line
// ctrl-a insert last text
// ctrl-u delete to start of line
// ctrl-x ctrl-f file name completion
//
// norm command
// !!

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let listener = TcpListener::bind("localhost:4443")?;
    let (tcp_stream, _) = listener.accept()?;

    let mut server = TlsServer::new(
        TlsConfigBuilder::new()
            .with_session_ticket_store("server-sdb")
            .with_certificate_pem("testing/rsacert.pem", "testing/rsakey.pem")
            .with_validation_policy(ValidationPolicy {
                unrecognised_server_name: UnrecognisedServerNamePolicy::Ignore,
                renegotiation: RenegotiationPolicy::None,
            })
            .build(),
        tcp_stream,
    );

    server.serve()?;
    sleep(Duration::from_secs(10));
    Ok(())
}
