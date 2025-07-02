use std::{
    io::{ErrorKind::{TimedOut, WouldBlock}, Read, Write},
    net::{TcpStream, UdpSocket}, time::{Duration, Instant},
};

#[allow(dead_code)]
#[derive(Debug)]
enum RData {
    A([u8; 4]),
    NS(String),
    AAAA([u8; 16]),
}

#[allow(dead_code)]
#[derive(Debug)]
struct ResourceRecord {
    name: String,
    rtype: u16,
    class: u16,
    ttl: u32,
    rdata: RData,
}

#[allow(dead_code)]
#[derive(Debug)]
struct Header {
    id: u16,
    qr: bool,
    opcode: u8,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    rcode: u8,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,
}

#[allow(dead_code)]
#[derive(Debug)]
struct Question {
    name: String,
    rtype: u16,
    class: u16,
}

#[allow(dead_code)]
#[derive(Debug)]
struct Message {
    header: Header,
    question: Question,
    answer: Vec<ResourceRecord>,
    authority: Vec<ResourceRecord>,
    additional: Vec<ResourceRecord>,
}

fn rdata_to_ipv4_string(rdata: &RData) -> String {
    if let RData::A(xs) = rdata {
        return format!("{}.{}.{}.{}", xs[0], xs[1], xs[2], xs[3]);
    }
    unreachable!();
}

impl Message {

    fn has_answer(&self) -> bool {
        self.header.an_count > 0
    }

    fn next_name_servers(&self) -> Vec<String> {
        self.authority.iter()
            .filter(|x| x.rtype == 2 || x.rtype == 5)
            .map(|x| {
                match &x.rdata {
                    RData::NS(domain) => domain.clone(),
                    _ => unreachable!()
                }
            })
            .collect::<Vec<String>>()
    }

    fn find_ns_ipv4_addr(&self, domain: &str) -> Option<String> {
        self.additional.iter()
            .find(|x| x.rtype == 1 && x.name == domain)
            .map(|x| rdata_to_ipv4_string(&x.rdata))
    }

    fn find_domain_in_additional(&self, domain: &str) -> Option<String> {
        self.additional.iter().find(|x| x.name == domain).map(|x| rdata_to_ipv4_string(&x.rdata))
    }
}

#[derive(Debug)]
pub enum ParseError {
    UnexpectedEOF,
    InvalidFormat,
    InvalidDomain,
}

fn name_to_bytes(name: &str) -> Vec<u8> {
    let mut qname = Vec::new();
    for label in name.split('.') {
        qname.push(label.len() as u8);
        qname.extend_from_slice(label.as_bytes());
    }
    qname.push(0);
    qname
}

fn create_query(domain: &str) -> Vec<u8> {
    let mut buf = [0u8; 12];
    buf[0..2].copy_from_slice(&42u16.to_be_bytes());
    buf[4..6].copy_from_slice(&1u16.to_be_bytes());

    let mut qname = name_to_bytes(domain);
    qname.extend_from_slice(&1u16.to_be_bytes());
    qname.extend_from_slice(&1u16.to_be_bytes());

    let mut combined = Vec::with_capacity(buf.len() + qname.len());
    combined.extend_from_slice(&buf);
    combined.extend_from_slice(&qname);
    return combined;
}

type DNSResult<T> = Result<T, Box<dyn std::error::Error>>;

fn parse_name(buf: &[u8], pos: usize) -> DNSResult<(String, usize)> {
    let mut labels = Vec::new();
    let mut idx = pos;
    while let Some(&len) = buf.get(idx) {
        if len == 192 {
            let ptr = buf[idx + 1] as usize;
            let (name, _) = parse_name(buf, ptr)?;
            labels.push(name);
            return Ok((labels.join("."), idx + 2));
        }
        if len == 0 {
            idx += 1;
            break;
        }
        idx += 1;
        let label = buf
            .get(idx..idx + len as usize)
            .ok_or("Unexpected end of buffer while parsing label")?;
        labels.push(std::str::from_utf8(label)?.to_string());
        idx += len as usize;
    }
    Ok((labels.join("."), idx))
}

fn parse_question(buf: &[u8], pos: usize) -> DNSResult<(Question, usize)> {
    let (name, pos) = parse_name(buf, pos)?;
    let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let class = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
    let question = Question { name, rtype, class };
    Ok((question, pos + 4))
}

fn parse_record(buf: &[u8], pos: usize) -> DNSResult<(ResourceRecord, usize)> {
    let (name, pos) = parse_name(buf, pos)?;
    let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let class = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
    let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
    let rdata_len: usize = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]).into();
    let rdata = match rtype {
        1 => RData::A([buf[pos + 10], buf[pos + 11], buf[pos + 12], buf[pos + 13]]),
        2 | 5 => {
            let (name, _) = parse_name(buf, pos + 10)?;
            RData::NS(name)
        }
        28 => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&buf[pos + 10..pos + 26]);
            RData::AAAA(addr)
        }
        _ => {
            println!("new rtype: {}", rtype);
            panic!();
        }
    };
    let record = ResourceRecord {
        name,
        rtype,
        class,
        ttl,
        rdata,
    };
    Ok((record, pos + 10 + rdata_len))
}

fn parse_header(buf: &[u8], pos: usize) -> DNSResult<(Header, usize)> {
    let id = u16::from_be_bytes(
        buf.get(pos..pos + 2)
            .ok_or("buffer too short for ID")?
            .try_into()
            .map_err(|_| "failed to parse header")?,
    );

    let qd_count = u16::from_be_bytes(
        buf.get(pos + 4..pos + 6)
            .ok_or("buffer too short for QD count")?
            .try_into()
            .map_err(|_| "failed to parse header")?,
    );
    assert!(qd_count == 1);

    let qd_count = u16::from_be_bytes(
        buf.get(pos + 4..pos + 6)
            .ok_or("buffer too short for QD count")?
            .try_into()
            .map_err(|_| "failed to parse header")?,
    );

    let an_count = u16::from_be_bytes(
        buf.get(pos + 6..pos + 8)
            .ok_or("buffer too short for AN count")?
            .try_into()
            .map_err(|_| "failed to parse header")?,
    );

    let ns_count = u16::from_be_bytes(
        buf.get(pos + 8..pos + 10)
            .ok_or("buffer too short for NS count")?
            .try_into()
            .map_err(|_| "failed to parse header")?,
    );

    let ar_count = u16::from_be_bytes(
        buf.get(pos + 10..pos + 12)
            .ok_or("buffer too short for AR count")?
            .try_into()
            .map_err(|_| "failed to parse header")?,
    );

    let header = Header {
        id,
        opcode: (buf[pos + 2] >> 3) & 0x0f,
        qr: buf[pos + 2] & 0x80 != 0,
        aa: buf[pos + 2] & 0x04 != 0,
        tc: buf[pos + 2] & 0x02 != 0,
        rd: buf[pos + 2] & 0x01 != 0,
        ra: buf[pos + 3] & 0x80 != 0,
        rcode: buf[pos + 3] & 0x0f,
        qd_count,
        an_count,
        ns_count,
        ar_count,
    };
    Ok((header, pos + 12))
}

fn parse_message(buf: &[u8]) -> DNSResult<Message> {
    let (header, mut pos) = parse_header(buf, 0)?;

    let (question, new_pos) = parse_question(buf, pos)?;
    pos = new_pos;

    let mut answer: Vec<ResourceRecord> = vec![];
    for _ in 0..header.an_count {
        let (record, new_pos) = parse_record(buf, pos)?;
        answer.push(record);
        pos = new_pos
    }

    let mut authority: Vec<ResourceRecord> = vec![];
    for _ in 0..header.ns_count {
        let (record, new_pos) = parse_record(buf, pos)?;
        authority.push(record);
        pos = new_pos
    }

    let mut additional: Vec<ResourceRecord> = vec![];
    for _ in 0..header.ar_count {
        let (record, new_pos) = parse_record(buf, pos)?;
        additional.push(record);
        pos = new_pos
    }

    let message = Message {
        header,
        question,
        answer,
        authority,
        additional,
    };
    Ok(message)
}


const DEFAULT_TIMEOUT: u64 = 2;

fn udp<'a>(addr: &str, query: &[u8], buf: &'a mut [u8]) -> DNSResult<(usize, &'a [u8])> {
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect(format!("{addr}:53")).expect("failed to connect");
    socket.set_read_timeout(Some(Duration::from_secs(DEFAULT_TIMEOUT))).unwrap();

    socket.send(query).expect("failed to send");
    match socket.recv(buf) {
        Ok(received) => Ok((received, &buf[..received])),
        Err(e) => {
            if e.kind() == WouldBlock || e.kind() == TimedOut {
                println!("Timed out waiting for response.");
            }
            Err(Box::new(e))
        }
    }
}

#[allow(dead_code)]
fn tcp<'a>(addr: &str, query: &[u8], buf: &'a mut [u8]) -> DNSResult<(usize, &'a [u8])> {
    let mut stream = TcpStream::connect(format!("{addr}:53")).expect("connect failed");
    stream.set_read_timeout(Some(Duration::from_secs(DEFAULT_TIMEOUT))).unwrap();

    let len = (query.len() as u16).to_be_bytes();
    stream.write_all(&len).expect("write length failed");
    stream.write(query).expect("write failed");

    match stream.read(buf) {
        Ok(received) => Ok((received, &buf[2..received])),
        Err(e) => {
            if e.kind() == WouldBlock || e.kind() == TimedOut {
                println!("Timed out waiting for response.");
            }
            Err(Box::new(e))
        }
    }
}


const ROOT_DNS: &str = "198.41.0.4";
// const ROOT_DNS: &str = "8.8.8.8";

fn resolve(dns_addr: &str, domain: &str) -> DNSResult<String> {

    println!("\nQuerying DNS({dns_addr}) for {domain}");
    let query: &[u8] = &create_query(domain);
    let mut buf = [0; 2048];
    let (_, bytes) = udp(dns_addr, query, &mut buf)?;
    let msg = parse_message(bytes)?;
    // println!("{:?}", msg);

    if msg.has_answer() {
        // TODO: sometimes the answer contains CNAME followed by multiple A for that CNAME, i.e
        // len(answer) == 3. E.G. renrenthehamster.wordpress.com
        let domain_addr = rdata_to_ipv4_string(&msg.answer[0].rdata);
        println!("DNS({dns_addr}) knows the domain address = {domain_addr}");
        return Ok(domain_addr);
    }

    // Check if the answer is in the additionals
    if let Some(addr) = msg.find_domain_in_additional(domain) {
        println!("Found domain address in additionals: {addr}");
        return Ok(addr)
    }

    println!("DNS({dns_addr}) doesn't know the location of {domain}");
    let next_nameservers = msg.next_name_servers();
    if next_nameservers.len() == 0 {
        println!("DNS({dns_addr}) didn't provide any other name servers");
        return Err("Failed to find next name server".into());
    }

    for (i, ns) in next_nameservers.iter().enumerate() {
        println!("DNS({dns_addr}) referred to {ns} [{i}]");
        match msg.find_ns_ipv4_addr(&ns) {
            Some(ns_addr) => {
                println!("DNS({dns_addr}) provided ipv4 address for {ns} = {ns_addr}");
                if let Ok(domain_addr) = resolve(&ns_addr, domain) {
                    return Ok(domain_addr)
                }
            },
            None => {
                println!("DNS({dns_addr}) didn't provide address for {ns}");
                if let Ok(ns_addr) = resolve_root(&ns) {
                    if let Ok(domain_addr) = resolve(&ns_addr, domain) {
                        return Ok(domain_addr)
                    }
                }
            }
        }
    };

    println!("exhausted nameservers provided by DNS_{dns_addr}");
    return Err("Failed to find next name server".into());
}

fn resolve_root(domain: &str) -> DNSResult<String> {
    Ok(resolve(ROOT_DNS, domain)?) 
}
// SOA-6 szte.etszk.hu


fn main() {
    let start = Instant::now();

    // resolve_root("renrenthehamster.wordpress.com").expect("resolve failed");
    resolve_root("youtube.com").expect("resolve failed");

    let duration = start.elapsed();
    println!("Elapsed: {:.2?}", duration);
}

