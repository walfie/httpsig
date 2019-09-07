use std::error::Error;

use openssl::hash::MessageDigest;
use openssl::pkey::HasPrivate;
use openssl::pkey::PKey;
use openssl::pkey::PKeyRef;
use openssl::rsa::Rsa;
use openssl::sign::Signer;

fn main() -> Result<(), Box<dyn Error>> {
    let input = br#"POST /foo?param=value&pet=dog HTTP/1.1
Host: example.com
Date: Sun, 05 Jan 2014 21:31:40 GMT
Content-Type: application/json
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
Content-Length: 18

{"hello": "world"}"#;

    let request = parse_request(input);

    // Generate a keypair
    let keypair = Rsa::generate(2048).unwrap();
    let keypair = PKey::from_rsa(keypair).unwrap();

    let signature = compute_signature(&request, MessageDigest::sha256(), &keypair)?;
    dbg!(base64::encode(&signature));

    Ok(())
}

fn compute_signature<T>(
    request: &http::Request<T>,
    digest: MessageDigest,
    private_key: &PKeyRef<impl HasPrivate>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut signer = Signer::new(digest, private_key)?;

    let mut payload_to_sign: Vec<u8> = Vec::new();
    create_payload_to_sign(&request, &mut payload_to_sign)?;

    signer.update(&payload_to_sign)?;
    Ok(signer.sign_to_vec()?)
}

fn create_payload_to_sign<T>(
    req: &http::Request<T>,
    output: &mut impl std::io::Write,
) -> Result<(), Box<dyn Error>> {
    write!(
        output,
        "(request-target): {} {}",
        req.method().as_str().to_ascii_lowercase(),
        req.uri()
    )?;

    for (header_name, header_value) in req.headers() {
        // HeaderName's `as_str` is guaranteed to be lowercase
        write!(
            output,
            "\n{}: {}",
            header_name.as_str(),
            header_value.to_str()?
        )?;
    }

    Ok(())
}

// Not returning a `Result` here because it's not part of the library
fn parse_request<'a>(buf: &'a [u8]) -> http::Request<&'a [u8]> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let bytes_parsed = req.parse(buf).expect("failed to parse request").unwrap() as usize;

    let version = match req.version.expect("no version") {
        0 => http::version::Version::HTTP_10,
        1 => http::version::Version::HTTP_11,
        other => panic!(format!("unexpected HTTP version {}", other)),
    };

    let mut builder = http::Request::builder();
    builder
        .method(req.method.expect("no method"))
        .uri(req.path.expect("no path"))
        .version(version);

    for header in req.headers {
        builder.header(header.name, header.value);
    }

    builder
        .body(&buf[bytes_parsed..])
        .expect("failed to create HTTP request")
}
