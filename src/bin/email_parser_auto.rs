use futures::executor::block_on;
use mail_auth::common::verify::VerifySignature;
use mail_auth::{AuthenticatedMessage, DkimResult, Resolver};

// Use tokio async runtime to do network requests
#[tokio::main]
async fn main() -> std::io::Result<()> {
    let test_verify = test_dkim_verify_local_eml();
    block_on(test_verify);
    Ok(())
}

async fn test_dkim_verify_local_eml() {
    // Create a resolver using Cloudflare DNS
    let resolver = Resolver::new_cloudflare_tls().unwrap();

    // Parse message
    let raw_email = std::fs::read_to_string("./test_email/testemail.eml").unwrap();
    let authenticated_message = AuthenticatedMessage::parse(raw_email.as_bytes()).unwrap();

    // Validate signature
    let result = resolver.verify_dkim(&authenticated_message).await;
    assert!(result.iter().all(|s| s.result() == &DkimResult::Pass));

    let (parsed_headers, signed_parsed_headers) = authenticated_message.get_canonicalized_header().await.unwrap();
    println!("Result: {:?}", result[0]);

    let signature = result[0].signature().unwrap();
    println!("B: {:?}", std::str::from_utf8(signature.signature()));
    println!(
        "Parsed headers: {:?} {:?}",
        std::str::from_utf8(parsed_headers.as_slice()),
        std::str::from_utf8(signed_parsed_headers)
    );

    let body_bytes = &authenticated_message.raw_message[authenticated_message.body_offset..];

    // Print the array indexes authenticated_message.body_offset:end of the raw message
    println!(
        "A: {:?} {:?}",
        // std::str::from_utf8(&authenticated_message.raw_message).unwrap(),
        "Body offset: ",
        std::str::from_utf8(&authenticated_message.raw_message[authenticated_message.body_offset..]).unwrap()
    );
    // Make sure all signatures passed verification
}
