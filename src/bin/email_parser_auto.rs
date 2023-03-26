// extern crate mail_auth;
use futures::executor::block_on;
use mail_auth::{AuthenticatedMessage, DkimResult, Resolver};

// Use tokio async runtime to do network requests
#[tokio::main]
async fn main() -> std::io::Result<()> {
    let test_verify = test_dkim_verify();
    block_on(test_verify);
    Ok(())
}

async fn test_dkim_verify() {
    // Create a resolver using Cloudflare DNS
    let resolver = Resolver::new_cloudflare_tls().unwrap();

    // Parse message
    let raw_email = std::fs::read_to_string("./test_email/testemail.eml").unwrap();
    let authenticated_message = AuthenticatedMessage::parse(raw_email.as_bytes()).unwrap();
    println!("authenticated_message: {:?}\n", authenticated_message);
    println!("authenticated_message headers: {:?}\n", authenticated_message.headers);
    println!("authenticated_message dkim_headers: {:?}\n", authenticated_message.dkim_headers);
    println!("authenticated_message raw_message: {:?}\n", std::str::from_utf8(authenticated_message.raw_message));
    authenticated_message.dkim_headers.iter().for_each(|dkim_header| {
        println!("dkim_header: {:?}", dkim_header);
        println!("dkim_header name: {:?}", std::str::from_utf8(dkim_header.name));
        println!("dkim_header value: {:?}\n", std::str::from_utf8(dkim_header.value));
    });
    authenticated_message.headers.iter().for_each(|dkim_header| {
        println!("dkim_header raw: {:?}", dkim_header);
        println!("dkim_header name: {:?}", std::str::from_utf8(dkim_header.0));
        println!("dkim_header value: {:?}\n", std::str::from_utf8(dkim_header.1));
        // println!("dkim_header name: {:?}", std::str::from_utf8(dkim_header.name));
        // println!("dkim_header value: {:?}\n", std::str::from_utf8(dkim_header.value));
    });
    // Validate signature
    let result = resolver.verify_dkim(&authenticated_message).await;
    assert!(result.iter().all(|s| s.result() == &DkimResult::Pass));

    let parsedHeaders = authenticated_message.get_canonicalized_header().await.unwrap();
    println!("Result: {:?}", result);
    println!("Parsed headers: {:?}", std::str::from_utf8(parsedHeaders));

    // Make sure all signatures passed verification
}
