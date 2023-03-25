extern crate mail_auth;

use mail_auth::dkim::{Dkim, DkimResult};
use mail_auth::mail_parser::{parse_mail, Mail};

fn main() -> std::io::Result<()> {
    let raw_email = std::fs::read_to_string("../../test_email/testemail.eml")?;

    let mail: Mail = parse_mail(&raw_email)?;

    let dkim_header = mail.get_header_value("DKIM-Signature")?;
    let dkim: DkimResult = Dkim::parse(dkim_header)?;

    let modulus = dkim.modulus.unwrap_or_default();
    let signature = dkim.signature.unwrap_or_default();

    let headers = mail.headers.to_string();
    let body = mail.body.to_string();

    println!("Modulus: {}", modulus);
    println!("Signature: {}", signature);
    println!("Headers: {}", headers);
    println!("Body: {}", body);

    Ok(())
}
