//! Name rules. A name is one flat string such as `alice.xyz`; the dot has no
//! meaning to the protocol and nobody owns an ending.

use crate::config::NameRules;
use crate::error::{Error, Result};

/// Lower-cases and validates a name against the network's rules.
///
/// Beyond the configured character set and length, a name must also be a
/// valid host name so browsers can send it to the resolver: no empty
/// dot-separated parts, no part longer than 63 characters, no part starting
/// or ending with `-`, and it must not look like an IP address.
pub fn normalize(name: &str, rules: &NameRules) -> Result<String> {
    let name = name.trim().to_ascii_lowercase();
    let len = name.chars().count() as u32;
    if len < rules.min_length || len > rules.max_length {
        return Err(Error::Name(format!(
            "length must be between {} and {} characters",
            rules.min_length, rules.max_length
        )));
    }
    if let Some(c) = name.chars().find(|c| !rules.allowed_chars.contains(*c)) {
        return Err(Error::Name(format!("character {c:?} is not allowed")));
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err(Error::Name(
                "name must not start or end with '.' or contain '..'".into(),
            ));
        }
        if label.len() > 63 {
            return Err(Error::Name(
                "each dot-separated part must be at most 63 characters".into(),
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(Error::Name("a part must not start or end with '-'".into()));
        }
    }
    if name.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(Error::Name("name must not look like an IP address".into()));
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        let r = NameRules::default();
        assert_eq!(normalize("Alice.XYZ", &r).unwrap(), "alice.xyz");
        assert_eq!(normalize("a", &r).unwrap(), "a");
        assert_eq!(
            normalize("my-site.anything.goes", &r).unwrap(),
            "my-site.anything.goes"
        );
        for bad in [
            "", ".a", "a.", "a..b", "-a", "a-.b", "a b", "a_b", "1.2.3.4", "ä",
        ] {
            assert!(normalize(bad, &r).is_err(), "{bad:?} should be rejected");
        }
    }
}
