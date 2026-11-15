//! Format rules for usernames, email addresses and display names.

use super::error::LocalError;

const MIN_USERNAME_CHARS: usize = 3;
const MAX_USERNAME_CHARS: usize = 32;
/// Longest address that fits in an SMTP path (RFC 5321).
pub(crate) const MAX_EMAIL_CHARS: usize = 254;
const MAX_NAME_CHARS: usize = 255;

/// Trim and check a username: 3 to 32 ASCII letters, digits, `.`, `_` or `-`, starting
/// with a letter or digit.
///
/// `@` is not allowed, which is what lets a login identifier be told apart from an email
/// address.
pub(crate) fn username(input: &str) -> Result<&str, LocalError> {
    let username = input.trim();
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    let valid = (MIN_USERNAME_CHARS..=MAX_USERNAME_CHARS).contains(&username.len())
        && username.chars().all(allowed)
        && username.starts_with(|c: char| c.is_ascii_alphanumeric());
    if valid {
        Ok(username)
    } else {
        Err(LocalError::InvalidUsername)
    }
}

/// Trim and check an email address.
///
/// This is a shape check only (`local@domain` with a dot-separated domain and no spaces
/// or control characters). Whether the address works is established by the verification
/// email.
pub(crate) fn email(input: &str) -> Result<&str, LocalError> {
    let email = input.trim();
    let shape_ok = || {
        let (local, domain) = email.rsplit_once('@')?;
        let ok = !local.is_empty()
            && local.len() <= 64
            && !local.contains('@')
            && domain.contains('.')
            && domain.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
            });
        ok.then_some(())
    };
    let valid = email.len() <= MAX_EMAIL_CHARS
        && !email.chars().any(|c| c.is_whitespace() || c.is_control())
        && shape_ok().is_some();
    if valid {
        Ok(email)
    } else {
        Err(LocalError::InvalidEmail)
    }
}

/// Trim and check a display name: 1 to 255 characters, no control characters.
pub(crate) fn name(input: &str) -> Result<&str, LocalError> {
    let name = input.trim();
    let valid = !name.is_empty()
        && name.chars().count() <= MAX_NAME_CHARS
        && !name.chars().any(char::is_control);
    if valid {
        Ok(name)
    } else {
        Err(LocalError::InvalidName)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames() {
        for ok in [
            "budi",
            "Budi.Santoso",
            "a_b-c",
            "abc",
            &"a".repeat(32),
            "9lives",
        ] {
            assert_eq!(username(ok).unwrap(), ok);
        }
        assert_eq!(username("  budi  ").unwrap(), "budi");
        for bad in [
            "",
            "ab",
            &"a".repeat(33),
            "budi santoso",
            "budi@example.com",
            ".budi",
            "-budi",
            "büdi",
            "bu\ndi",
        ] {
            assert!(
                matches!(username(bad), Err(LocalError::InvalidUsername)),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn emails() {
        for ok in [
            "budi@example.com",
            "Budi.Santoso+tag@mail.example.co.id",
            "o'brien@example.com",
        ] {
            assert_eq!(email(ok).unwrap(), ok);
        }
        assert_eq!(email(" budi@example.com ").unwrap(), "budi@example.com");
        let too_long = format!("{}@example.com", "a".repeat(250));
        for bad in [
            "",
            "budi",
            "@example.com",
            "budi@",
            "budi@localhost",
            "budi@example..com",
            "budi@-example.com",
            "bu di@example.com",
            "budi@exam\tple.com",
            "a@b@example.com",
            too_long.as_str(),
        ] {
            assert!(
                matches!(email(bad), Err(LocalError::InvalidEmail)),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn names() {
        assert_eq!(name("  Budi Santoso ").unwrap(), "Budi Santoso");
        assert!(matches!(name(""), Err(LocalError::InvalidName)));
        assert!(matches!(name("   "), Err(LocalError::InvalidName)));
        assert!(name(&"é".repeat(255)).is_ok());
        assert!(matches!(
            name(&"a".repeat(256)),
            Err(LocalError::InvalidName)
        ));
        assert!(matches!(name("Budi\u{0}"), Err(LocalError::InvalidName)));
    }
}
