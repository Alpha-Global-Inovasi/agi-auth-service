//! TOTP codes (RFC 6238 on top of the HOTP algorithm of RFC 4226).

use hmac::Hmac;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

/// Hash function for the HMAC in TOTP codes.
///
/// Authenticator apps generally support only [`Sha1`](Self::Sha1), and many silently
/// ignore the algorithm in the setup URI, so use another one only when every client is
/// known to support it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum TotpAlgorithm {
    /// HMAC-SHA-1, the RFC 6238 default and what authenticator apps expect.
    #[default]
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl TotpAlgorithm {
    /// The name used in `otpauth://` URIs: `SHA1`, `SHA256` or `SHA512`.
    pub fn uri_name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

/// Smallest TOTP secret, in bytes (128 bits, the minimum of RFC 4226).
pub const MIN_TOTP_SECRET_BYTES: usize = 16;
/// Largest TOTP secret, in bytes.
pub const MAX_TOTP_SECRET_BYTES: usize = 64;
/// Most time steps accepted on either side of the current one.
pub const MAX_TOTP_SKEW_STEPS: u32 = 10;

/// How TOTP codes are made and checked.
///
/// | | Default |
/// |---|---|
/// | Algorithm | HMAC-SHA-1 |
/// | Digits | 6 |
/// | Period | 30 seconds |
/// | Accepted clock difference | 1 step either way (±30 seconds) |
/// | Secret | 20 bytes (160 bits) |
///
/// These are the values authenticator apps assume. Keep the algorithm, digits and period
/// fixed once users have enrolled: stored records do not remember them, so changing one
/// breaks every authenticator set up before. The window and the length of new secrets
/// can be changed at any time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct TotpConfig {
    /// HMAC hash function.
    pub algorithm: TotpAlgorithm,
    /// Digits per code, 6 to 8.
    pub digits: u32,
    /// Length of a time step.
    pub period: Duration,
    /// Steps accepted before and after the current one, to allow for clock differences
    /// and for the time it takes to type a code. At most [`MAX_TOTP_SKEW_STEPS`].
    pub skew_steps: u32,
    /// Length of new secrets in bytes, from [`MIN_TOTP_SECRET_BYTES`] to
    /// [`MAX_TOTP_SECRET_BYTES`].
    pub secret_bytes: usize,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: Duration::from_secs(30),
            skew_steps: 1,
            secret_bytes: 20,
        }
    }
}

impl TotpConfig {
    /// Set [`algorithm`](Self::algorithm).
    pub fn algorithm(mut self, algorithm: TotpAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Set [`digits`](Self::digits).
    pub fn digits(mut self, digits: u32) -> Self {
        self.digits = digits;
        self
    }

    /// Set [`period`](Self::period).
    pub fn period(mut self, period: Duration) -> Self {
        self.period = period;
        self
    }

    /// Set [`skew_steps`](Self::skew_steps).
    pub fn skew_steps(mut self, steps: u32) -> Self {
        self.skew_steps = steps;
        self
    }

    /// Set [`secret_bytes`](Self::secret_bytes).
    pub fn secret_bytes(mut self, bytes: usize) -> Self {
        self.secret_bytes = bytes;
        self
    }

    /// `Err` with a description when a value is out of range.
    pub(crate) fn check(&self) -> Result<(), String> {
        if !(6..=8).contains(&self.digits) {
            return Err(format!("TOTP digits must be 6 to 8, not {}", self.digits));
        }
        if self.period.as_secs() == 0 || self.period.subsec_nanos() != 0 {
            return Err("TOTP period must be a whole number of seconds, at least 1".into());
        }
        if self.skew_steps > MAX_TOTP_SKEW_STEPS {
            return Err(format!(
                "TOTP skew must be at most {MAX_TOTP_SKEW_STEPS} steps, not {}",
                self.skew_steps
            ));
        }
        if !(MIN_TOTP_SECRET_BYTES..=MAX_TOTP_SECRET_BYTES).contains(&self.secret_bytes) {
            return Err(format!(
                "TOTP secrets must be {MIN_TOTP_SECRET_BYTES} to {MAX_TOTP_SECRET_BYTES} bytes, not {}",
                self.secret_bytes
            ));
        }
        Ok(())
    }

    /// The time step that contains `at`. Times before 1970 count as step 0.
    pub(crate) fn step_at(&self, at: SystemTime) -> u64 {
        let seconds = at.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        seconds / self.period.as_secs().max(1)
    }

    /// The code for `step`, as ASCII digits with leading zeros.
    pub(crate) fn code(&self, secret: &[u8], step: u64) -> Zeroizing<String> {
        let truncated = match self.algorithm {
            TotpAlgorithm::Sha1 => hotp::<Hmac<sha1::Sha1>>(secret, step),
            TotpAlgorithm::Sha256 => hotp::<Hmac<sha2::Sha256>>(secret, step),
            TotpAlgorithm::Sha512 => hotp::<Hmac<sha2::Sha512>>(secret, step),
        };
        let modulus = 10u32.pow(self.digits);
        Zeroizing::new(format!(
            "{:0width$}",
            truncated % modulus,
            width = self.digits as usize
        ))
    }

    /// `true` when `input` has the shape of a code: exactly [`digits`](Self::digits)
    /// ASCII digits. Spaces are ignored.
    pub(crate) fn looks_like_code(&self, input: &str) -> bool {
        let mut count = 0usize;
        for c in input.chars().filter(|c| *c != ' ') {
            if !c.is_ascii_digit() {
                return false;
            }
            count += 1;
        }
        count == self.digits as usize
    }

    /// Check `input` against the steps around `now`.
    ///
    /// Every step in the window is computed and compared in constant time, whatever
    /// matches, so the time taken does not depend on the code. Returns the newest
    /// matching step after `last_used_step`, or tells that the code matched only steps
    /// that were already used.
    pub(crate) fn verify(
        &self,
        secret: &[u8],
        input: &str,
        now: SystemTime,
        last_used_step: Option<u64>,
    ) -> TotpCheck {
        if !self.looks_like_code(input) {
            return TotpCheck::Invalid;
        }
        let input: Zeroizing<Vec<u8>> =
            Zeroizing::new(input.bytes().filter(|b| *b != b' ').collect());
        let current = self.step_at(now);
        let skew = u64::from(self.skew_steps);
        let first = current.saturating_sub(skew);
        let last = current.saturating_add(skew);

        let mut fresh: Option<u64> = None;
        let mut replayed = false;
        for step in first..=last {
            let code = self.code(secret, step);
            let matches: bool = code.as_bytes().ct_eq(&input).into();
            if matches {
                if last_used_step.is_some_and(|used| step <= used) {
                    replayed = true;
                } else {
                    fresh = Some(step);
                }
            }
        }
        match fresh {
            Some(step) => TotpCheck::Valid { step },
            None if replayed => TotpCheck::Reused,
            None => TotpCheck::Invalid,
        }
    }
}

/// Result of [`TotpConfig::verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TotpCheck {
    /// The code matches `step`, which is newer than any step used before.
    Valid { step: u64 },
    /// The code matches only steps that were already used.
    Reused,
    /// The code matches no step in the window, or is malformed.
    Invalid,
}

/// HOTP (RFC 4226 section 5.3): HMAC of the big-endian counter, dynamically truncated
/// to 31 bits.
fn hotp<M: hmac::Mac + hmac::KeyInit>(secret: &[u8], counter: u64) -> u32 {
    // HMAC accepts keys of any length.
    let mut mac = <M as hmac::KeyInit>::new_from_slice(secret)
        .unwrap_or_else(|_| unreachable!("HMAC takes keys of any length"));
    mac.update(&counter.to_be_bytes());
    let digest = Zeroizing::new(mac.finalize().into_bytes().to_vec());
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ])
}

/// RFC 4648 base32 alphabet, upper case, as authenticator apps expect it.
const BASE32_UPPER: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Base32 without padding (RFC 4648 section 6) in the given alphabet.
pub(crate) fn base32(bytes: &[u8], alphabet: &[u8; 32]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len().div_ceil(5) * 8));
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(alphabet[((buffer >> bits) & 0x1f) as usize]));
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(
            alphabet[((buffer << (5 - bits)) & 0x1f) as usize],
        ));
    }
    out
}

/// The `otpauth://totp/` URI that authenticator apps read, usually from a QR code.
pub(crate) fn otpauth_uri(
    config: &TotpConfig,
    secret: &[u8],
    issuer: Option<&str>,
    account_name: &str,
) -> Zeroizing<String> {
    let secret = base32(secret, BASE32_UPPER);
    let mut uri = Zeroizing::new(String::with_capacity(128));
    uri.push_str("otpauth://totp/");
    if let Some(issuer) = issuer {
        percent_encode(issuer, &mut uri);
        uri.push(':');
    }
    percent_encode(account_name, &mut uri);
    uri.push_str("?secret=");
    uri.push_str(&secret);
    if let Some(issuer) = issuer {
        uri.push_str("&issuer=");
        percent_encode(issuer, &mut uri);
    }
    uri.push_str("&algorithm=");
    uri.push_str(config.algorithm.uri_name());
    uri.push_str(&format!(
        "&digits={}&period={}",
        config.digits,
        config.period.as_secs()
    ));
    uri
}

/// Percent-encode everything but the RFC 3986 unreserved characters.
fn percent_encode(text: &str, out: &mut String) {
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
}

/// A new TOTP secret, shown once during setup.
///
/// The `Debug` output never contains it, and the memory is wiped when the value is
/// dropped.
pub(crate) struct Secret(pub(crate) Zeroizing<Vec<u8>>);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Secret {
    pub(crate) fn generate(bytes: usize) -> Result<Self, getrandom::Error> {
        let mut secret = Zeroizing::new(vec![0u8; bytes]);
        getrandom::fill(&mut secret)?;
        Ok(Self(secret))
    }

    pub(crate) fn base32(&self) -> Zeroizing<String> {
        base32(&self.0, BASE32_UPPER)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    /// RFC 6238 appendix B: the test seeds are the ASCII digits "1234567890" repeated
    /// to the hash's output length, and the codes have 8 digits.
    #[test]
    fn rfc_6238_test_vectors() {
        let seeds = [
            (TotpAlgorithm::Sha1, b"12345678901234567890".to_vec()),
            (
                TotpAlgorithm::Sha256,
                b"12345678901234567890123456789012".to_vec(),
            ),
            (
                TotpAlgorithm::Sha512,
                b"1234567890123456789012345678901234567890123456789012345678901234".to_vec(),
            ),
        ];
        let vectors: [(u64, [&str; 3]); 6] = [
            (59, ["94287082", "46119246", "90693936"]),
            (1_111_111_109, ["07081804", "68084774", "25091201"]),
            (1_111_111_111, ["14050471", "67062674", "99943326"]),
            (1_234_567_890, ["89005924", "91819424", "93441116"]),
            (2_000_000_000, ["69279037", "90698825", "38618901"]),
            (20_000_000_000, ["65353130", "77737706", "47863826"]),
        ];
        for (time, codes) in vectors {
            for ((algorithm, seed), expected) in seeds.iter().zip(codes) {
                let config = TotpConfig::default().algorithm(*algorithm).digits(8);
                let step = config.step_at(at(time));
                assert_eq!(
                    config.code(seed, step).as_str(),
                    expected,
                    "{algorithm:?} at {time}"
                );
                assert_eq!(
                    config.verify(seed, expected, at(time), None),
                    TotpCheck::Valid { step }
                );
            }
        }
    }

    #[test]
    fn rfc_4226_hotp_vectors_with_six_digits() {
        // RFC 4226 appendix D.
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        let config = TotpConfig::default();
        for (counter, code) in expected.iter().enumerate() {
            assert_eq!(
                config
                    .code(b"12345678901234567890", counter as u64)
                    .as_str(),
                *code
            );
        }
    }

    #[test]
    fn window_accepts_one_step_either_way_by_default() {
        let config = TotpConfig::default();
        let secret = b"12345678901234567890";
        let now = at(1_700_000_015);
        let step = config.step_at(now);
        for (offset, accepted) in [(-2i64, false), (-1, true), (0, true), (1, true), (2, false)] {
            let candidate = step.checked_add_signed(offset).unwrap();
            let code = config.code(secret, candidate);
            let result = config.verify(secret, &code, now, None);
            if accepted {
                assert_eq!(result, TotpCheck::Valid { step: candidate }, "{offset}");
            } else {
                assert_eq!(result, TotpCheck::Invalid, "{offset}");
            }
        }

        let wide = config.skew_steps(2);
        let code = config.code(secret, step - 2);
        assert_eq!(
            wide.verify(secret, &code, now, None),
            TotpCheck::Valid { step: step - 2 }
        );
        let narrow = config.skew_steps(0);
        let code = config.code(secret, step - 1);
        assert_eq!(narrow.verify(secret, &code, now, None), TotpCheck::Invalid);
    }

    #[test]
    fn used_and_older_steps_are_refused() {
        let config = TotpConfig::default();
        let secret = b"12345678901234567890";
        let now = at(1_700_000_015);
        let step = config.step_at(now);
        let code = config.code(secret, step);

        assert_eq!(
            config.verify(secret, &code, now, Some(step - 1)),
            TotpCheck::Valid { step }
        );
        assert_eq!(
            config.verify(secret, &code, now, Some(step)),
            TotpCheck::Reused
        );
        let older = config.code(secret, step - 1);
        assert_eq!(
            config.verify(secret, &older, now, Some(step)),
            TotpCheck::Reused
        );
        // A newer step is still accepted after an older one was used.
        let newer = config.code(secret, step + 1);
        assert_eq!(
            config.verify(secret, &newer, now, Some(step)),
            TotpCheck::Valid { step: step + 1 }
        );
    }

    #[test]
    fn malformed_codes_are_refused() {
        let config = TotpConfig::default();
        let secret = b"12345678901234567890";
        let now = at(59);
        let code = config.code(secret, config.step_at(now));
        assert_eq!(
            config.verify(secret, &format!("{} {}", &code[..3], &code[3..]), now, None),
            TotpCheck::Valid {
                step: config.step_at(now)
            }
        );
        for bad in [
            "",
            "12345",
            "1234567",
            "12345a",
            "١٢٣٤٥٦",
            "-12345",
            &format!("{}\n", code.as_str()),
        ] {
            assert_eq!(
                config.verify(secret, bad, now, None),
                TotpCheck::Invalid,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn config_ranges_are_checked() {
        assert!(TotpConfig::default().check().is_ok());
        assert!(TotpConfig::default().digits(5).check().is_err());
        assert!(TotpConfig::default().digits(9).check().is_err());
        assert!(TotpConfig::default().digits(8).check().is_ok());
        assert!(
            TotpConfig::default()
                .period(Duration::ZERO)
                .check()
                .is_err()
        );
        assert!(
            TotpConfig::default()
                .period(Duration::from_millis(1500))
                .check()
                .is_err()
        );
        assert!(TotpConfig::default().skew_steps(11).check().is_err());
        assert!(TotpConfig::default().secret_bytes(15).check().is_err());
        assert!(TotpConfig::default().secret_bytes(65).check().is_err());
        assert!(TotpConfig::default().secret_bytes(32).check().is_ok());
    }

    #[test]
    fn base32_matches_rfc_4648() {
        // RFC 4648 section 10, without padding.
        for (input, expected) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32(input.as_bytes(), BASE32_UPPER).as_str(), expected);
        }
    }

    #[test]
    fn otpauth_uri_is_well_formed() {
        let config = TotpConfig::default();
        let uri = otpauth_uri(
            &config,
            b"12345678901234567890",
            Some("Acme Co"),
            "budi@example.com",
        );
        assert_eq!(
            uri.as_str(),
            "otpauth://totp/Acme%20Co:budi%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\
             &issuer=Acme%20Co&algorithm=SHA1&digits=6&period=30"
        );
        let uri = otpauth_uri(&config.digits(8), b"12345678901234567890", None, "a:b");
        assert!(uri.starts_with("otpauth://totp/a%3Ab?secret="), "{}", *uri);
        assert!(
            uri.ends_with("&algorithm=SHA1&digits=8&period=30"),
            "{}",
            *uri
        );
    }

    #[test]
    fn secrets_are_random_and_redacted() {
        let a = Secret::generate(20).unwrap();
        let b = Secret::generate(20).unwrap();
        assert_ne!(*a.0, *b.0);
        assert_eq!(a.base32().len(), 32);
        assert_eq!(format!("{a:?}"), "Secret(<redacted>)");
    }
}
