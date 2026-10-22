// SPDX-License-Identifier: MIT OR Apache-2.0

//! Primary and secondary rate limits.
//!
//! The client never retries and never sleeps. When GitHub says to stop, the
//! gate records until when, and every request before that instant fails
//! locally without touching the network. The scheduler decides when to try
//! again, so a refusal cannot turn into a retry storm.
//!
//! Rules (GitHub REST documentation, "Rate limits for the REST API"):
//! - `x-ratelimit-remaining: 0` stops requests until `x-ratelimit-reset`,
//!   even on a successful response;
//! - a 403 or 429 with `retry-after` stops for that many seconds;
//! - a 403 or 429 with `x-ratelimit-remaining: 0` stops until the reset;
//! - another 429, or a 403 whose message names a rate limit, is a secondary
//!   limit without guidance: wait one minute, doubling on each consecutive
//!   refusal.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::transport::ResponseHeaders;

/// No wait is longer than this, whatever a header says. GitHub's primary
/// window is one hour.
pub const MAX_WAIT: Duration = Duration::from_secs(3660);

/// First wait for a secondary limit without guidance.
pub const SECONDARY_BASE_WAIT: Duration = Duration::from_secs(60);

/// Source of the current time; replaceable in tests.
pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimitKind {
    /// The hourly quota is exhausted.
    Primary,
    /// GitHub's abuse protection.
    Secondary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimited {
    pub kind: RateLimitKind,
    /// No request is sent before this instant.
    pub until: SystemTime,
}

/// The last quota GitHub reported, for status output.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct QuotaSnapshot {
    pub limit: Option<u64>,
    pub remaining: Option<u64>,
    pub reset: Option<SystemTime>,
    pub resource: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct RateLimitGate {
    blocked: Option<RateLimited>,
    secondary_strikes: u32,
    quota: QuotaSnapshot,
}

impl RateLimitGate {
    /// Refuses locally while a wait is in force.
    pub(crate) fn check(&self, now: SystemTime) -> Result<(), RateLimited> {
        match self.blocked {
            Some(blocked) if now < blocked.until => Err(blocked),
            _ => Ok(()),
        }
    }

    pub(crate) fn quota(&self) -> &QuotaSnapshot {
        &self.quota
    }

    /// Records a response. Returns the refusal when the response itself is a
    /// rate-limit refusal; a successful response that exhausts the quota is
    /// returned to the caller and only blocks later requests.
    pub(crate) fn observe(
        &mut self,
        now: SystemTime,
        status: u16,
        headers: &ResponseHeaders,
        message: Option<&str>,
    ) -> Option<RateLimited> {
        let remaining = parse_u64(headers.ratelimit_remaining.as_deref());
        let reset = parse_u64(headers.ratelimit_reset.as_deref())
            .and_then(|seconds| UNIX_EPOCH.checked_add(Duration::from_secs(seconds)));
        self.quota = QuotaSnapshot {
            limit: parse_u64(headers.ratelimit_limit.as_deref()),
            remaining,
            reset,
            resource: headers
                .ratelimit_resource
                .as_ref()
                .filter(|value| {
                    value.len() <= 64 && value.bytes().all(|byte| byte.is_ascii_graphic())
                })
                .cloned(),
        };
        let exhausted = remaining == Some(0);
        let retry_after = parse_u64(headers.retry_after.as_deref()).map(Duration::from_secs);

        if (200..400).contains(&status) {
            self.secondary_strikes = 0;
            if exhausted {
                self.blocked = Some(RateLimited {
                    kind: RateLimitKind::Primary,
                    until: until_reset(now, reset),
                });
            }
            return None;
        }

        let names_rate_limit =
            message.is_some_and(|message| message.to_ascii_lowercase().contains("rate limit"));
        let refusal = match status {
            403 | 429 => {
                if let Some(wait) = retry_after {
                    let kind = if exhausted {
                        RateLimitKind::Primary
                    } else {
                        RateLimitKind::Secondary
                    };
                    Some(RateLimited {
                        kind,
                        until: now + wait.clamp(Duration::from_secs(1), MAX_WAIT),
                    })
                } else if exhausted {
                    Some(RateLimited {
                        kind: RateLimitKind::Primary,
                        until: until_reset(now, reset),
                    })
                } else if status == 429 || names_rate_limit {
                    let factor = 1_u32 << self.secondary_strikes.min(6);
                    self.secondary_strikes = self.secondary_strikes.saturating_add(1);
                    Some(RateLimited {
                        kind: RateLimitKind::Secondary,
                        until: now + (SECONDARY_BASE_WAIT * factor).min(MAX_WAIT),
                    })
                } else {
                    None
                }
            }
            _ => None,
        };
        if refusal.is_some() {
            self.blocked = refusal;
        }
        refusal
    }
}

/// The reset instant, clamped into `[now + 1 s, now + MAX_WAIT]` so that a
/// missing, past, or absurd value neither busy-loops nor blocks forever.
fn until_reset(now: SystemTime, reset: Option<SystemTime>) -> SystemTime {
    let earliest = now + Duration::from_secs(1);
    let latest = now + MAX_WAIT;
    match reset {
        Some(reset) => reset.clamp(earliest, latest),
        None => latest,
    }
}

fn parse_u64(value: Option<&str>) -> Option<u64> {
    let value = value?.trim();
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(
        remaining: Option<&str>,
        reset: Option<&str>,
        retry_after: Option<&str>,
    ) -> ResponseHeaders {
        ResponseHeaders {
            ratelimit_remaining: remaining.map(str::to_owned),
            ratelimit_reset: reset.map(str::to_owned),
            retry_after: retry_after.map(str::to_owned),
            ..ResponseHeaders::default()
        }
    }

    #[test]
    fn exhausted_quota_on_success_blocks_until_reset() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let mut gate = RateLimitGate::default();
        assert_eq!(
            gate.observe(now, 200, &headers(Some("0"), Some("1600"), None), None),
            None
        );
        let blocked = gate.check(now);
        assert_eq!(
            blocked,
            Err(RateLimited {
                kind: RateLimitKind::Primary,
                until: UNIX_EPOCH + Duration::from_secs(1_600)
            })
        );
        assert!(gate.check(UNIX_EPOCH + Duration::from_secs(1_600)).is_ok());
    }

    #[test]
    fn absurd_or_past_resets_are_clamped() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let mut gate = RateLimitGate::default();
        let far = gate.observe(
            now,
            403,
            &headers(Some("0"), Some("99999999999"), None),
            None,
        );
        assert_eq!(far.map(|limit| limit.until), Some(now + MAX_WAIT));
        let past = gate.observe(now, 403, &headers(Some("0"), Some("10"), None), None);
        assert_eq!(
            past.map(|limit| limit.until),
            Some(now + Duration::from_secs(1))
        );
    }

    #[test]
    fn forbidden_without_rate_limit_signals_is_not_a_rate_limit() {
        let now = UNIX_EPOCH;
        let mut gate = RateLimitGate::default();
        assert_eq!(
            gate.observe(
                now,
                403,
                &headers(Some("10"), None, None),
                Some("Resource not accessible")
            ),
            None
        );
        assert!(gate.check(now).is_ok());
    }

    #[test]
    fn malformed_numbers_are_ignored() {
        assert_eq!(parse_u64(Some("-1")), None);
        assert_eq!(parse_u64(Some("1.5")), None);
        assert_eq!(parse_u64(Some("")), None);
        assert_eq!(parse_u64(Some(" 42 ")), Some(42));
    }
}
