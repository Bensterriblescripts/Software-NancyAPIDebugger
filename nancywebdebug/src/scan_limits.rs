use std::fmt::Display;
use std::ops::RangeInclusive;
use std::time::Duration;

pub(crate) const CONCURRENCY: RangeInclusive<usize> = 1..=4_096;
pub(crate) const CONNECTION_RATE: RangeInclusive<u32> = 1..=10_000;
pub(crate) const CONNECTION_TIMEOUT: RangeInclusive<f64> = 0.1..=120.0;
pub(crate) const PROBE_TIMEOUT: RangeInclusive<f64> = 0.1..=300.0;
pub(crate) const STAGE_TIMEOUT: RangeInclusive<f64> = 0.1..=3_600.0;
pub(crate) const ACTIVE_PER_ORIGIN: RangeInclusive<usize> = 1..=10_000;
pub(crate) const ACTIVE_TOTAL: RangeInclusive<usize> = 1..=100_000;
pub(crate) const CT_HOSTNAMES: RangeInclusive<usize> = 1..=5_000;
pub(crate) const CRAWL_URLS: RangeInclusive<usize> = 1..=100_000;
pub(crate) const CRAWL_CONCURRENCY: RangeInclusive<usize> = 1..=1_024;
pub(crate) const CRAWL_RATE: RangeInclusive<u32> = 1..=10_000;

fn range_error<T: Display>(range: &RangeInclusive<T>, name: &str) -> String {
    format!(
        "{name} must be between {} and {} (inclusive)",
        range.start(),
        range.end()
    )
}

pub(crate) fn validate<T: PartialOrd + Display>(
    value: T,
    range: RangeInclusive<T>,
    name: &str,
) -> Result<(), String> {
    if range.contains(&value) {
        Ok(())
    } else {
        Err(range_error(&range, name))
    }
}

pub(crate) fn timeout(
    seconds: f64,
    range: RangeInclusive<f64>,
    name: &str,
) -> Result<Duration, String> {
    validate(seconds, range.clone(), name)?;
    Duration::try_from_secs_f64(seconds).map_err(|_| range_error(&range, name))
}

pub(crate) fn validate_timeout(
    duration: Duration,
    range: RangeInclusive<f64>,
    name: &str,
) -> Result<(), String> {
    if (Duration::from_secs_f64(*range.start())..=Duration::from_secs_f64(*range.end()))
        .contains(&duration)
    {
        Ok(())
    } else {
        Err(range_error(&range, name))
    }
}
