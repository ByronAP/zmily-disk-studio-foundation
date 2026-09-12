//! Shared bounded recovery page admission. Callers choose whether an empty
//! aggregate-only request is meaningful for their protocol.

pub const DEFAULT_PAGE_LIMIT: usize = 1_000;

#[derive(Clone, Copy)]
pub struct PagePolicy {
    pub maximum: usize,
    pub allow_zero: bool,
}

impl PagePolicy {
    pub fn validate_count(self, count: usize) -> Result<(), String> {
        if count > self.maximum || count == 0 && !self.allow_zero {
            return Err(format!(
                "recovery page count {count} is outside {}..={}",
                usize::from(!self.allow_zero),
                self.maximum
            ));
        }
        Ok(())
    }

    pub fn validate_window(
        self,
        start: u64,
        requested: usize,
        returned: u64,
        total: u64,
        actual: usize,
    ) -> Result<(), String> {
        self.validate_count(requested)?;
        if returned != actual as u64
            || returned != (requested as u64).min(total.saturating_sub(start))
        {
            return Err("recovery page does not contain its exact requested window".into());
        }
        Ok(())
    }
}
