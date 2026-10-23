// Licensed under the Apache-2.0 license

//! Strap pin options shared by `cargo xtask rom` and `cargo xtask runtime`.
//! They are forwarded to the emulator as a single `--strap-pins <mask>`.

use clap::Args;

#[derive(Args, Clone, Debug, Default)]
pub struct StrapPinArgs {
    /// Strap pin bitmask (hex or decimal, 0..=0x3f), forwarded to the emulator:
    /// bit0=bootmode0, bit1=bootmode1, bit2=strap0, bit3=strap1, bit4=strap2,
    /// bit5=strap3. ORed with the individual flags below.
    #[arg(long, value_parser = parse_strap_pins, default_value = "0")]
    pub strap_pins: u8,
    /// Drive the bootmode0 strap pin high
    #[arg(long)]
    pub bootmode0: bool,
    /// Drive the bootmode1 strap pin high
    #[arg(long)]
    pub bootmode1: bool,
    /// Drive the strap0 pin high
    #[arg(long)]
    pub strap0: bool,
    /// Drive the strap1 pin high
    #[arg(long)]
    pub strap1: bool,
    /// Drive the strap2 pin high
    #[arg(long)]
    pub strap2: bool,
    /// Drive the strap3 pin high
    #[arg(long)]
    pub strap3: bool,
}

fn parse_strap_pins(s: &str) -> Result<u8, String> {
    let v = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u8::from_str_radix(h, 16)
    } else {
        s.parse::<u8>()
    }
    .map_err(|e| e.to_string())?;
    if v > 0x3f {
        return Err(format!("strap pin mask {v:#x} exceeds 6 bits (max 0x3f)"));
    }
    Ok(v)
}

impl StrapPinArgs {
    pub fn mask(&self) -> u8 {
        self.strap_pins
            | (self.bootmode0 as u8)
            | (self.bootmode1 as u8) << 1
            | (self.strap0 as u8) << 2
            | (self.strap1 as u8) << 3
            | (self.strap2 as u8) << 4
            | (self.strap3 as u8) << 5
    }

    /// Emulator CLI args (empty when no pins are set).
    pub fn emulator_args(&self) -> Vec<String> {
        match self.mask() {
            0 => vec![],
            m => vec!["--strap-pins".into(), format!("{m:#x}")],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_combines_bitmask_and_flags() {
        let a = StrapPinArgs {
            strap_pins: 0x01,
            strap3: true,
            ..Default::default()
        };
        assert_eq!(a.mask(), 0x21);
        assert_eq!(a.emulator_args(), vec!["--strap-pins", "0x21"]);
        assert!(StrapPinArgs::default().emulator_args().is_empty());
        assert!(parse_strap_pins("0x40").is_err());
        assert_eq!(parse_strap_pins("0x3f"), Ok(0x3f));
    }
}
