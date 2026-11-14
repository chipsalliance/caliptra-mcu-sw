use crate::fake;
use fake::alarm::*;

// Tests the command implementation.
#[test]
fn command() {
    use fake::SyscallDriver;
    let alarm = Alarm::new(10);

    assert_eq!(
        alarm.command(command::FREQUENCY, 1, 2).get_success_u32(),
        Some(10)
    );
}

// TIME starts at zero and tracks the accumulated set_relative deltas, so a
// consumer that sleeps then reads the clock sees it advance.
#[test]
fn time_advances_with_set_relative() {
    use fake::SyscallDriver;
    let alarm = Alarm::new(1000);

    assert_eq!(
        alarm.command(command::TIME, 0, 0).get_success_u32(),
        Some(0)
    );
    let _ = alarm.command(command::SET_RELATIVE, 250, 0);
    assert_eq!(
        alarm.command(command::TIME, 0, 0).get_success_u32(),
        Some(250)
    );
    let _ = alarm.command(command::SET_RELATIVE, 750, 0);
    assert_eq!(
        alarm.command(command::TIME, 0, 0).get_success_u32(),
        Some(1000)
    );
}
