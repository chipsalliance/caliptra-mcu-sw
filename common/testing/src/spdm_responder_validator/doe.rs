// Licensed under the Apache-2.0 license

use crate::doe_util::common::DoeUtil;
use crate::doe_util::protocol::{DataObjectType, DoeHeader};
use crate::spdm_responder_validator::common::{
    execute_spdm_attestation, execute_spdm_responder_validator, execute_spdm_tee_io_validator,
    start_doe_session_requester, wait_for_spdm_responder_validator, SpdmValidatorRunner,
    SERVER_LISTENING,
};
use crate::spdm_responder_validator::transport::{Transport, SOCKET_TRANSPORT_TYPE_PCI_DOE};
use crate::spdm_responder_validator::SpdmTestType;
use crate::{
    sleep_emulator_ticks, wait_for_runtime_start, wait_for_spdm_responder_ready,
    SpdmResponderTransport,
};
use std::cell::Cell;
use std::net::TcpListener;
use std::process::exit;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::time::{Duration, Instant};
use zerocopy::IntoBytes;

const TEST_NAME: &str = "DOE-SPDM-RESPONDER-VALIDATOR";
const RAW_RECOVERY: u8 = 1;
const SECURED_RESPONSE: u8 = 1 << 1;
const DISCOVERY_NEGOTIATION: u8 = 1 << 2;
const DISCOVERY_CHUNKING: u8 = 1 << 3;
const DISCOVERY_SECURED: u8 = 1 << 4;
const REQUIRED_COVERAGE: u8 = RAW_RECOVERY
    | SECURED_RESPONSE
    | DISCOVERY_NEGOTIATION
    | DISCOVERY_CHUNKING
    | DISCOVERY_SECURED;
// FINISH and END_SESSION are required; HEARTBEAT depends on advertised capabilities.
const REQUIRED_SECURED_EXCHANGES: usize = 2;

enum TxRxState {
    Start,
    SendReq,
    ReceiveResp,
    Finish,
}

pub struct DoeTransport {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    tx_rx_state: TxRxState,
    retry_count: usize,
    recovery_checks: Option<Rc<Cell<u8>>>,
    session_exchanges: Option<Rc<Cell<usize>>>,
}

impl DoeTransport {
    pub fn new(tx: Sender<Vec<u8>>, rx: Receiver<Vec<u8>>, retry_count: usize) -> Self {
        Self {
            tx,
            rx,
            tx_rx_state: TxRxState::Start,
            retry_count,
            recovery_checks: None,
            session_exchanges: None,
        }
    }

    fn exchange(&mut self, req: &[u8], wait_for_responder: bool) -> Option<Vec<u8>> {
        self.tx_rx_state = TxRxState::Start;
        let mut resp = None;
        let mut retry_count = 0;

        while crate::is_emulator_running() {
            match self.tx_rx_state {
                TxRxState::Start => {
                    if wait_for_responder {
                        sleep_emulator_ticks(5_000_000);
                    } else {
                        // This is to give some time for send_done upcall to be invoked by the kernel to the app.
                        // Just a hack and may not be perfect solution.
                        sleep_emulator_ticks(100_000);
                    }
                    self.tx_rx_state = TxRxState::SendReq;
                }
                TxRxState::SendReq => {
                    if DoeUtil::send_raw_data_object(req, &mut self.tx).is_ok() {
                        self.tx_rx_state = TxRxState::ReceiveResp;
                    } else {
                        println!("[{}]: Failed to send request", TEST_NAME);
                        self.tx_rx_state = TxRxState::Finish;
                    }
                }
                TxRxState::ReceiveResp => match DoeUtil::receive_raw_data_object(&self.rx) {
                    Ok(response) if !response.is_empty() => {
                        resp = Some(response.clone());
                        self.tx_rx_state = TxRxState::Finish;
                    }
                    Ok(_) => {
                        if retry_count < self.retry_count {
                            retry_count += 1;
                            println!(
                                "[{}]: No response received, retrying... ({})",
                                TEST_NAME, retry_count
                            );
                            self.tx_rx_state = TxRxState::SendReq;
                        } else {
                            println!(
                                "[{}]: No response received after {} retries, failing test",
                                TEST_NAME, self.retry_count
                            );
                            self.tx_rx_state = TxRxState::Finish;
                        }
                    }
                    Err(e) => {
                        println!("[{}]: Failed to receive response: {:?}", TEST_NAME, e);
                        self.tx_rx_state = TxRxState::Finish;
                    }
                },
                TxRxState::Finish => {
                    break;
                }
            }
        }
        resp
    }

    fn object(kind: DataObjectType, payload: &[u8]) -> Vec<u8> {
        let length = (8 + payload.len()).next_multiple_of(4);
        let mut object = DoeHeader::new(kind, length as u32).as_bytes().to_vec();
        object.extend_from_slice(payload);
        object.resize(length, 0);
        object
    }

    fn validate_object(object: &[u8], kind: u8) -> Result<(), String> {
        if object.len() < 12
            || !object.len().is_multiple_of(4)
            || object[..4] != [1, 0, kind, 0]
            || u32::from_le_bytes(object[4..8].try_into().unwrap()) as usize != object.len() / 4
        {
            return Err(format!("Invalid DOE response framing: {object:02x?}"));
        }
        Ok(())
    }

    fn expect_discard(&mut self, request: &[u8]) -> Result<(), String> {
        sleep_emulator_ticks(100_000);
        DoeUtil::send_raw_data_object(request, &mut self.tx)
            .map_err(|error| format!("Failed to inject DOE object: {error:?}"))?;
        for _ in 0..10 {
            sleep_emulator_ticks(100_000);
            match self.rx.try_recv() {
                Ok(response) => {
                    return Err(format!("Expected DOE discard, received {response:02x?}"));
                }
                Err(TryRecvError::Empty) => {}
                Err(error) => return Err(format!("DOE probe channel failed: {error}")),
            }
        }
        Ok(())
    }

    fn check_discovery(&mut self) -> Result<(), String> {
        let request = Self::object(DataObjectType::DoeDiscovery, &[1, 0, 0, 0]);
        let expected = Self::object(DataObjectType::DoeDiscovery, &[1, 0, 1, 2]);
        let response = self
            .exchange(&request, false)
            .ok_or_else(|| "No interleaved DOE discovery response".to_string())?;
        if response != expected {
            return Err(format!("Interleaved discovery mismatch: {response:02x?}"));
        }
        Ok(())
    }

    fn check_raw_recovery(&mut self) -> Result<(), String> {
        let version_request = Self::object(DataObjectType::DoeSpdm, &[0x10, 0x84, 0, 0]);
        let version_response = self
            .exchange(&version_request, false)
            .ok_or_else(|| "No initial DOE VERSION response".to_string())?;
        Self::validate_object(&version_response, 1)?;
        if version_response[8..10] != [0x10, 0x04] {
            return Err(format!(
                "Unexpected DOE VERSION payload: {version_response:02x?}"
            ));
        }
        for object in [
            Self::object(DataObjectType::DoeSpdm, &[0; 1028]),
            Self::object(DataObjectType::DoeSecureSpdm, &[0xff; 24]),
        ] {
            self.expect_discard(&object)?;
            let response = self.exchange(&version_request, false).ok_or_else(|| {
                "DOE responder did not recover after discarded object".to_string()
            })?;
            if response != version_response {
                return Err(format!("DOE recovery VERSION mismatch: {response:02x?}"));
            }
        }
        println!("[{TEST_NAME}]: Live raw DOE framing and recovery checks passed");
        Ok(())
    }

    fn before_exchange(&mut self, req: &[u8]) -> Result<(), String> {
        let Some(coverage) = self.recovery_checks.clone() else {
            return Ok(());
        };
        if coverage.get() & RAW_RECOVERY == 0 {
            self.check_raw_recovery()?;
            coverage.set(coverage.get() | RAW_RECOVERY);
        }
        if req.len() < 12 {
            return Ok(());
        }
        let completed = coverage.get();
        let phase = match (req[2], req[9]) {
            (1, 0xe1 | 0xe3) => DISCOVERY_NEGOTIATION,
            (1, 0x85 | 0x86) => DISCOVERY_CHUNKING,
            (2, _) if completed & SECURED_RESPONSE != 0 => DISCOVERY_SECURED,
            _ => 0,
        };
        if phase != 0 && completed & phase == 0 {
            if phase == DISCOVERY_SECURED {
                let mut stale = req.to_vec();
                stale[11] ^= 0x80;
                self.expect_discard(&stale)?;
            } else {
                let mut invalid_type = Self::object(DataObjectType::DoeSpdm, &[0; 4]);
                invalid_type[2] = 0xff;
                self.expect_discard(&invalid_type)?;
            }
            self.check_discovery()?;
            coverage.set(coverage.get() | phase);
        }
        Ok(())
    }

    fn observe_response(&self, req: &[u8], response: &[u8]) -> Result<(), String> {
        if self.recovery_checks.is_none() && self.session_exchanges.is_none() {
            return Ok(());
        }
        let kind = *req
            .get(2)
            .ok_or_else(|| "Requester sent a truncated DOE request".to_string())?;
        Self::validate_object(req, kind)?;
        Self::validate_object(response, kind)?;
        if kind == DataObjectType::DoeSecureSpdm as u8 {
            if req[8..12] != response[8..12] {
                return Err(
                    "DOE secured response session ID does not match the request".to_string()
                );
            }
            if let Some(exchanges) = &self.session_exchanges {
                exchanges.set(exchanges.get() + 1);
            }
            if let Some(coverage) = &self.recovery_checks {
                coverage.set(coverage.get() | SECURED_RESPONSE);
            }
        }
        Ok(())
    }
}

impl Transport for DoeTransport {
    fn target_send_and_receive(&mut self, req: &[u8], wait_for_responder: bool) -> Option<Vec<u8>> {
        if let Err(error) = self.before_exchange(req) {
            println!("[{TEST_NAME}]: DOE recovery check failed: {error}");
            exit(1);
        }
        let response = self.exchange(req, wait_for_responder)?;
        if let Err(error) = self.observe_response(req, &response) {
            println!("[{TEST_NAME}]: {error}");
            exit(1);
        }
        Some(response)
    }

    fn transport_type(&self) -> u32 {
        SOCKET_TRANSPORT_TYPE_PCI_DOE
    }
}

fn check_session_tuple(secured_exchanges: &Cell<usize>) -> Result<(), String> {
    let observed = secured_exchanges.replace(0);
    if observed < REQUIRED_SECURED_EXCHANGES {
        return Err(format!(
            "Requester completed {observed} secured DOE exchanges; expected at least \
             {REQUIRED_SECURED_EXCHANGES} (FINISH, END_SESSION). \
             Use a session-capable spdm_requester_emu build; the default pinned \
             Caliptra requester is measurement-only."
        ));
    }
    Ok(())
}

fn run_session_matrix(
    listener: &TcpListener,
    test: &mut SpdmValidatorRunner,
    secured_exchanges: &Cell<usize>,
) -> Result<(), String> {
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    for (pqc, kem) in [(false, false), (false, true), (true, false), (true, true)] {
        let mut child = start_doe_session_requester(pqc, kem)
            .map_err(|error| format!("Could not start DOE session requester: {error}"))?;
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(format!("DOE session accept failed: {error}")),
            }
            if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                return Err(format!(
                    "DOE session requester exited before connecting: {status}"
                ));
            }
            if Instant::now() >= deadline {
                child.kill().map_err(|error| error.to_string())?;
                child.wait().map_err(|error| error.to_string())?;
                return Err("DOE session requester connection timed out".to_string());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        test.run_test(&mut stream);
        if !test.is_passed() {
            child.kill().map_err(|error| error.to_string())?;
            child.wait().map_err(|error| error.to_string())?;
            return Err(format!("DOE session bridge failed: pqc={pqc}, kem={kem}"));
        }
        let status = child.wait().map_err(|error| error.to_string())?;
        if !status.success() {
            return Err(format!(
                "DOE session crypto verification failed: pqc={pqc}, kem={kem}: {status}"
            ));
        }
        check_session_tuple(secured_exchanges)
            .map_err(|error| format!("DOE session tuple failed: pqc={pqc}, kem={kem}: {error}"))?;
        println!("[{TEST_NAME}]: Real DOE session tuple passed: pqc={pqc}, kem={kem}");
    }
    Ok(())
}

/// `SPDM_DOE_SESSION_MATRIX_ONLY` runs the four requester tuples instead of conformance.
/// `SPDM_DOE_RECOVERY_CHECKS` runs the tuples with recovery/interleaving probes enabled.
/// Point `SPDM_VALIDATOR_DIR` at a requester build with its existing session path enabled.
/// Keep measurement support enabled: certificate helpers require it in the pinned build.
/// Its default measurement-only build fails the per-tuple secured-exchange check.
pub fn run_doe_spdm_conformance_test(
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    test_type: SpdmTestType,
    test_timeout_seconds: Duration,
) {
    let check_responder_results = matches!(&test_type, SpdmTestType::SpdmResponderConformance);
    let recovery_checks =
        check_responder_results && std::env::var_os("SPDM_DOE_RECOVERY_CHECKS").is_some();
    let run_matrix = recovery_checks
        || (check_responder_results && std::env::var_os("SPDM_DOE_SESSION_MATRIX_ONLY").is_some());
    // Spawn a thread to handle the timeout for the test
    crate::spawn_with_emulator_state(move || {
        std::thread::sleep(test_timeout_seconds);
        println!(
            "[{}] TIMED OUT AFTER {:?} SECONDS",
            TEST_NAME,
            test_timeout_seconds.as_secs()
        );
        exit(-1);
    });

    // Spawn a thread to run the tests
    crate::spawn_with_emulator_state(move || {
        wait_for_runtime_start();
        wait_for_spdm_responder_ready(SpdmResponderTransport::Doe);

        if !crate::is_emulator_running() {
            exit(-1);
        }

        let listener =
            TcpListener::bind("127.0.0.1:2323").expect("Could not bind to the SPDM listerner port");
        println!("[{}]: Spdm Server Listening on port 2323", TEST_NAME);
        SERVER_LISTENING.store(true, Ordering::Relaxed);

        let coverage = recovery_checks.then(|| Rc::new(Cell::new(0)));
        let session_exchanges = Rc::new(Cell::new(0));
        let mut transport = DoeTransport::new(tx, rx, 1);
        transport.recovery_checks = coverage.clone();
        transport.session_exchanges = run_matrix.then(|| session_exchanges.clone());
        let mut test = SpdmValidatorRunner::new(Box::new(transport), TEST_NAME);
        if run_matrix {
            if let Err(error) = run_session_matrix(&listener, &mut test, &session_exchanges) {
                println!("[{TEST_NAME}]: {error}");
                exit(1);
            }
            if let Some(coverage) = coverage {
                if coverage.get() != REQUIRED_COVERAGE {
                    println!(
                        "[{TEST_NAME}]: Required live DOE checks were not exercised: {:#x}",
                        coverage.get()
                    );
                    exit(1);
                }
            }
            println!("[{TEST_NAME}]: DOE session matrix passed");
            exit(0);
        }

        if let Some(spdm_stream) = listener.incoming().next() {
            let mut spdm_stream = spdm_stream.expect("Failed to accept connection");

            test.run_test(&mut spdm_stream);
            if !test.is_passed() {
                println!("[{}]: Spdm Responder Conformance Test Failed", TEST_NAME);
                exit(-1);
            }
            if check_responder_results && !wait_for_spdm_responder_validator() {
                println!("[{}]: Spdm Validator Result Check Failed", TEST_NAME);
                exit(-1);
            }
            println!("[{}]: Spdm Responder Conformance Test Passed", TEST_NAME);
            exit(0);
        }
    });

    match test_type {
        SpdmTestType::SpdmResponderConformance if run_matrix => {}
        SpdmTestType::SpdmResponderConformance => {
            let _ = execute_spdm_responder_validator("PCI_DOE");
        }
        SpdmTestType::SpdmTeeIoValidator => execute_spdm_tee_io_validator("PCI_DOE"),
        SpdmTestType::SpdmAttestation => execute_spdm_attestation("PCI_DOE"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::{channel, TryRecvError};

    #[test]
    fn transport_does_not_inject_recovery_objects_by_default() {
        for track_sessions in [false, true] {
            let (tx, requests) = channel();
            let (_responses, rx) = channel();
            let mut transport = DoeTransport::new(tx, rx, 1);
            transport.session_exchanges = track_sessions.then(|| Rc::new(Cell::new(0)));

            for kind in [DataObjectType::DoeSpdm, DataObjectType::DoeSecureSpdm] {
                let request = DoeTransport::object(kind, &[0; 4]);
                transport.before_exchange(&request).unwrap();
                assert_eq!(requests.try_recv(), Err(TryRecvError::Empty));
            }
            if !track_sessions {
                transport.observe_response(&[], &[]).unwrap();
            }
        }
    }

    #[test]
    fn session_matrix_requires_secured_exchanges_for_each_tuple() {
        let exchanges = Cell::new(0);
        for count in 0..REQUIRED_SECURED_EXCHANGES {
            exchanges.set(count);
            let error = check_session_tuple(&exchanges).unwrap_err();
            assert!(error.contains("session-capable spdm_requester_emu"));
            assert_eq!(exchanges.get(), 0);
        }
        for count in [REQUIRED_SECURED_EXCHANGES, REQUIRED_SECURED_EXCHANGES + 1] {
            exchanges.set(count);
            check_session_tuple(&exchanges).unwrap();
            assert_eq!(exchanges.get(), 0);
            assert!(check_session_tuple(&exchanges).is_err());
        }
    }

    #[test]
    fn session_matrix_counts_only_framed_secured_exchanges() {
        let (tx, _requests) = channel();
        let (_responses, rx) = channel();
        let mut transport = DoeTransport::new(tx, rx, 1);
        let exchanges = Rc::new(Cell::new(0));
        transport.session_exchanges = Some(exchanges.clone());

        let plain = DoeTransport::object(DataObjectType::DoeSpdm, &[0; 4]);
        transport.observe_response(&plain, &plain).unwrap();
        assert!(check_session_tuple(&exchanges).is_err());
        let secured = DoeTransport::object(DataObjectType::DoeSecureSpdm, &[0x5a; 32]);
        for count in 1..=REQUIRED_SECURED_EXCHANGES {
            transport.observe_response(&secured, &secured).unwrap();
            assert_eq!(exchanges.get(), count);
        }
        check_session_tuple(&exchanges).unwrap();
        assert!(check_session_tuple(&exchanges).is_err());
    }

    #[test]
    fn session_tracking_preserves_recovery_coverage() {
        let (tx, _requests) = channel();
        let (_responses, rx) = channel();
        let mut transport = DoeTransport::new(tx, rx, 1);
        let exchanges = Rc::new(Cell::new(0));
        let coverage = Rc::new(Cell::new(RAW_RECOVERY));
        transport.session_exchanges = Some(exchanges.clone());
        transport.recovery_checks = Some(coverage.clone());

        let secured = DoeTransport::object(DataObjectType::DoeSecureSpdm, &[0x5a; 32]);
        transport.observe_response(&secured, &secured).unwrap();
        assert_eq!(exchanges.get(), 1);
        assert_eq!(coverage.get(), RAW_RECOVERY | SECURED_RESPONSE);
    }

    #[test]
    fn session_matrix_rejects_invalid_or_mismatched_response_objects() {
        let (tx, requests) = channel();
        let (_responses, rx) = channel();
        let mut transport = DoeTransport::new(tx, rx, 1);
        let exchanges = Rc::new(Cell::new(0));
        transport.session_exchanges = Some(exchanges.clone());

        let secured = DoeTransport::object(DataObjectType::DoeSecureSpdm, &[0x5a; 32]);
        let plain = DoeTransport::object(DataObjectType::DoeSpdm, &[0x5a; 32]);
        let mut wrong_session = secured.clone();
        wrong_session[8] ^= 0x80;
        let mut wrong_length = secured.clone();
        wrong_length[4] += 1;
        for response in [&secured[..4], &plain, &wrong_session, &wrong_length] {
            assert!(transport.observe_response(&secured, response).is_err());
            assert_eq!(exchanges.get(), 0);
        }
        assert!(transport.observe_response(&secured[..4], &secured).is_err());
        assert_eq!(exchanges.get(), 0);
        assert_eq!(requests.try_recv(), Err(TryRecvError::Empty));
    }
}
