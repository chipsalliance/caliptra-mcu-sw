// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{CapabilitiesResp, CommandId, HpkeAlgorithms, MailboxReqHeader};
use caliptra_api::Capabilities;
use caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox;
use caliptra_mcu_libsyscall_caliptra::system::System;
use caliptra_mcu_measurement_api::attestation_manifest::{
    ATTESTATION_MANIFEST_FIXED_HEADER_SIZE, ATTESTATION_MANIFEST_MARKER,
    ATTESTATION_MANIFEST_VERSION,
};
use caliptra_mcu_measurement_api::signer::CaliptraDpeSigner;
use caliptra_mcu_measurement_api::{BootKind, DpeProfile, EvidenceReadinessPolicy};
use caliptra_mcu_romtime::println;
use caliptra_mcu_scratch_alloc::{BitmapAllocator, StaticBitmapAllocatorCell, BITMAP_SLOT_SIZE};
use core::mem::size_of;
use core::ptr::NonNull;
use mcu_caliptra_api::ocp_lock::{OcpLock, OcpLockEnumerateHpkeHandlesResp};
use mcu_caliptra_api::raw::raw_mailbox_execute;
use zerocopy::{FromBytes, IntoBytes};

static EXAMPLE_ATTESTATION_MANIFEST_BYTES: [u8; ATTESTATION_MANIFEST_FIXED_HEADER_SIZE] = {
    let mut bytes = [0u8; ATTESTATION_MANIFEST_FIXED_HEADER_SIZE];
    let marker = ATTESTATION_MANIFEST_MARKER.to_le_bytes();
    let size = (ATTESTATION_MANIFEST_FIXED_HEADER_SIZE as u32).to_le_bytes();
    let version = ATTESTATION_MANIFEST_VERSION.to_le_bytes();
    bytes[0] = marker[0];
    bytes[1] = marker[1];
    bytes[2] = marker[2];
    bytes[3] = marker[3];
    bytes[4] = size[0];
    bytes[5] = size[1];
    bytes[6] = size[2];
    bytes[7] = size[3];
    bytes[8] = version[0];
    bytes[9] = version[1];
    bytes[10] = version[2];
    bytes[11] = version[3];
    bytes[12] = size[0];
    bytes[13] = size[1];
    bytes[14] = size[2];
    bytes[15] = size[3];
    // entry_count = 0 (bytes 16..20), tcb_entry_count = 0 (bytes 20..24)
    // vendor_len = 4 ("test"), model_len = 4 ("test")
    bytes[24] = 4;
    bytes[26] = 4;
    bytes[28] = b't';
    bytes[29] = b'e';
    bytes[30] = b's';
    bytes[31] = b't';
    bytes[128] = b't';
    bytes[129] = b'e';
    bytes[130] = b's';
    bytes[131] = b't';
    bytes
};

const OCP_LOCK_SIGNER_SCRATCH_SIZE: usize = 9 * 1024;
const OCP_LOCK_SIGNER_SCRATCH_SLOTS: usize = OCP_LOCK_SIGNER_SCRATCH_SIZE / BITMAP_SLOT_SIZE;

#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct OcpLockSignerScratchSlot([u8; BITMAP_SLOT_SIZE]);

static OCP_LOCK_SIGNER_ALLOCATOR: StaticBitmapAllocatorCell = StaticBitmapAllocatorCell::new();
static mut OCP_LOCK_SIGNER_SCRATCH: [OcpLockSignerScratchSlot; OCP_LOCK_SIGNER_SCRATCH_SLOTS] =
    [OcpLockSignerScratchSlot([0; BITMAP_SLOT_SIZE]); OCP_LOCK_SIGNER_SCRATCH_SLOTS];

fn init_ocp_lock_signer_allocator() -> &'static BitmapAllocator {
    let scratch_ptr = unsafe {
        NonNull::new_unchecked(core::ptr::addr_of_mut!(OCP_LOCK_SIGNER_SCRATCH).cast::<u8>())
    };
    // SAFETY: this test initializes the allocator once and owns its static
    // backing storage for the task's lifetime.
    unsafe { OCP_LOCK_SIGNER_ALLOCATOR.init_once(scratch_ptr, OCP_LOCK_SIGNER_SCRATCH_SIZE) }
}

pub(crate) async fn test_get_algorithms() {
    println!("Starting OCP LOCK get algorithms test");

    let mailbox = Mailbox::new();

    // First check capabilities to ensure OCP LOCK is supported by caliptra-sw
    println!("Checking Caliptra capabilities...");
    let mut cap_req = MailboxReqHeader::default();
    let mut cap_resp_bytes = [0u8; size_of::<CapabilitiesResp>()];

    println!("Executing CAPABILITIES mailbox command");
    match raw_mailbox_execute(
        CommandId::CAPABILITIES.into(),
        cap_req.as_mut_bytes(),
        &mut cap_resp_bytes,
    )
    .await
    {
        Ok(size) => {
            println!("CAPABILITIES command finished with size {}", size);
            if size != size_of::<CapabilitiesResp>() {
                println!("Error: Unexpected capabilities response size {}", size);
                System::exit(1);
            }
            let cap_resp = CapabilitiesResp::read_from_bytes(&cap_resp_bytes).unwrap();
            let caps = Capabilities::try_from(cap_resp.capabilities.as_ref()).unwrap();
            println!("Capabilities: {:?}", caps);
            if !caps.contains(caliptra_api::Capabilities::RT_OCP_LOCK) {
                println!("Error: RT_OCP_LOCK capability not found!");
                System::exit(1);
            }
            println!("RT_OCP_LOCK capability is present");
        }
        Err(err) => {
            println!("Failed to get capabilities: {:?}", err);
            System::exit(1);
        }
    }

    let ocp_lock = OcpLock::new(&mailbox, &crate::ocp_lock_config::EXAMPLE_RUNTIME_CONFIG);

    println!("Sending OCP_LOCK_GET_ALGORITHMS command...");

    match ocp_lock.get_algorithms().await {
        Ok(resp) => {
            println!("OCP_LOCK_GET_ALGORITHMS command success");
            // Check that some algorithms are returned.
            // Based on caliptra-sw implementation, it should return all supported ones.
            if resp.hpke_algorithms.is_empty() {
                println!("Error: No HPKE algorithms returned");
                System::exit(1);
            }
            println!("HPKE algorithms: {:?}", resp.hpke_algorithms);
            println!("Access key sizes: {:?}", resp.access_key_sizes);
        }
        Err(err) => {
            println!("OCP_LOCK_GET_ALGORITHMS command failed with err {:?}", err);
            System::exit(1);
        }
    }

    println!("Test passed");
}
pub(crate) async fn test_get_hpke_public_key_x509() {
    println!("Starting OCP LOCK get HPKE public key x509 test");

    let mailbox = Mailbox::new();
    let signer_scratch = init_ocp_lock_signer_allocator();
    let mut cert_buf = [0u8; OcpLock::MAX_ENDORSEMENT_CERT_SIZE];

    caliptra_mcu_measurement_api::init(
        &EXAMPLE_ATTESTATION_MANIFEST_BYTES,
        &[],
        BootKind::ColdBoot,
        EvidenceReadinessPolicy::ReadyAfterBootInit,
        signer_scratch,
    )
    .await
    .unwrap();
    caliptra_mcu_measurement_api::export_cdi_and_stash(
        signer_scratch,
        None,
        DpeProfile::P384Sha384,
        &mut cert_buf,
    )
    .await
    .unwrap();

    let ocp_lock = OcpLock::new(&mailbox, &crate::ocp_lock_config::EXAMPLE_RUNTIME_CONFIG);
    let signer = CaliptraDpeSigner::new(signer_scratch);

    println!("Enumerate HPKE handles...");
    let mut handles_resp = OcpLockEnumerateHpkeHandlesResp::default();
    ocp_lock
        .enumerate_hpke_handles(&mut handles_resp)
        .await
        .unwrap_or_else(|err| {
            println!("OCP_LOCK_ENUMERATE_HPKE_HANDLES failed with err {:?}", err);
            System::exit(1);
            unreachable!();
        });

    let handle = handles_resp.hpke_handles[..handles_resp.hpke_handle_count as usize]
        .iter()
        .find(|handle| handle.hpke_algorithm == HpkeAlgorithms::ECDH_P384_HKDF_SHA384_AES_256_GCM)
        .unwrap();

    match ocp_lock
        .get_hpke_public_key_x509(handle, &mut cert_buf, &signer)
        .await
    {
        Ok(cert_len) => {
            println!(
                "OCP LOCK get HPKE public key x509 success, size {}",
                cert_len
            );
        }
        Err(err) => {
            println!(
                "OCP_LOCK_GET_HPKE_PUBLIC_KEY_X509 failed with err {:x?}",
                err
            );
            System::exit(1);
        }
    }

    println!("Test passed");
}
