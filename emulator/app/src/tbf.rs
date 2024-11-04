// Licensed under the Apache-2.0 license

// Make a Tock binary format (TBF) from the given application raw binary.
pub(crate) fn make_tbf(app_raw_binary: Vec<u8>) -> Vec<u8> {
    let len = 0x60 + app_raw_binary.len();
    let mut tbf = Vec::new();
    tbf.extend_from_slice(&[0; 0x60]); // TBF header
    tbf.extend_from_slice(&app_raw_binary);

    tbf[0] = 2;
    tbf[2] = 0x60;
    tbf[4..8].copy_from_slice((len as u32).to_le_bytes().as_ref());
    tbf[8] = 1;
    // Program Header
    tbf[16] = 9; // tag
    tbf[18] = 20; // length
    tbf[20] = 0x20; // offset of _start
    tbf[28..32].copy_from_slice(1024u32.to_le_bytes().as_ref()); // minimum RAM size

    tbf[32..36].copy_from_slice((len as u32).to_le_bytes().as_ref()); // binary end offset
    tbf[36..40].copy_from_slice(1u32.to_le_bytes().as_ref()); // app version

    let mut checksum = 0u32;
    for i in 0..(0x60 / 4) {
        checksum ^= u32::from_le_bytes(tbf[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    tbf[12..16].copy_from_slice(checksum.to_le_bytes().as_ref());
    tbf
}
