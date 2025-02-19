
// Create a unit test to encode pldm packet header

#[cfg(test)]
mod test_packet_codec {
    use pldm_common::protocol::base::{PldmMsgHeader, PldmMsgType, PldmControlCmd, PldmSupportedType};
    use pldm_fw::GetStatusResponse;
    #[test]
    fn test_encode_header() {
        // create a header
        let header = PldmMsgHeader::new(
            0x0a,
            PldmMsgType::Request,
            PldmSupportedType::FwUpdate,
            PldmControlCmd::GetPldmTypes as u8
        );
        // Print bytes as hex
        let raw_bytes = header.0;
        println!(
            "Hex Dump: {}",
            raw_bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<String>>().join(" ")
        );
        
        // Expected header bytes : 2a 05 04

        // Expected header to be size 3 only (from rq to command code)
        assert_eq!(raw_bytes.len(), 3);

        // Expect byte0 to be 0x2a
        assert_eq!(raw_bytes[0], 0x2a);

        // Expect byte1 to be 0x05
        assert_eq!(raw_bytes[1], 0x05);

        // Expect byte2 to be 0x04
        assert_eq!(raw_bytes[2], 0x04);


    }
}
