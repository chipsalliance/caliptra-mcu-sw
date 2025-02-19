
// Create a unit test to encode pldm packet header
#[cfg(test)]
mod test_packet_codec {
    use pldm_common::protocol::base::{PldmMsgHeader, PldmMsgType, PldmControlCmd, PldmSupportedType};
    #[test]
    fn test_encode_header() {
        // create a header
        let header = PldmMsgHeader::new(
            0xFF,
            PldmMsgType::Request,
            PldmSupportedType::Base,
            PldmControlCmd::GetPldmVersion as u8
        );

        // encode the header
        println!("Header: {:?}", header[0]);
        println!("Header: {:?}", header[1]);
        println!("Header: {:?}", header[2]);
        println!("Header: {:?}", header[3]);
        
    }
}
