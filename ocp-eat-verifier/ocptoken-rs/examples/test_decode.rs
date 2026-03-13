fn main() {
    let data = std::fs::read("/tmp/test_corim_payload.cbor").unwrap();
    match corim_rs::Corim::from_cbor(data.as_slice()) {
        Ok(corim) => {
            println!("Decoded successfully!");
            let map = corim.into_map();
            println!("ID: {:?}", map.id);
            println!("Profile: {:?}", map.profile);
            println!("Tags: {}", map.tags.len());
        }
        Err(e) => {
            eprintln!("Decode error: {:?}", e);
        }
    }
}
