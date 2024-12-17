
use crate::i3c_socket::{TestState, TestTrait, receive_ibi, receive_private_read, send_private_write};

pub(crate) struct MctpLoopBackTest{
    test_name: String,
    state: TestState,
    write_pkts: VecDeque<Vec<u8>>,
    read_pkts: VecDeque<Vec<u8>>,
}

impl MctpLoopBackTest {
    

}