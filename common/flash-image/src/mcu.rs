use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
#[derive(Default, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct McuImageHeader {

    pub svn: u32,
}
