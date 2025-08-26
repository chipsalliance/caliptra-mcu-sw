// Licensed under the Apache-2.0 license
use crate::codec::{Codec, CodecError, CodecResult, CommonCodec, MessageBuf};
use crate::protocol::*;
use bitfield::bitfield;
use core::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes};

const MAX_SEC_MSG_VERSION_COUNT: usize = 4;
const MIN_VERSION_DATA_LEN: u16 = 1 + 1 + size_of::<SmVersion>() as u16; // sm_data_version + sm_data_id + at least one SmVersion
const DATA_ID_SUPPORTED_VERSION_LIST: u8 = 1;
const DATA_ID_VERSION_SELECTION: u8 = 0;

pub(crate) struct SmOpaqueElementHdr {
    pub(crate) hdr: OpaqueElementHdr,
    pub(crate) data_hdr: SmOpaqueElementDataHdr,
}

impl Codec for SmOpaqueElementHdr {
    fn encode(&self, buf: &mut MessageBuf<'_>) -> CodecResult<usize> {
        let mut len = self.hdr.encode(buf)?;
        len += self.data_hdr.encode(buf)?;

        Ok(len)
    }

    fn decode(buf: &mut MessageBuf<'_>) -> CodecResult<Self> {
        let hdr = OpaqueElementHdr::decode(buf)?;
        let data_hdr = SmOpaqueElementDataHdr::decode(buf)?;

        Ok(SmOpaqueElementHdr { hdr, data_hdr })
    }
}

#[derive(Debug)]
pub(crate) struct SmOpaqueElementDataHdr {
    sm_data_version: u8,
    sm_data_id: u8,
}

impl Codec for SmOpaqueElementDataHdr {
    fn encode(&self, buf: &mut MessageBuf<'_>) -> CodecResult<usize> {
        let mut len = self.sm_data_version.encode(buf)?;
        len += self.sm_data_id.encode(buf)?;
        Ok(len)
    }

    fn decode(buf: &mut MessageBuf<'_>) -> CodecResult<Self> {
        let sm_data_version = u8::decode(buf)?;
        let sm_data_id = u8::decode(buf)?;
        Ok(SmOpaqueElementDataHdr {
            sm_data_version,
            sm_data_id,
        })
    }
}
#[derive(Debug)]
pub(crate) struct SmVersionList {
    pub version_count: u8,
    pub versions: [SmVersion; MAX_SEC_MSG_VERSION_COUNT],
}

impl Default for SmVersionList {
    fn default() -> Self {
        SmVersionList {
            version_count: 0,
            versions: [SmVersion(0); MAX_SEC_MSG_VERSION_COUNT],
        }
    }
}

impl SmVersionList {
    pub fn len(&self) -> usize {
        // 1 byte for version_count + 2 bytes per SmVersion
        1 + (self.version_count as usize) * core::mem::size_of::<SmVersion>()
    }
}

impl Codec for SmVersionList {
    fn encode(&self, buf: &mut MessageBuf<'_>) -> CodecResult<usize> {
        let mut len = self.version_count.encode(buf)?;
        for version in &self.versions[..self.version_count as usize] {
            len += version.encode(buf)?;
        }
        Ok(len)
    }

    fn decode(buf: &mut MessageBuf<'_>) -> CodecResult<Self> {
        let version_count = u8::decode(buf)?;
        if version_count > MAX_SEC_MSG_VERSION_COUNT as u8 {
            return Err(CodecError::BufferOverflow);
        }

        let mut versions = [SmVersion(0); MAX_SEC_MSG_VERSION_COUNT];
        versions
            .iter_mut()
            .take(version_count as usize)
            .try_for_each(|v| {
                *v = SmVersion::decode(buf)?;
                Ok(())
            })?;

        Ok(SmVersionList {
            version_count,
            versions,
        })
    }
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable, Default, Clone, Copy)]
    #[repr(C)]
    pub struct SmVersion(u16);
    impl Debug;
    u8;
    pub alpha, set_alpha: 3,0;
    pub update_version_number, set_update_version_number: 7,4;
    pub minor_version, set_minor_version: 11,8;
    pub major_version, set_major_version: 15,12;
}

impl CommonCodec for SmVersion {}

pub(crate) fn sm_select_version_from_list(
    mut opaque_data: OpaqueData,
    local_sec_msg_version_list: &[SpdmVersion],
) -> OpaqueDataResult<SmVersion> {
    opaque_data.validate_general_opaque_data_format()?;

    let min_ver_list_data_size = min_secure_version_list_size();
    let min_opaque_data_len = size_of::<GeneralOpaqueDataHdr>() + min_ver_list_data_size;

    if min_opaque_data_len > opaque_data.len as usize {
        return Err(OpaqueDataError::InvalidFormat);
    }

    let mut opaque_data_buf = MessageBuf::from(&mut opaque_data.data[..opaque_data.len as usize]);
    let opaque_data_hdr = GeneralOpaqueDataHdr::decode(&mut opaque_data_buf)
        .map_err(|_| OpaqueDataError::InvalidFormat)?;
    if opaque_data_hdr.total_elements != 1 {
        return Err(OpaqueDataError::InvalidFormat);
    }

    let _hdr = OpaqueElementHdr::decode(&mut opaque_data_buf)
        .map_err(|_| OpaqueDataError::InvalidFormat)?;

    let version_list_data_hdr = SmOpaqueElementDataHdr::decode(&mut opaque_data_buf)
        .map_err(|_| OpaqueDataError::InvalidFormat)?;

    if version_list_data_hdr.sm_data_version != 1
        || version_list_data_hdr.sm_data_id != DATA_ID_SUPPORTED_VERSION_LIST
    {
        return Err(OpaqueDataError::InvalidFormat);
    }

    let version_list =
        SmVersionList::decode(&mut opaque_data_buf).map_err(|_| OpaqueDataError::InvalidFormat)?;

    if version_list.version_count == 0
        || version_list.version_count as usize > MAX_SEC_MSG_VERSION_COUNT
    {
        return Err(OpaqueDataError::InvalidFormat);
    }

    select_secure_version(&version_list, local_sec_msg_version_list)
}

pub(crate) fn sm_selected_version_opaque_data(
    sel_sm_version: SmVersion,
) -> OpaqueDataResult<OpaqueData> {
    let mut opaque_data = OpaqueData::default();
    let mut opaque_data_buf = MessageBuf::new(&mut opaque_data.data[..]);
    let opaque_data_hdr = GeneralOpaqueDataHdr::new(1);

    let opaque_elem_hdr =
        OpaqueElementHdr::new(StandardsBodyId::Dmtf as u8, 0, None, MIN_VERSION_DATA_LEN);
    let sm_opaque_elem_data_hdr = SmOpaqueElementDataHdr {
        sm_data_version: 1,
        sm_data_id: DATA_ID_VERSION_SELECTION,
    };
    let sm_opaque_elem_hdr = SmOpaqueElementHdr {
        hdr: opaque_elem_hdr,
        data_hdr: sm_opaque_elem_data_hdr,
    };

    let mut opaque_data_len = opaque_data_hdr
        .encode(&mut opaque_data_buf)
        .map_err(OpaqueDataError::Codec)?;

    opaque_data_len += sm_opaque_elem_hdr
        .encode(&mut opaque_data_buf)
        .map_err(OpaqueDataError::Codec)?;
    opaque_data_len += sel_sm_version
        .encode(&mut opaque_data_buf)
        .map_err(OpaqueDataError::Codec)?;

    opaque_data.len = opaque_data_len as u16;
    Ok(opaque_data)
}

fn select_secure_version(
    sec_msg_versions: &SmVersionList,
    local_sec_msg_version_list: &[SpdmVersion],
) -> OpaqueDataResult<SmVersion> {
    let mut max_version: Option<SmVersion> = None;
    for version in &sec_msg_versions.versions[..sec_msg_versions.version_count as usize] {
        let ver: SpdmVersion = SpdmVersion::new(version.major_version(), version.minor_version())
            .map_err(|_| OpaqueDataError::InvalidFormat)?;
        if local_sec_msg_version_list.contains(&ver) {
            if let Some(current_max) = max_version {
                if version.minor_version() > current_max.minor_version() {
                    max_version = Some(*version);
                }
            } else {
                max_version = Some(*version);
            }
        }
    }

    if let Some(selected) = max_version {
        Ok(selected)
    } else {
        Err(OpaqueDataError::InvalidFormat)
    }
}

fn min_secure_version_list_size() -> usize {
    // We need a min of 1 version in the list
    let sm_version = SmVersion::default();
    let mut sm_version_list = SmVersionList {
        version_count: 1,
        ..Default::default()
    };
    sm_version_list.versions[0] = sm_version;

    let sm_version_list_data_len = sm_version_list.len();

    let sm_version_opaque_elem_hdr =
        OpaqueElementHdr::new(StandardsBodyId::Dmtf as u8, 0, None, MIN_VERSION_DATA_LEN);

    sm_version_opaque_elem_hdr.len()
        + size_of::<SmOpaqueElementDataHdr>()
        + sm_version_list_data_len
}
