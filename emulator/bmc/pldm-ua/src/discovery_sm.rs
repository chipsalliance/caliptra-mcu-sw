use crate::transport::{PldmSocket, RxPacket, MAX_PLDM_PAYLOAD_SIZE};
use log::{debug, error};
use pldm_common::codec::PldmCodec;
use pldm_common::message::control::{self as pldm_packet, is_bit_set, GetPldmCommandsRequest};
use pldm_common::protocol::base::{InstanceId, PldmBaseCompletionCode, PldmControlCmd, PldmMsgHeader, PldmMsgType, PldmSupportedType, TransferOperationFlag, TransferRespFlag};
use pldm_common::protocol::firmware_update::FwUpdateCmd;
use pldm_common::protocol::version::{PLDM_BASE_PROTOCOL_VERSION, PLDM_FW_UPDATE_PROTOCOL_VERSION};
use smlang::statemachine;

#[derive(Debug, Clone, Default)]
pub enum DiscoveryAgentEvents {
    Sm(Events),
    #[default]
    Rx,
    DeferredTx,
}

// Define the state machine for PLDM Discovery Requester
statemachine! {
    derive_states: [Debug],
    derive_events: [Clone, Debug],
    transitions: {
        *Idle + StartDiscovery / on_start_discovery = GetTIDSent,

        GetTIDSent + GetTIDResponse(pldm_packet::GetTidResponse) / on_tid_response = GetPLDMTypesSent,

        GetPLDMTypesSent + GetPLDMTypesResponse(pldm_packet::GetPldmTypeResponse) [is_valid_pldm_types_response0] / on_pldm_types_response = GetPLDMVersionType0Sent,

        GetPLDMVersionType0Sent + GetPLDMVersionResponse(pldm_packet::GetPldmVersionResponse) [is_pldm_version_response_valid] / on_pldm_version_response_type0 = GetPLDMCommandsType0Sent,

        GetPLDMCommandsType0Sent + GetPLDMCommandsResponse(pldm_packet::GetPldmCommandsResponse)  [is_pldm_commands_response_type0_valid] / on_pldm_commands_response_type0 = GetPLDMVersionType5Sent,

        GetPLDMVersionType5Sent + GetPLDMVersionResponse(pldm_packet::GetPldmVersionResponse) [is_pldm_version_response_valid] / on_pldm_version_response_type5 = GetPLDMCommandsType5Sent,

        GetPLDMCommandsType5Sent + GetPLDMCommandsResponse(pldm_packet::GetPldmCommandsResponse) [is_pldm_commands_response_type5_valid] / on_pldm_commands_response_type5 = Done,

        _ + CancelDiscovery / on_cancel_discovery = Done
    }
}

fn send_helper<S: PldmSocket, P: PldmCodec>(socket: &S, message: &P) -> Result<(), ()> {
    let mut buffer = [0u8; MAX_PLDM_PAYLOAD_SIZE];
    let sz = message.encode(&mut buffer).map_err(|_| ())?;
    socket.send(&buffer[..sz]).map_err(|_| ())?;
    Ok(())
}

pub trait StateMachineActions {
    // Actions
    fn on_start_discovery(&self, ctx: &InnerContext<impl PldmSocket>) -> Result<(), ()> {
        debug!("on_start_discovery");
        send_helper(&ctx.socket,&pldm_packet::GetTidRequest::new(ctx.instance_id, PldmMsgType::Request))

    }
    fn on_tid_response(
        &self,
        ctx: &mut InnerContext<impl PldmSocket>,
        response: pldm_packet::GetTidResponse,
    ) -> Result<(), ()> {
        debug!("on_tid_response : {:?}", response);
        ctx.instance_id +=1;
        send_helper(&ctx.socket,&pldm_packet::GetPldmTypeRequest::new(ctx.instance_id, PldmMsgType::Request))
    }
    fn on_pldm_types_response(
        &self,
        ctx: &mut InnerContext<impl PldmSocket>,
        _response: pldm_packet::GetPldmTypeResponse,
    ) -> Result<(), ()> {
        debug!("on_pldm_types_response");
        ctx.instance_id +=1;
        send_helper(&ctx.socket,& pldm_packet::GetPldmVersionRequest::new(
            ctx.instance_id, 
            PldmMsgType::Request, 
            0, // data_transfer_handle
            TransferOperationFlag::GetFirstPart,
            PldmSupportedType::Base,
        ))

    }
    fn on_pldm_version_response_type0(
        &self,
        ctx: &mut InnerContext<impl PldmSocket>,
        _response: pldm_packet::GetPldmVersionResponse,
    ) -> Result<(), ()> {
        debug!("on_pldm_version_response_type0");
        
        ctx.instance_id +=1;
        send_helper(&ctx.socket, &GetPldmCommandsRequest::new(
            ctx.instance_id,
            PldmMsgType::Request,
            PldmSupportedType::Base as u8,
            PLDM_BASE_PROTOCOL_VERSION,
        ))


    }
    fn on_pldm_commands_response_type0(
        &self,
        ctx: &mut InnerContext<impl PldmSocket>,
        _response: pldm_packet::GetPldmCommandsResponse,
    ) -> Result<(), ()> {
        debug!("on_pldm_commands_response_type0");
        ctx.instance_id +=1;
        send_helper(&ctx.socket,& pldm_packet::GetPldmVersionRequest::new(
            ctx.instance_id, 
            PldmMsgType::Request, 
            0, // data_transfer_handle
            TransferOperationFlag::GetFirstPart,
            PldmSupportedType::FwUpdate,
        ))
    }
    fn on_pldm_version_response_type5(
        &self,
        ctx: &mut InnerContext<impl PldmSocket>,
        _response: pldm_packet::GetPldmVersionResponse,
    ) -> Result<(), ()> {
        debug!("on_pldm_version_response_type5");
        ctx.instance_id +=1;
        send_helper(&ctx.socket, &GetPldmCommandsRequest::new(
            ctx.instance_id,
            PldmMsgType::Request,
            PldmSupportedType::FwUpdate as u8,
            PLDM_FW_UPDATE_PROTOCOL_VERSION,
        ))
    }
    fn on_pldm_commands_response_type5(
        &self,
        _ctx: &mut InnerContext<impl PldmSocket>,
        _response: pldm_packet::GetPldmCommandsResponse,
    ) -> Result<(), ()> {
        debug!("on_pldm_commands_response_type5");
        Ok(())
    }
    fn on_cancel_discovery(&self, _ctx: &mut InnerContext<impl PldmSocket>) -> Result<(), ()> {
        debug!("on_cancel_discovery");
        Ok(())
    }

    // Guards
    fn is_valid_pldm_types_response0(
        &self,
        ctx: &InnerContext<impl PldmSocket>,
        response: &pldm_packet::GetPldmTypeResponse,
    ) -> Result<bool, ()> {
        debug!("is_valid_pldm_types_response0");

        // Verify correct instance id
        if response.hdr.instance_id() != ctx.instance_id {
            return Ok(false);
        }

        // Verify completion code is successful
        if response.completion_code != PldmBaseCompletionCode::Success as u8 {
            return Ok(false);
        }

        // Verify both base and fwupdate pldm types are supported
        if is_bit_set(&response.pldm_types, PldmSupportedType::Base as u8)
            && is_bit_set(&response.pldm_types, PldmSupportedType::FwUpdate as u8)
        {
            return Ok(true);
        }
        Ok(false)
        
    }
    fn is_pldm_version_response_valid(
        &self,
        ctx: &InnerContext<impl PldmSocket>,
        response: &pldm_packet::GetPldmVersionResponse,
    ) -> Result<bool, ()> {
        debug!("is_pldm_version_response_valid");

        // Verify correct instance id
        if response.hdr.instance_id() != ctx.instance_id {
            return Ok(false);
        }

        // Verify completion code is successful
        if response.completion_code != PldmBaseCompletionCode::Success as u8 {
            return Ok(false);
        }

        // Verify transfer flag
        if response.transfer_rsp_flag != TransferRespFlag::StartAndEnd as u8 {
            return Ok(false);
        }

        Ok(true)
    }
    fn is_pldm_commands_response_type0_valid(
        &self,
        ctx: &InnerContext<impl PldmSocket>,
        response: &pldm_packet::GetPldmCommandsResponse,
    ) -> Result<bool, ()> {
        debug!("is_pldm_commands_response_type0_valid");
        // Verify correct instance id
        if response.hdr.instance_id() != ctx.instance_id {
            return Ok(false);
        }
        if response.completion_code != PldmBaseCompletionCode::Success as u8 {
            return Ok(false);
        }
        let supported_cmds = [
            PldmControlCmd::GetTid,
            PldmControlCmd::SetTid,
            PldmControlCmd::GetPldmTypes,
            PldmControlCmd::GetPldmVersion,
            PldmControlCmd::GetPldmCommands,
        ];
        for cmd in supported_cmds {
            if !is_bit_set(&response.supported_cmds, cmd as u8) {
                return Ok(false);
            }
        }
        Ok(true)

    }
    fn is_pldm_commands_response_type5_valid(
        &self,
        ctx: &InnerContext<impl PldmSocket>,
        response: &pldm_packet::GetPldmCommandsResponse,
    ) -> Result<bool, ()> {
        debug!("is_pldm_commands_response_type5_valid");
        // Verify correct instance id
        if response.hdr.instance_id() != ctx.instance_id {
            return Ok(false);
        }
        if response.completion_code != PldmBaseCompletionCode::Success as u8 {
            return Ok(false);
        }
        if response.hdr.instance_id() != ctx.instance_id {
            return Ok(false);
        }
        if response.completion_code != PldmBaseCompletionCode::Success as u8 {
            return Ok(false);
        }
        let supported_cmds = [
            FwUpdateCmd::QueryDeviceIdentifiers,
            FwUpdateCmd::GetFirmwareParameters,
            FwUpdateCmd::RequestUpdate,
            FwUpdateCmd::PassComponentTable,
            FwUpdateCmd::UpdateComponent,
            FwUpdateCmd::RequestFirmwareData,
            FwUpdateCmd::TransferComplete,
            FwUpdateCmd::VerifyComplete,
            FwUpdateCmd::ApplyComplete,
            FwUpdateCmd::ActivateFirmware,
            FwUpdateCmd::GetStatus,
            FwUpdateCmd::CancelUpdateComponent,
            FwUpdateCmd::CancelUpdate,
        ];
        for cmd in supported_cmds {
            if !is_bit_set(&response.supported_cmds, cmd as u8) {
                return Ok(false);
            }
        }
       
        Ok(true)
    }    
}

fn is_response<S: AsRef<[u8]>>(pldm_packet: &PldmMsgHeader<S>) -> bool {
    pldm_packet.rq() == 0 && pldm_packet.datagram() == 0
}

pub fn process_packet(packet: &RxPacket) -> Result<DiscoveryAgentEvents, ()> {
    debug!("Handling packet: {}", packet);
    let header = PldmMsgHeader::decode(&packet.payload.data[..packet.payload.len])
        .map_err(|_| (error!("Error decoding packet!")))?;
    if !header.is_hdr_ver_valid() {
        error!("Invalid header version!");
        return Err(());
    }

    match PldmControlCmd::try_from(header.cmd_code()) {
        Ok(cmd) => {
            debug!("Command: {:?}", cmd);
            match cmd {
                PldmControlCmd::GetTid => {
                    debug!("GetTID command");
                    if !is_response(&header) {
                        error!("Not a GetTid response");
                        return Err(());
                    }
                    Ok(DiscoveryAgentEvents::Sm(Events::GetTIDResponse(
                        pldm_packet::GetTidResponse::decode(
                            &packet.payload.data[..packet.payload.len],
                        )
                        .map_err(|_| ())?,
                    )))
                }
                PldmControlCmd::GetPldmTypes => {
                    debug!("GetPLDMTypes command");
                    if !is_response(&header) {
                        error!("Not a GetPldmTypes response");
                        return Err(());
                    }
                    Ok(DiscoveryAgentEvents::Sm(Events::GetPLDMTypesResponse(
                        pldm_packet::GetPldmTypeResponse::decode(
                            &packet.payload.data[..packet.payload.len],
                        )
                        .map_err(|_| ())?,
                    )))
                }
                PldmControlCmd::GetPldmVersion => {
                    debug!("GetPLDMVersion command");
                    if !is_response(&header) {
                        error!("Not a GetPldmVersion response");
                        return Err(());
                    }
                    Ok(DiscoveryAgentEvents::Sm(Events::GetPLDMVersionResponse(
                        pldm_packet::GetPldmVersionResponse::decode(
                            &packet.payload.data[..packet.payload.len],
                        )
                        .map_err(|_| ())?,
                    )))
                }
                PldmControlCmd::GetPldmCommands => {
                    debug!("GetPLDMCommands command");
                    if !is_response(&header) {
                        error!("Not a GetPldmCommands response");
                        return Err(());
                    }
                    Ok(DiscoveryAgentEvents::Sm(Events::GetPLDMCommandsResponse(
                        pldm_packet::GetPldmCommandsResponse::decode(
                            &packet.payload.data[..packet.payload.len],
                        )
                        .map_err(|_| ())?,
                    )))
                }
                _ => {
                    error!("Unknown discovery command");
                    Err(())
                }
            }
        }
        Err(_) => Err(()),
    }
}
// Implement the context struct
pub struct DefaultActions;
impl StateMachineActions for DefaultActions {}

pub struct InnerContext<S: PldmSocket> {
    socket: S,
    instance_id: InstanceId,
}

pub struct Context<T: StateMachineActions, S: PldmSocket> {
    inner: T,
    inner_ctx: InnerContext<S>,
}

impl<T: StateMachineActions, S: PldmSocket> Context<T, S> {
    pub fn new(context: T, socket: S) -> Self {
        Self {
            inner: context,
            inner_ctx: InnerContext {
                socket,
                instance_id: 0,
            },
        }
    }
}

impl<T: StateMachineActions, S: PldmSocket> StateMachineContext for Context<T, S> {
    // Actions
    fn on_start_discovery(&mut self) -> Result<(), ()> {
        self.inner.on_start_discovery(&mut self.inner_ctx)
    }
    fn on_tid_response(&mut self, response: pldm_packet::GetTidResponse) -> Result<(), ()> {
        self.inner.on_tid_response(&mut self.inner_ctx, response)
    }
    fn on_pldm_types_response(
        &mut self,
        response: pldm_packet::GetPldmTypeResponse,
    ) -> Result<(), ()> {
        self.inner
            .on_pldm_types_response(&mut self.inner_ctx, response)
    }
    fn on_pldm_version_response_type0(
        &mut self,
        response: pldm_packet::GetPldmVersionResponse,
    ) -> Result<(), ()> {
        self.inner
            .on_pldm_version_response_type0(&mut self.inner_ctx, response)
    }
    fn on_pldm_commands_response_type0(
        &mut self,
        response: pldm_packet::GetPldmCommandsResponse,
    ) -> Result<(), ()> {
        self.inner
            .on_pldm_commands_response_type0(&mut self.inner_ctx, response)
    }
    fn on_pldm_version_response_type5(
        &mut self,
        response: pldm_packet::GetPldmVersionResponse,
    ) -> Result<(), ()> {
        self.inner
            .on_pldm_version_response_type5(&mut self.inner_ctx, response)
    }
    fn on_pldm_commands_response_type5(
        &mut self,
        response: pldm_packet::GetPldmCommandsResponse,
    ) -> Result<(), ()> {
        self.inner
            .on_pldm_commands_response_type5(&mut self.inner_ctx, response)
    }
    fn on_cancel_discovery(&mut self) -> Result<(), ()> {
        self.inner.on_cancel_discovery(&mut self.inner_ctx)
    }

    // Guards
    fn is_valid_pldm_types_response0(
        &self,
        response: &pldm_packet::GetPldmTypeResponse,
    ) -> Result<bool, ()> {
        self.inner
            .is_valid_pldm_types_response0(&self.inner_ctx, response)
    }
    fn is_pldm_version_response_valid(
        &self,
        response: &pldm_packet::GetPldmVersionResponse,
    ) -> Result<bool, ()> {
        self.inner
            .is_pldm_version_response_valid(&self.inner_ctx, response)
    }
    fn is_pldm_commands_response_type0_valid(
        &self,
        response: &pldm_packet::GetPldmCommandsResponse,
    ) -> Result<bool, ()> {
        self.inner
            .is_pldm_commands_response_type0_valid(&self.inner_ctx, response)
    }
    fn is_pldm_commands_response_type5_valid(
        &self,
        response: &pldm_packet::GetPldmCommandsResponse,
    ) -> Result<bool, ()> {
        self.inner
            .is_pldm_commands_response_type5_valid(&self.inner_ctx, response)
    }
}
