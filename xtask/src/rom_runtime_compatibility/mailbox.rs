// Licensed under the Apache-2.0 license

use anyhow::{bail, ensure, Context as _, Result};
use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, fs, path::Path};

const MESSAGES: &str = "common/mcu-mbox/src/messages.rs";
const DISPATCHER: &str = "runtime/userspace/api/mcu-mbox-lib/src/cmd_interface.rs";
const ENVELOPE: &str = "runtime/userspace/api/caliptra-common-commands/src/command.rs";
const OTP_USER: &str = "runtime/userspace/syscall/src/otp.rs";
const OTP_KERNEL: &str = "runtime/kernel/capsules/src/otp.rs";

/// Derive release-specific mailbox layouts and authorization framing.
pub(super) fn expectations(
    repo: &Path,
    checkout: &Path,
    runtime_version: &str,
    capabilities: &[u8],
) -> Result<Value> {
    let mut provenance = Map::new();
    let result = derive(
        repo,
        checkout,
        runtime_version,
        capabilities,
        &mut provenance,
    );
    Ok(match result {
        Ok(mut expected) => {
            expected["status"] = json!("SUPPORTED");
            expected["provenance"] = Value::Object(provenance);
            expected
        }
        Err(error) => json!({
            "status": "BLOCKED",
            "reason": format!("Selected mailbox source contract is unresolved: {error:#}"),
            "provenance": provenance,
        }),
    })
}

fn source(
    root: &Path,
    relative: &str,
    key: &str,
    evidence: &mut Map<String, Value>,
) -> Result<String> {
    let path = root.join(relative);
    let text = fs::read_to_string(&path)
        .with_context(|| format!("missing readable source {}", path.display()))?;
    evidence.insert(
        key.to_string(),
        json!({"path": path, "sha256": super::sha256(&path)?}),
    );
    Ok(text)
}

pub(super) fn compact(source: &str) -> String {
    source
        .lines()
        .map(|line| line.split("//").next().unwrap_or_default())
        .flat_map(str::chars)
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn expression<'a>(source: &'a str, name: &str) -> Result<&'a str> {
    let prefix = format!("{name}:");
    let declarations: Vec<_> = source
        .split("pubconst")
        .skip(1)
        .filter(|declaration| declaration.starts_with(&prefix))
        .collect();
    ensure!(
        declarations.len() == 1,
        "unknown or duplicate constant {name}"
    );
    declarations[0]
        .split_once('=')
        .and_then(|(_, value)| value.split_once(';'))
        .map(|(value, _)| value)
        .with_context(|| format!("unknown constant expression for {name}"))
}

fn number(value: &str) -> Result<u32> {
    let value = value.replace('_', "");
    Ok(if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex, 16)?
    } else {
        value.parse()?
    })
}

fn command_ids(source: &str) -> Result<BTreeMap<String, u32>> {
    let mut ids = BTreeMap::new();
    for declaration in source.split("pubconst").skip(1) {
        let Some((name, _)) = declaration.split_once(':') else {
            continue;
        };
        if !name.starts_with("MC_") {
            continue;
        }
        let value = expression(source, name)?;
        let literal = value
            .strip_prefix("Self(")
            .and_then(|value| value.strip_suffix(')'))
            .with_context(|| format!("nonliteral command ID {name}"))?;
        ensure!(
            ids.insert(name.to_string(), number(literal)?).is_none(),
            "duplicate command ID symbol {name}"
        );
    }
    ensure!(!ids.is_empty(), "no selected MCU command IDs");
    Ok(ids)
}

pub(super) fn declaration(source: &str, kind: &str, name: &str) -> Result<String> {
    let prefix = format!("pub{kind}{name}");
    let start = source
        .find(&format!("{prefix}{{"))
        .or_else(|| source.find(&format!("{prefix}(")))
        .with_context(|| format!("missing {kind} {name}"))?;
    let rest = &source[start + prefix.len()..];
    if rest.starts_with('(') {
        let end = rest.find(';').context("unterminated tuple declaration")?;
        return Ok(rest[..end].to_string());
    }
    ensure!(rest.starts_with('{'), "unknown declaration of {name}");
    let mut depth = 0usize;
    for (index, character) in rest.char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(rest[..=index].to_string());
                }
            }
            _ => {}
        }
    }
    bail!("unterminated declaration of {name}")
}

fn derive(
    repo: &Path,
    checkout: &Path,
    runtime_version: &str,
    capabilities: &[u8],
    evidence: &mut Map<String, Value>,
) -> Result<Value> {
    ensure!(
        !runtime_version.is_empty(),
        "missing selected runtime version"
    );
    source(checkout, "Cargo.toml", "runtime_manifest", evidence)?;
    source(checkout, "Cargo.lock", "runtime_lock", evidence)?;
    let messages = compact(&source(checkout, MESSAGES, "messages", evidence)?);
    let dispatcher = compact(&source(checkout, DISPATCHER, "dispatcher", evidence)?);
    let otp_user = compact(&source(checkout, OTP_USER, "otp_syscall", evidence)?);
    let otp_kernel = compact(&source(checkout, OTP_KERNEL, "otp_kernel", evidence)?);
    let ids = command_ids(&messages)?;
    let current_messages = compact(&source(repo, MESSAGES, "harness_messages", evidence)?);
    let current_ids = command_ids(&current_messages)?;
    let caps_size = number(expression(&messages, "DEVICE_CAPS_SIZE")?)? as usize;
    ensure!(
        capabilities.len() + 16 == caps_size,
        "capability suffix length disagrees with source"
    );
    ensure!(
        expression(&messages, "MAX_FW_VERSION_STR_LEN")?
            == expression(&current_messages, "MAX_FW_VERSION_STR_LEN")?,
        "unknown firmware-version response string bound"
    );
    for name in [
        "FirmwareVersionReq",
        "FirmwareVersionResp",
        "DeviceCapsResp",
        "GetAuthCmdChallengeReq",
        "GetAuthCmdChallengeResp",
    ] {
        ensure!(
            declaration(&messages, "struct", name)?
                == declaration(&current_messages, "struct", name)?,
            "unknown selected MCU response/request declaration {name}"
        );
    }
    let has_envelope = ids.contains_key("MC_AUTHORIZED_COMMAND");
    let abi = match (caps_size, has_envelope) {
        (36, false) => {
            ensure!(
                dispatcher.contains("CommandId::MC_GET_AUTH_CMD_CHALLENGE=>")
                    && dispatcher.contains("GetAuthCmdChallengeReq::ref_from_bytes(req)"),
                "unknown legacy direct challenge dispatcher"
            );
            if checkout.join(ENVELOPE).is_file() {
                source(checkout, ENVELOPE, "authorized_envelope", evidence)?;
            } else {
                evidence.insert(
                    "authorized_envelope".into(),
                    json!({
                        "path": checkout.join(ENVELOPE), "present": false, "required": false,
                    }),
                );
            }
            "legacy36_direct"
        }
        (64, true) => {
            let envelope = compact(&source(
                checkout,
                ENVELOPE,
                "authorized_envelope",
                evidence,
            )?);
            ensure!(
                dispatcher.contains("CommandId::MC_AUTHORIZED_COMMAND=>")
                    && dispatcher
                        .contains("resp_buf[..size_of::<MailboxRespHeaderVarSize>()].fill(0)")
                    && envelope.contains("iftarget_id==CommandId::MC_GET_AUTH_CMD_CHALLENGE.0{")
                    && envelope.contains("if!request.is_empty(){"),
                "unknown authorized challenge request/response framing"
            );
            "capabilities64_envelope"
        }
        _ => bail!("unrecognized capability/authorization ABI"),
    };
    for name in [
        "MC_FIRMWARE_VERSION",
        "MC_DEVICE_CAPABILITIES",
        "MC_GET_AUTH_CMD_CHALLENGE",
    ] {
        ensure!(
            ids.get(name).is_some() && ids.get(name) == current_ids.get(name),
            "unsupported selected ID {name}"
        );
    }
    if has_envelope {
        ensure!(
            ids.get("MC_AUTHORIZED_COMMAND") == current_ids.get("MC_AUTHORIZED_COMMAND"),
            "unsupported authorization envelope ID"
        );
    }
    let status_names = ["MC_FE_STATUS", "MC_VENDOR_PK_HASH_STATUS", "MC_HEK_STATUS"];
    let present = status_names
        .iter()
        .filter(|name| ids.contains_key(**name))
        .count();
    let provisioning_status = match present {
        0 => json!("unavailable_in_source"),
        3 => {
            for name in status_names {
                ensure!(
                    ids.get(name) == current_ids.get(name)
                        && dispatcher.contains(&format!("CommandId::{name}=>")),
                    "unknown provisioning-status dispatch for {name}"
                );
            }
            ensure!(
                number(expression(&messages, "VENDOR_PQC_KEY_TYPE_LMS")?)? == 1
                    && otp_user.contains("pubfnhek_status(")
                    && otp_user.contains("self.get_hek_metadata()?")
                    && otp_kernel.contains("fnget_hek_metadata(")
                    && otp_kernel.contains("CommandReturn::failure(ErrorCode::NOSUPPORT)"),
                "unknown fixture/status encoding or OCP-lock backend prerequisite"
            );
            let mut types = [0u8; 16];
            types[0] = 1;
            json!({"supported": {
                "field_entropy_provisioned": 0, "vendor_used_slots": 1,
                "vendor_key_types": types, "hek": "unavailable_in_configuration",
            }})
        }
        _ => bail!("partial/unknown provisioning-status command family"),
    };
    evidence.insert(
        "agreed_configuration_prerequisites".into(),
        json!({
            "vendor_hash_slot": 0, "vendor_pqc": "LMS",
            "field_entropy_unprogrammed": true, "ocp_lock": false,
            "note": "Caller must verify these against retained build/OTP metadata before execution."
        }),
    );
    Ok(json!({
        "runtime_version": runtime_version, "mcu_capabilities": capabilities,
        "abi": abi,
        "command_ids": ids, "provisioning_status": provisioning_status,
    }))
}
