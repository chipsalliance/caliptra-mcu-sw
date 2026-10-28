// Licensed under the Apache-2.0 license

use anyhow::{bail, Context};
use caliptra_mcu_hw_model::DefaultHwModel;

#[cfg(not(feature = "fpga_realtime"))]
pub(crate) fn compatibility_attestation_support() -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "transport_required_feature": "spdm",
        "scope": ["ocp-eat-non-tcb", "ocp-eat-tcb", "ocp-eat-mixed", "pcr-quote"],
        "without_spdm": {"status": "NOT APPLICABLE", "reason": "Selected firmware has no SPDM transport"},
        "production_eat": {
            "status": "BLOCKED",
            "host_only_manifest_variants_sufficient": false,
            "missing_prerequisites": [
                "Provenance for the immutable binary's embedded attestation manifest, vendor/model, SoC firmware ID load list, TCB flags, and AK target",
                "Authenticated SoC payloads matching that embedded policy and a proven initial-load/measurement-completion boundary",
                "A selected production configuration that keeps the emulator serving SPDM after successful initial image loading",
                "Matching reference values and endorsement trust for every emitted component, plus a fresh requester nonce and retained evidence/appraisal results"
            ],
            "firmware_blockers": [
                "ImageCfg.is_tcb feeds generated build-time attestation_manifest.toml; signed authorization manifests cannot replace the compiled base attestation policy or SoC load list",
                "image_loading_task calls System::exit(0) after successful initial loading when firmware-update and the cold-boot attestation test features are absent; EmulatorExiter exits the emulator",
                "Test-only evidence readiness banners and test features that suppress the exit are absent from agreed production images"
            ],
            "owner_policy_alternative": {
                "availability": "Verify validate_and_set_owner_policy/manifest_lookup in each pinned source; not present in every release",
                "limitations": [
                    "A dynamic owner policy does not replace the compiled vendor policy/load topology or suppress the post-load emulator exit",
                    "Existing corim::read_evidence_components reads vendor AuthorizationManifest metadata, not owner policy/key/image reference values; owner appraisal is a distinct, unprepared fixture path"
                ]
            }
        },
        "pcr_quote": {
            "status": "NOT APPLICABLE",
            "provider_required_feature": "test-mctp-spdm-attestation-pcr-quote",
            "reason": "The selected immutable images lack the feature that switches measurement_provider from OCP EAT to PCR quote"
        },
        "source_checks": [
            {
                "path": "builder/src/attestation_manifest.rs",
                "symbols": ["config_source", "write_config_to_target_dir"],
                "role": "ImageCfg.is_tcb creates build inputs, not a mutable runtime policy"
            },
            {
                "path": "platforms/emulator/runtime/userspace/apps/user/build.rs",
                "symbols": ["write_attestation_manifest", "serialize_attestation_manifest", "write_soc_image_descriptors"],
                "role": "Embeds ATTESTATION_MANIFEST_BYTES and SOC_IMAGE_LOAD_LIST into userspace"
            },
            {
                "path": "platforms/emulator/runtime/userspace/apps/user/src/measurement/integrator_manifest.rs",
                "symbols": ["include!", "OUT_DIR"],
                "role": "Includes the generated static manifest in the binary"
            },
            {
                "path": "platforms/emulator/runtime/userspace/apps/user/src/measurement/boot.rs",
                "symbols": ["boot_init", "evidence_readiness_policy"],
                "role": "Production ReadyAfterBootInit is not proof of initial SoC measurement completion"
            },
            {
                "path": "runtime/userspace/api/measurement-api/src/api/mod.rs",
                "symbols": ["MeasurementApi", "new", "authorize_and_stash", "mark_initial_soc_load_complete", "encode_measurement_evidence"],
                "optional_symbols": ["validate_and_set_owner_policy", "manifest_lookup"],
                "role": "Owns embedded base policy, component membership and evidence lifecycle; optional owner policy is release-specific"
            },
            {
                "path": "runtime/userspace/api/measurement-api/src/api/initial_load.rs",
                "symbols": ["is_tcb", "create_dpe_context", "create_software_pcr_record"],
                "role": "TCB/non-TCB recording follows the attestation entry, not host authorization metadata"
            },
            {
                "path": "platforms/emulator/runtime/userspace/apps/user/src/image_loader/mod.rs",
                "symbols": ["image_loading_task", "image_loading", "emit_attestation_evidence_ready", "System::exit"],
                "role": "Verify successful-load exit cfg and test-only evidence readiness"
            },
            {
                "path": "runtime/userspace/syscall/src/system.rs",
                "symbols": ["System", "exit"],
                "role": "System exit syscall"
            },
            {
                "path": "runtime/kernel/capsules/src/system.rs",
                "symbols": ["EXIT", "exiter"],
                "role": "Routes exit syscall to the platform exiter"
            },
            {
                "path": "platforms/emulator/runtime/src/board.rs",
                "symbols": ["EmulatorExiter", "exit_emulator"],
                "role": "Selected emulator kernel terminates on System::exit"
            },
            {
                "path": "xtask/src/corim.rs",
                "symbols": ["read_evidence_components", "generate"],
                "role": "Current host reference-value helper reads vendor manifest metadata; it cannot change the measured firmware policy"
            }
        ],
        "spdm_source_checks": super::spdm::compatibility_spdm_source_checks()
    })
}

#[cfg(not(feature = "fpga_realtime"))]
pub(crate) fn write_compatibility_attestation_support(
    output_dir: &std::path::Path,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(output_dir)
        .context("BLOCKED: could not create attestation prerequisite artifact directory")?;
    let report = serde_json::to_vec_pretty(&compatibility_attestation_support())?;
    std::fs::write(output_dir.join("attestation-prerequisites.json"), report)
        .context("BLOCKED: could not retain attestation prerequisite artifact")
}

/// Production measurement initialization runs before protocol tasks in
/// `user/src/main.rs`; it uses the manifest and SoC load list embedded by
/// `user/build.rs`. Unlike the feature-specific tests below, the selected
/// images cannot acquire a different manifest through `TestParams`.
///
/// Keep these cases blocked until their immutable fixture configuration,
/// cold-boot SoC load/measurement completion, and matching appraisal inputs
/// are provided. A successful GET_MEASUREMENTS alone does not establish
/// non-TCB, TCB, or mixed coverage.
#[cfg(not(feature = "fpga_realtime"))]
pub(crate) fn run_compatibility_attestation(
    _hw: &mut DefaultHwModel,
    kind: &str,
) -> anyhow::Result<()> {
    let output_dir = std::env::var_os("MCU_COMPAT_EVIDENCE_DIR")
        .context("BLOCKED: MCU_COMPAT_EVIDENCE_DIR is required for attestation prerequisites")?;
    write_compatibility_attestation_support(std::path::Path::new(&output_dir))?;
    match kind {
        "ocp-eat-non-tcb" | "ocp-eat-tcb" | "ocp-eat-mixed" => bail!(
            "BLOCKED: {kind} requires a verified embedded attestation manifest and SoC \
             image load list for the requested component classes, authenticated SoC \
             payloads loaded and measured through the selected production boot flow, \
             and matching reference-value/endorsement appraisal inputs. The agreed \
             immutable baseline/service fixtures do not establish these prerequisites; \
             successful initial image loading also exits the selected emulator via \
             image_loading_task/System::exit. Host-only signed manifest variants cannot \
             change the compiled component classes or keep post-load SPDM serving; \
             see attestation-prerequisites.json"
        ),
        "pcr-quote" => bail!(
            "NOT APPLICABLE: the pinned production responder selects OCP EAT; \
             user/src/spdm/mod.rs selects the PCR quote provider only under \
             test-mctp-spdm-attestation-pcr-quote, which is absent from the agreed \
             immutable baseline/service images"
        ),
        _ => bail!("unsupported cold-boot compatibility attestation kind: {kind}"),
    }
}
