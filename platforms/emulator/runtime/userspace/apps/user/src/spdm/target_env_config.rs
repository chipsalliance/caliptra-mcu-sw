use core::mem::MaybeUninit;

use core::sync::atomic::{AtomicBool, Ordering};
use libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use ocp_eat::eat_encoder::{IntegrityRegisterEntry, IntegrityRegisterIdChoice};
use ocp_eat::{
    ClassMap, DigestEntry, EnvironmentMap, EvTriplesMap, EvidenceTripleRecord, MeasurementMap,
    MeasurementValue,
};

// Add this near the end of the file, after your existing functions
static EVIDENCE_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn get_evidence_storage() -> &'static mut EvTriplesMap<'static> {
    if !EVIDENCE_INITIALIZED.load(Ordering::Acquire) {
        // Initialize once
        unsafe {
            let _ = build_ev_triples_map_static();
        }
        EVIDENCE_INITIALIZED.store(true, Ordering::Release);
    }

    unsafe { EV_TRIPLES_MAP_STORAGE.assume_init_mut() }
}

// Configuration structure for components
#[derive(Clone, Copy)]
pub struct ComponentConfig {
    pub class_id: &'static str,
    pub vendor: Option<&'static str>,
    pub model: Option<&'static str>,
    pub component_type: ComponentType,
}

#[derive(Clone, Copy, PartialEq)]
pub enum ComponentType {
    Firmware,
    Hardware,
    Software,
}

// Macro to define component configurations
macro_rules! define_components {
    ($($name:ident => ComponentConfig {
        class_id: $class_id:expr,
        vendor: $vendor:expr,
        model: $model:expr,
        component_type: $comp_type:expr,
    }),* $(,)?) => {
        // Generate component constants
        $(
            #[allow(dead_code)]
            pub const $name: ComponentConfig = ComponentConfig {
                class_id: $class_id,
                vendor: $vendor,
                model: $model,
                component_type: $comp_type,
            };
        )*

        // Generate the component list
        pub const COMPONENT_CONFIGS: &[ComponentConfig] = &[
            $($name),*
        ];

        pub const NUM_COMPONENTS: usize = COMPONENT_CONFIGS.len();

        // Count components by type using compile-time counting
        pub const NUM_FW_COMPONENTS: usize = 0 $(+ if matches!($comp_type, ComponentType::Firmware) { 1 } else { 0 })*;
        pub const NUM_HW_COMPONENTS: usize = 0 $(+ if matches!($comp_type, ComponentType::Hardware) { 1 } else { 0 })*;
        pub const NUM_SW_COMPONENTS: usize = 0 $(+ if matches!($comp_type, ComponentType::Software) { 1 } else { 0 })*;

    };
}

// Define your components here - easily extensible!
define_components! {
    FMC_COMPONENT => ComponentConfig {
        class_id: "FMC_INFO",
        vendor: None,
        model: None,
        component_type: ComponentType::Firmware,
    },
    RT_COMPONENT => ComponentConfig {
        class_id: "RT_INFO",
        vendor: None,
        model: None,
        component_type: ComponentType::Firmware,
    },
    AUTH_MANIFEST_COMPONENT => ComponentConfig {
        class_id: "TEST_SOC_MANIFEST",
        vendor: Some("CHIPS_ALLIANCE"),
        model: Some("CALIPTRA_SS"),
        component_type: ComponentType::Firmware,
    },
    MCU_FW_COMPONENT => ComponentConfig {
        class_id: "0x00000002",
        vendor: Some("CHIPS_ALLIANCE"),
        model: Some("CALIPTRA_SS"),
        component_type: ComponentType::Firmware,
    },
    VENDOR_FUSES_COMPONENT => ComponentConfig {
        class_id: "VENDOR_MANUF_FUSES",
        vendor: Some("CHIPS_ALLIANCE"),
        model: Some("CALIPTRA_SS"),
        component_type: ComponentType::Hardware,
    },
}

// Fix the component indices manually since const string comparison is complex
pub const FMC_COMPONENT_INDEX: usize = 0;
pub const RT_COMPONENT_INDEX: usize = 1;
pub const AUTH_MANIFEST_COMPONENT_INDEX: usize = 2;
pub const MCU_FW_COMPONENT_INDEX: usize = 3;
pub const VENDOR_FUSES_COMPONENT_INDEX: usize = 4;

// Maximum components we can support (adjust as needed)
const MAX_COMPONENTS: usize = NUM_COMPONENTS;
const NUM_FW_HW_COMPONENTS: usize = NUM_FW_COMPONENTS + NUM_HW_COMPONENTS;

// Static storage arrays for FW and HW components
pub static mut DIGESTS: [[u8; SHA384_HASH_SIZE]; NUM_FW_HW_COMPONENTS] =
    [[0u8; SHA384_HASH_SIZE]; NUM_FW_HW_COMPONENTS];

// Journey measurements
pub static mut JOURNEY_DIGESTS: [[u8; SHA384_HASH_SIZE]; NUM_FW_COMPONENTS] =
    [[0u8; SHA384_HASH_SIZE]; NUM_FW_COMPONENTS];

// Static storage for measurement maps
static mut MEASUREMENT_MAPS_STORAGE: [MaybeUninit<MeasurementMap<'static>>; MAX_COMPONENTS] =
    [MaybeUninit::uninit(); MAX_COMPONENTS];

// Static storage for measurement references (each component has 1 measurement)
static mut MEASUREMENT_REFS_STORAGE: [MaybeUninit<&'static [MeasurementMap<'static>]>;
    MAX_COMPONENTS] = [MaybeUninit::uninit(); MAX_COMPONENTS];

// Static storage for evidence triples
static mut EVIDENCE_TRIPLES_STORAGE: [MaybeUninit<EvidenceTripleRecord<'static>>; MAX_COMPONENTS] =
    [MaybeUninit::uninit(); MAX_COMPONENTS];

// Static storage for environment maps
static mut ENVIRONMENT_MAPS_STORAGE: [MaybeUninit<EnvironmentMap<'static>>; MAX_COMPONENTS] =
    [MaybeUninit::uninit(); MAX_COMPONENTS];

// Static storage for the EvTriplesMap
static mut EV_TRIPLES_MAP_STORAGE: MaybeUninit<EvTriplesMap<'static>> = MaybeUninit::uninit();

// Static storage for digest entries (one per fw and hw)
static mut DIGEST_ENTRIES_STORAGE: [MaybeUninit<DigestEntry<'static>>; NUM_FW_HW_COMPONENTS] =
    [MaybeUninit::uninit(); NUM_FW_HW_COMPONENTS];

// Static storage for Journey digest entries for fw components
static mut JOURNEY_DIGEST_ENTRIES_STORAGE: [MaybeUninit<DigestEntry<'static>>; NUM_FW_COMPONENTS] =
    [MaybeUninit::uninit(); NUM_FW_COMPONENTS];

static mut INTEGRITY_REGISTER_ENTRIES_STORAGE: [MaybeUninit<IntegrityRegisterEntry<'static>>;
    NUM_FW_COMPONENTS] = [MaybeUninit::uninit(); NUM_FW_COMPONENTS];

pub fn initialize_measurement_maps() {
    unsafe {
        // Initialize environment maps from component configs
        for i in 0..NUM_COMPONENTS {
            let config = &COMPONENT_CONFIGS[i];
            ENVIRONMENT_MAPS_STORAGE[i].write(EnvironmentMap {
                class: ClassMap {
                    class_id: config.class_id,
                    vendor: config.vendor,
                    model: config.model,
                },
            });
        }

        let num_fw_hw_components = NUM_FW_COMPONENTS + NUM_HW_COMPONENTS;
        // Initialize digest entries
        for i in 0..num_fw_hw_components {
            DIGEST_ENTRIES_STORAGE[i].write(DigestEntry {
                alg_id: 7, // SHA-384 algorithm ID
                value: &DIGESTS[i],
            });
        }

        // Initialize journey digests for FW components
        for i in 0..NUM_FW_COMPONENTS {
            JOURNEY_DIGEST_ENTRIES_STORAGE[i].write(DigestEntry {
                alg_id: 7, // SHA-384 algorithm ID
                value: &JOURNEY_DIGESTS[i],
            });
        }

        // Initialize Integrity register entries (represent the journey digests)
        for i in 0..NUM_FW_COMPONENTS {
            INTEGRITY_REGISTER_ENTRIES_STORAGE[i].write(IntegrityRegisterEntry {
                id: IntegrityRegisterIdChoice::Uint(0),
                digests: core::slice::from_ref(JOURNEY_DIGEST_ENTRIES_STORAGE[i].assume_init_ref()),
            });
        }
        for i in 0..NUM_COMPONENTS {
            let config = &COMPONENT_CONFIGS[i];

            let measurement_map = match config.component_type {
                ComponentType::Firmware => {
                    // Firmware components have both digests and integrity registers (journey measurements)
                    MeasurementMap {
                        key: i as u64,
                        mval: MeasurementValue {
                            version: None,
                            svn: None,
                            digests: Some(core::slice::from_ref(
                                DIGEST_ENTRIES_STORAGE[i].assume_init_ref(),
                            )),
                            integrity_registers: Some(core::slice::from_ref(
                                INTEGRITY_REGISTER_ENTRIES_STORAGE[i].assume_init_ref(),
                            )),
                            raw_value: None,
                            raw_value_mask: None,
                        },
                    }
                }
                ComponentType::Hardware => {
                    // Hardware components have only digests (no journey measurements)
                    MeasurementMap {
                        key: i as u64,
                        mval: MeasurementValue {
                            version: None,
                            svn: None,
                            digests: Some(core::slice::from_ref(
                                DIGEST_ENTRIES_STORAGE[i].assume_init_ref(),
                            )),
                            integrity_registers: None, // No journey measurements for HW
                            raw_value: None,
                            raw_value_mask: None,
                        },
                    }
                }
                ComponentType::Software => {
                    // Software components (if any) - basic measurement without digests
                    // TODO: Extend this to include raw measurements of fixed size
                    MeasurementMap {
                        key: i as u64,
                        mval: MeasurementValue {
                            version: None,
                            svn: None,
                            digests: None, // Software might not have digests
                            integrity_registers: None,
                            raw_value: None,
                            raw_value_mask: None,
                        },
                    }
                }
            };

            MEASUREMENT_MAPS_STORAGE[i].write(measurement_map);

            // Each component has currently one MeasurementMap. Create a reference to it.
            // EvidenceTripleRecord expects measurements: &'a [MeasurementMap<'a>]
            let measurement_slice =
                core::slice::from_ref(MEASUREMENT_MAPS_STORAGE[i].assume_init_ref());
            MEASUREMENT_REFS_STORAGE[i].write(measurement_slice);
        }
    }
}

fn build_ev_triples_map_static() -> &'static mut EvTriplesMap<'static> {
    unsafe {
        // Initialize measurement maps first
        initialize_measurement_maps();

        // Initialize evidence triples
        for i in 0..NUM_COMPONENTS {
            EVIDENCE_TRIPLES_STORAGE[i].write(EvidenceTripleRecord {
                environment: *ENVIRONMENT_MAPS_STORAGE[i].assume_init_ref(),
                measurements: MEASUREMENT_REFS_STORAGE[i].assume_init(),
            });
        }

        // Create evidence triples slice
        let evidence_triples_slice = core::slice::from_raw_parts(
            EVIDENCE_TRIPLES_STORAGE.as_ptr() as *const EvidenceTripleRecord<'static>,
            NUM_COMPONENTS,
        );

        // Initialize EvTriplesMap
        let ev_triples_map = EvTriplesMap {
            evidence_triples: Some(evidence_triples_slice),
            identity_triples: None,
            dependency_triples: None,
            membership_triples: None,
            coswid_triples: None,
            attest_key_triples: None,
        };

        EV_TRIPLES_MAP_STORAGE.write(ev_triples_map);
        EV_TRIPLES_MAP_STORAGE.assume_init_mut()
    }
}

// // MeasurementManager with extensible component support
// pub struct MeasurementManager {
//     ev_triples_map: &'static EvTriplesMap<'static>,
// }

// impl MeasurementManager {
//     pub fn new() -> Self {
//         let ev_triples_map = build_ev_triples_map_static();
//         Self { ev_triples_map }
//     }

//     pub fn get_ev_triples_map(&self) -> &'static EvTriplesMap<'static> {
//         self.ev_triples_map
//     }

//     // Component lookup by class_id
//     pub fn find_component_index(&self, class_id: &str) -> Option<usize> {
//         for i in 0..NUM_COMPONENTS {
//             if COMPONENT_CONFIGS[i].class_id == class_id {
//                 return Some(i);
//             }
//         }
//         None
//     }

//     // Get all components of a specific type
//     pub fn get_components_by_type(&self, component_type: ComponentType) -> Vec<usize> {
//         let mut indices = Vec::new();
//         for i in 0..NUM_COMPONENTS {
//             if COMPONENT_CONFIGS[i].component_type == component_type {
//                 indices.push(i);
//             }
//         }
//         indices
//     }

//     // Update methods
//     pub fn update_component_digest(
//         &mut self,
//         component_index: usize,
//         digest: &[u8],
//     ) -> Result<(), &'static str> {
//         if component_index >= NUM_COMPONENTS {
//             return Err("Invalid component index");
//         }

//         if digest.len() != SHA384_HASH_SIZE {
//             return Err("Invalid digest size");
//         }

//         unsafe {
//             // Update the digest storage
//             DIGESTS[component_index].copy_from_slice(digest);
//             // The digest entry already points to DIGESTS[component_index], so no need to update the measurement map
//         }

//         Ok(())
//     }

//     pub fn update_component_by_class_id(
//         &mut self,
//         class_id: &str,
//         digest: &[u8],
//     ) -> Result<(), &'static str> {
//         if let Some(index) = self.find_component_index(class_id) {
//             self.update_component_digest(index, digest)
//         } else {
//             Err("Component not found")
//         }
//     }

//     pub fn get_measurement_mut(
//         &mut self,
//         component_index: usize,
//     ) -> Option<&'static mut MeasurementMap<'static>> {
//         if component_index >= NUM_COMPONENTS {
//             return None;
//         }

//         unsafe { Some(MEASUREMENT_MAPS_STORAGE[component_index].assume_init_mut()) }
//     }

//     // Convenience methods for updating specific component types
//     pub fn update_firmware_digest(
//         &mut self,
//         class_id: &str,
//         digest: &[u8],
//     ) -> Result<(), &'static str> {
//         self.update_component_by_class_id(class_id, digest)
//     }

//     pub fn update_hardware_digest(
//         &mut self,
//         class_id: &str,
//         digest: &[u8],
//     ) -> Result<(), &'static str> {
//         self.update_component_by_class_id(class_id, digest)
//     }

//     // Update version and SVN
//     pub fn update_component_version(
//         &mut self,
//         component_index: usize,
//         version: &'static str,
//     ) -> Result<(), &'static str> {
//         if let Some(measurement) = self.get_measurement_mut(component_index) {
//             measurement.mval.version = Some(version);
//             Ok(())
//         } else {
//             Err("Invalid component index")
//         }
//     }

//     pub fn update_component_svn(
//         &mut self,
//         component_index: usize,
//         svn: u64,
//     ) -> Result<(), &'static str> {
//         if let Some(measurement) = self.get_measurement_mut(component_index) {
//             measurement.mval.svn = Some(svn);
//             Ok(())
//         } else {
//             Err("Invalid component index")
//         }
//     }
// }
