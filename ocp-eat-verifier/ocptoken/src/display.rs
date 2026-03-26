// Licensed under the Apache-2.0 license

//! CoRIM display helpers for pretty-printing decoded CoRIM payloads.

fn format_unix_timestamp(secs: i128) -> String {
    use chrono::DateTime;
    match DateTime::from_timestamp(secs as i64, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => format!("{}(unknown)", secs),
    }
}

/// Print a decoded CoRIM payload (reference values, entities, tags).
pub(crate) fn print_corim_payload(file_name: &str, corim_map: &corim_rs::CorimMap) {
    println!("  File: {}", file_name);
    println!("  CoRIM ID: {:?}", corim_map.id);
    if let Some(ref profile) = corim_map.profile {
        println!("  Profile:  {:?}", profile);
    }
    if let Some(ref validity) = corim_map.rim_validity {
        let not_after_secs = validity.not_after.as_i128();
        let not_after_str = format_unix_timestamp(not_after_secs);
        if let Some(ref not_before) = validity.not_before {
            let not_before_secs = not_before.as_i128();
            let not_before_str = format_unix_timestamp(not_before_secs);
            println!("  Validity: {} to {}", not_before_str, not_after_str);
        } else {
            println!("  Validity: until {}", not_after_str);
        }
    }
    if let Some(ref entities) = corim_map.entities {
        println!("  Entities ({}):", entities.len());
        for (i, entity) in entities.iter().enumerate() {
            println!("    [{}] {:?}", i, entity);
        }
    }
    println!("  Tags ({}):", corim_map.tags.len());
    for (i, tag) in corim_map.tags.iter().enumerate() {
        match tag {
            corim_rs::ConciseTagTypeChoice::Mid(tagged_comid) => {
                let comid = &tagged_comid.0 .0;
                println!("    [{}] CoMID: tag-id={:?}", i, comid.tag_identity.tag_id);
                print_comid_triples(&comid.triples);
            }
            _ => {
                println!("    [{}] {:?}", i, tag);
            }
        }
    }
}

fn print_comid_triples(triples: &corim_rs::TriplesMap) {
    if let Some(ref ref_triples) = triples.reference_triples {
        println!("      Reference Triples ({}):", ref_triples.len());
        for (i, triple) in ref_triples.iter().enumerate() {
            println!("        [{}] Environment:", i);
            print_environment(&triple.ref_env);
            println!("            Measurements ({}):", triple.ref_claims.len());
            for (j, meas) in triple.ref_claims.iter().enumerate() {
                print_measurement(j, meas);
            }
        }
    }
    if let Some(ref end_triples) = triples.endorsed_triples {
        println!("      Endorsed Triples ({}):", end_triples.len());
        for (i, triple) in end_triples.iter().enumerate() {
            println!("        [{}] {:?}", i, triple);
        }
    }
    if let Some(ref id_triples) = triples.identity_triples {
        println!("      Identity Triples ({}):", id_triples.len());
        for (i, triple) in id_triples.iter().enumerate() {
            println!("        [{}] {:?}", i, triple);
        }
    }
    if let Some(ref ak_triples) = triples.attest_key_triples {
        println!("      Attest Key Triples ({}):", ak_triples.len());
        for (i, triple) in ak_triples.iter().enumerate() {
            println!("        [{}] {:?}", i, triple);
        }
    }
}

fn print_environment(env: &corim_rs::EnvironmentMap) {
    if let Some(ref class) = env.class {
        if let Some(ref class_id) = class.class_id {
            if let Some(bytes) = class_id.as_bytes() {
                match std::str::from_utf8(bytes) {
                    Ok(s) => println!("                Class ID:  \"{}\"", s),
                    Err(_) => println!("                Class ID:  {:?}", class_id),
                }
            } else {
                println!("                Class ID:  {:?}", class_id);
            }
        }
        if let Some(ref vendor) = class.vendor {
            println!("                Vendor:    {}", vendor);
        }
        if let Some(ref model) = class.model {
            println!("                Model:     {}", model);
        }
        if let Some(ref layer) = class.layer {
            println!("                Layer:     {}", layer);
        }
        if let Some(ref index) = class.index {
            println!("                Index:     {}", index);
        }
    }
    if let Some(ref instance) = env.instance {
        println!("                Instance:  {:?}", instance);
    }
    if let Some(ref group) = env.group {
        println!("                Group:     {:?}", group);
    }
}

fn print_measurement(_idx: usize, meas: &corim_rs::MeasurementMap) {
    let mval = &meas.mval;
    if let Some(ref ver) = mval.version {
        println!("                    Version:  {:?}", ver);
    }
    if let Some(ref svn) = mval.svn {
        println!("                    SVN:      {:?}", svn);
    }
    if let Some(ref digests) = mval.digests {
        println!("                    Digests:");
        for d in digests.iter() {
            println!("                      {:?}: {}", d.alg, hex::encode(&d.val));
        }
    }
    if let Some(ref flags) = mval.flags {
        println!("                    Flags:    {:?}", flags);
    }
    if let Some(ref raw) = mval.raw {
        println!("                    Raw:      {:?}", raw);
    }
}
