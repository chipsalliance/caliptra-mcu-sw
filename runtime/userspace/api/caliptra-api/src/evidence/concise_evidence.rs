// Licensed under the Apache-2.0 license

use crate::error::CaliptraApiResult;
use ocp_eat::eat_encoder::EvTriplesMap;

pub async fn fill_evidence_triples_map(
    _ev_triples_map: &mut EvTriplesMap<'_>,
) -> CaliptraApiResult<()> {
    Ok(())
}
