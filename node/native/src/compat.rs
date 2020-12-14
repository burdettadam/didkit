use neon::prelude::*;

use ssi::jwk::JWK;
use ssi::vc::Credential as VerifiableCredential;
use ssi::vc::LinkedDataProofOptions;
use ssi::vc::Presentation as VerifiablePresentation;

use crate::error::Error;
use crate::{map_opt_prop, prop, throws};

pub fn issue_credential(mut cx: FunctionContext) -> JsResult<JsValue> {
    let options = cx.argument::<JsObject>(0)?;

    let suite = options
        .get(&mut cx, "suite")?
        .downcast_or_throw::<JsObject, _>(&mut cx)?;

    let ldpo = cx.empty_object();

    map_opt_prop!(cx, suite, "verificationMethod", ldpo, "verificationMethod");
    map_opt_prop!(cx, suite, "purpose", ldpo, "proofPurpose");

    let ldpo: LinkedDataProofOptions = throws!(cx, neon_serde::from_value(&mut cx, ldpo.upcast()))?;

    let mut credential = prop!(cx, options, "credential", VerifiableCredential);
    let key = prop!(cx, suite, "key", JWK);

    throws!(cx, credential.validate_unsigned())?;

    let proof = throws!(cx, credential.generate_proof(&key, &ldpo))?;
    credential.add_proof(proof);

    let vc = throws!(cx, neon_serde::to_value(&mut cx, &credential))?;
    Ok(vc)
}

pub fn verify_presentation(mut cx: FunctionContext) -> JsResult<JsValue> {
    let options = cx.argument::<JsObject>(0)?;

    let suite = options
        .get(&mut cx, "suite")?
        .downcast_or_throw::<JsObject, _>(&mut cx)?;

    let ldpo = cx.empty_object();

    map_opt_prop!(cx, suite, "verificationMethod", ldpo, "verificationMethod");
    map_opt_prop!(cx, suite, "purpose", ldpo, "proofPurpose");
    map_opt_prop!(cx, suite, "challenge", ldpo, "challenge");
    map_opt_prop!(cx, suite, "domain", ldpo, "domain");

    let ldpo: LinkedDataProofOptions = throws!(cx, neon_serde::from_value(&mut cx, ldpo.upcast()))?;

    let vp = prop!(cx, options, "presentation", VerifiablePresentation);

    throws!(cx, vp.validate_unsigned())?;

    let result = vp.verify(Some(ldpo));
    let result = throws!(cx, neon_serde::to_value(&mut cx, &result))?;
    Ok(result)
}
