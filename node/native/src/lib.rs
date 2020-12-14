use neon::prelude::*;

mod compat;
mod didkit;
mod error;
mod macros;

register_module!(mut m, {
    m.export_function("getVersion", didkit::get_version)?;

    m.export_function("generateEd25519Key", didkit::generate_ed25519_key)?;
    m.export_function("keyToDID", didkit::key_to_did)?;
    m.export_function(
        "keyToVerificationMethod",
        didkit::key_to_verification_method,
    )?;

    m.export_function("issueCredential", didkit::issue_credential)?;
    m.export_function("verifyCredential", didkit::verify_credential)?;

    m.export_function("issuePresentation", didkit::issue_presentation)?;
    m.export_function("verifyPresentation", didkit::verify_presentation)?;

    let compat = {
        let ret = m.empty_object();

        let js_fn = JsFunction::new(&mut m, compat::issue_credential)?;
        ret.set(&mut m, "issue", js_fn)?;

        //let js_fn = JsFunction::new(&mut m, compat::verify_presentation)?;
        //ret.set(&mut m, "verify", js_fn);

        //let js_fn = JsFunction::new(&mut m, compat::verify_credential)?;
        //ret.set(&mut m, "verifyCredential", js_fn);

        //let js_fn = JsFunction::new(&mut m, compat::create_presentation)?;
        //ret.set(&mut m, "createPresentation", js_fn);

        //let js_fn = JsFunction::new(&mut m, compat::sign_presentation)?;
        //ret.set(&mut m, "signPresentation", js_fn);

        ret
    };

    m.export_value("compat", compat)?;

    Ok(())
});
