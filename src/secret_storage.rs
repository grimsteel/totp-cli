use std::collections::HashMap;

use gio::Cancellable;
use libsecret::{SchemaAttributeType, Schema, SchemaFlags, COLLECTION_DEFAULT, password_store_sync, password_search_sync, SearchFlags,prelude::{RetrievableExt, RetrievableExtManual}, password_clear_sync};

#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub label: String,
    pub issuer: String,
    pub token: String
}

pub fn make_schema() -> Schema {
    let mut attributes = HashMap::new();
    attributes.insert("token_id", SchemaAttributeType::String);
    attributes.insert("issuer", SchemaAttributeType::String);

    let schema = Schema::new("grimsteel.totp_cli", SchemaFlags::NONE, attributes);

    return schema;
}

pub fn store_token(schema: &Schema, label: &str, id: &str, issuer: &str, token: &str) -> Option<()> {
    let mut attributes = HashMap::new();
    attributes.insert("token_id", id);
    attributes.insert("issuer", issuer);

    // store
    password_store_sync(Some(schema), attributes, Some(&COLLECTION_DEFAULT), label, token, None::<&Cancellable>).ok()
}

pub fn delete_token(schema: &Schema, id: &str) -> Option<()> {
    let mut attributes = HashMap::new();
    attributes.insert("token_id", id);

    password_clear_sync(Some(schema), attributes, None::<&Cancellable>).ok()
}

pub fn get_token(schema: &Schema, id: &str) -> Option<TokenInfo> {
    let mut attributes = HashMap::new();
    attributes.insert("token_id", id);

    // search for the item
    let search_result = password_search_sync(Some(schema), attributes.clone(), SearchFlags::NONE, None::<&Cancellable>);
    
    match search_result.as_deref() {
        // We just need the first result
        Ok([password]) => {
            // Get the label
            let label = password.label().to_string();
            // Get the attributes
            let attrs = password.attributes();
            // Lookup the actual token
            let token_result = password.retrieve_secret_sync(None::<&Cancellable>)
                // get the String out of the value
                .map(|t| t.and_then(|t| t.text()).map(|t| t.to_string()));

            // Lookup the issuer on the attrs and the otken result
            match (attrs.get("issuer"), token_result) {
                (Some(issuer), Ok(Some(token))) => {
                    // token_value is Value, get the actual token out
                    Some(TokenInfo {
                        label,
                        issuer: issuer.clone(),
                        token
                    })
                },
                _ => None
            }
        },
        _ => None
    }
}
