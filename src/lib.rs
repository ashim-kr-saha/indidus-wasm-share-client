use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

#[wasm_bindgen]
pub async fn download_and_decrypt(url: &str, key_hex: &str) -> Result<(), JsValue> {
    // 1. Download encrypted blob
    let mut opts = RequestInit::new();
    opts.method("GET");
    opts.mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init(url, &opts)?;
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("No window found"))?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
    let resp: Response = resp_value.dyn_into().map_err(|_| JsValue::from_str("Failed to cast to Response"))?;

    if !resp.ok() {
        return Err(JsValue::from_str("Failed to download share"));
    }

    let array_buffer_value = JsFuture::from(resp.array_buffer()?).await?;
    let bytes = js_sys::Uint8Array::new(&array_buffer_value).to_vec();

    // 2. Decrypt
    let key_bytes = hex::decode(key_hex).map_err(|_| JsValue::from_str("Invalid key hex"))?;
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Assume first 12 bytes are nonce
    if bytes.len() < 12 {
        return Err(JsValue::from_str("Invalid payload"));
    }
    let (nonce_bytes, ciphertext) = bytes.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let decrypted = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| JsValue::from_str("Decryption failed"))?;

    // 3. Trigger Download
    trigger_download(&decrypted, "decrypted_share")?;

    Ok(())
}

fn trigger_download(data: &[u8], filename: &str) -> Result<(), JsValue> {
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("No window found"))?;
    let document = window.document().ok_or_else(|| JsValue::from_str("No document found"))?;
    
    let blob_parts = js_sys::Array::new();
    blob_parts.push(&js_sys::Uint8Array::from(data));
    
    let blob = web_sys::Blob::new_with_u8_array_sequence(&blob_parts)?;
    let url = web_sys::Url::create_object_url_with_blob(&blob)?;
    
    let a = document.create_element("a")?.dyn_into::<web_sys::HtmlElement>()?;
    a.set_attribute("href", &url)?;
    a.set_attribute("download", filename)?;
    a.click();
    
    // We should probably delay revocation or use a different mechanism,
    // but for simple cases this might work if click() is synchronous.
    // However, it's safer to revoke later.
    // web_sys::Url::revoke_object_url(&url)?;
    
    Ok(())
}
