//! Indy-sdk crypto functions
use {IndyHandle, ErrorCode};
use indy::crypto;
use logic::config::payment_address_config::PaymentAddressConfig;
use utils::callbacks;
use utils::base58::serialize_bytes;
use utils::json_conversion::JsonSerialize;
use std::sync::mpsc::channel;


/**
    This defines the interfaces for INDY SDK crypto apis, which can be replaced with different implementations
    (aka production vs test time)

    modeling: master/libindy/src/api/crypto.rs
*/
pub trait CryptoAPI {
    fn indy_create_key(&self, wallet_id: i32, config: PaymentAddressConfig ) -> Result<String, ErrorCode>;
    fn indy_create_key_async<F: 'static>(&self, wallet_id: i32, config: PaymentAddressConfig, closure: F) -> ErrorCode where F: FnMut(ErrorCode, String) + Send;
    fn indy_crypto_sign<F: FnMut(Result<String, ErrorCode>) + 'static + Send>(&self, wallet_handle: i32, verkey: String, message: String, cb: F) -> ErrorCode;
}

// ------------------------------------------------------------------
// CryptoAPI implementation using INDY SDK
// ------------------------------------------------------------------
/**
   This is the "production" implementation of CryptoAPI as
   this implementation calls Indy SDK indy_create_key(...)
*/
pub struct CryptoSdk{}

impl CryptoAPI for CryptoSdk {

    /**
       creates fully formatted address based on inputted seed.  If seed is empty
       then a randomly generated seed is used by libsodium
       the format of the return is:
           pay:sov:{32 byte address}{4 byte checksum}
    */
    fn indy_create_key(&self,command_handle_: i32, wallet_id: IndyHandle, config: PaymentAddressConfig) -> Result<String, ErrorCode> {

        trace!("create_payment_address calling indy_create_key");
        let mut config_json: String = config.to_json().unwrap();

        // indy-sdk expects a valid but empty input to be this below
        // so if no seed was provided, create the json to look like this instead
        if 0 == config.seed.chars().count() {
            config_json = r#"{ }"#.to_string();
        }

        /*let (sender, receiver) = channel();
        let closure: Box<FnMut(ErrorCode) + Send> = Box::new(move |err| {
            sender.send(err).unwrap();
        });
        let (command_handle, cb) = callbacks::closure_to_cb_ec_string(closure);
        let config = opt_c_str_json!(config);*/
        
        ErrorCode::from(unsafe { crypto:indy_create_key(
            //command_handle,
            wallet_handle,
            Some(&config_json),//config.as_ptr(),
            //cb
            ) })

        //return Key::create(wallet_id, Some(&config_json));
    }

    /**
        for consumers that cannot have blocking calls, this method indy_create_key asynchronously
    */
    fn indy_create_key_async<F: 'static>(&self, wallet_id: i32, config: PaymentAddressConfig, closure: F) -> ErrorCode where F: FnMut(ErrorCode, String) + Send {

        trace!("create_payment_address calling indy_create_key");
        let mut config_json: String = config.to_json().unwrap();

        // indy-sdk expects a valid but empty input to be this below
        // so if no seed was provided, create the json to look like this instead
        if 0 == config.seed.chars().count() {
            config_json = r#"{ }"#.to_string();
        }

        //return Key::create_async(wallet_id, Some(&config_json), closure);
    }

    fn indy_crypto_sign<F: FnMut(Result<String, ErrorCode>) + 'static + Send>(
        &self,
        wallet_handle: IndyHandle,
        verkey: String,
        message: String,
        mut cb: F
    ) -> ErrorCode {
        //TODO: build command_handle/cb and use ctypes
        return crypto::indy_crypto_sign(
            //command_handle,
            wallet_handle, 
            &verkey, 
            message.as_bytes(), 
            move |error_code, vec|
            {
            if error_code == ErrorCode::Success {
                cb(Ok(serialize_bytes(&vec)));
            } else {
                cb(Err(error_code));
            }
            },
            //cb
            );
    }
}
