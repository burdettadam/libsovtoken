//! Indy-sdk crypto functions
use {IndyHandle, ErrorCode};
use indy::crypto;
use logic::config::payment_address_config::PaymentAddressConfig;
//use utils::callbacks;
use utils::base58::serialize_bytes;
use utils::json_conversion::JsonSerialize;
use indy::CString;
use utils::results::ResultHandler;
use utils::callbacks::ClosureHandler;


/**
    This defines the interfaces for INDY SDK crypto apis, which can be replaced with different implementations
    (aka production vs test time)

    modeling: master/libindy/src/api/crypto.rs
*/
pub trait CryptoAPI {
    fn indy_create_key(&self, wallet_id: i32, config: PaymentAddressConfig ) -> Result<String, ErrorCode>;
    fn indy_create_key_async<F: 'static>(&self, wallet_id: i32, config: PaymentAddressConfig, closure: F) -> ErrorCode where F: FnMut(ErrorCode, String) + Send;
    fn indy_crypto_sign<F: FnMut(ErrorCode, String) + 'static + Send>(&self, wallet_handle: i32, verkey: String, message: String, cb: F) -> ErrorCode;
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
    fn indy_create_key(&self, wallet_id: IndyHandle, config: PaymentAddressConfig) -> Result<String, ErrorCode> {

        trace!("create_payment_address calling indy_create_key");
        let mut config_json: String = config.to_json().unwrap();

        // indy-sdk expects a valid but empty input to be this below
        // so if no seed was provided, create the json to look like this instead
        if 0 == config.seed.chars().count() {
            config_json = r#"{ }"#.to_string();
        }

        let (receiver, command_handle, cb) = ClosureHandler::cb_ec_string();

        let config = opt_c_str_json!(config_json);

        let error = ErrorCode::from(unsafe { crypto::indy_create_key(
            command_handle,
            wallet_id,
            config.as_ptr(),
            cb
            ) });
        ResultHandler::one(error, receiver)
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
        let (command_handle, cb) = ClosureHandler::convert_cb_ec_string(Box::new(closure));
        let config = opt_c_str_json!(config_json);

        ErrorCode::from(unsafe { crypto::indy_create_key(
            command_handle,
            wallet_id,
            config.as_ptr(),
            cb
            ) })
    }

    fn indy_crypto_sign<F: FnMut(ErrorCode, String) + 'static + Send>(
        &self,
        wallet_handle: IndyHandle,
        verkey: String,
        message: String,
        mut cb: F
    ) -> ErrorCode {
        let (command_handle, cb) = ClosureHandler::convert_cb_ec_string(Box::new(cb)); 
        let verkey = c_str!(verkey);
        //let message = c_str!(message);

        return ErrorCode::from(unsafe { crypto::indy_crypto_sign(
                        command_handle,
                        wallet_handle, 
                        verkey.as_ptr(), 
                        message.as_ptr() as *const u8,
                        message.len() as u32, 
                        move |error_code, vec| {
                            if error_code == ErrorCode::Success {
                                cb(Ok(serialize_bytes(&vec)));
                            } else {
                                cb(Err(error_code));
                            }
                        })
                    });
    }
}
