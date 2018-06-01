/*!
 *  Defines structure and implementation of getUtxoRequest
 *  these are the structures for the [`build_get_utxo_txn_handler`]
 *
 *  [`build_get_utxo_txn_handler`]: ../../../api/fn.build_utxo_txn_handler.html
 */
use std::collections::HashMap;
use logic::request::Request;

const GET_UTXO : &str = "10002";

/**
 *  Json config to customize [`build_get_utxo_txn_handler`]
 *
 *  [`build_get_utxo_txn_handler`]: ../../../api/fn.build_get_utxo_txn_handler.html
 */
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct GetUtxoRequest {
    address : String,
    #[serde(rename = "type")]
    req_type: String
}

impl GetUtxoRequest {
    pub fn new(address : String, identifier : String) -> Request<GetUtxoRequest> {
        let req = GetUtxoRequest {
            address,
            req_type: GET_UTXO.to_string(),
        };
        return Request::new(req, identifier);
    }
}