/*!
    Payment Input
*/

use serde::{de, Deserialize};
use std::fmt;
use logic::parsers::common::TXO;
use logic::type_aliases::TxnSeqNo;

pub type Inputs = Vec<Input>;

/**
 * Config which holds a vec of [`Input`]s
 * 
 * Also has a version for backward compatability.
 * 
 * [`Inputs`]: Input
 */
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct InputConfig {
    pub ver: u8,
    pub inputs: Inputs,
}


/**
    Struct which holds an address, seq_no, signature, and extra data.

    # Deserialization
    Input can be deserialized from an array or an object. Both are valid:

    ## From Array
    An array with the format of `[address, seq_no, signature]`.
    When deserializing from an array, the signature is required.
    ```
    use sovtoken::utils::json_conversion::JsonDeserialize;
    use sovtoken::logic::input::Input;
    let json = r#"{"address":"pay:sov:AesjahdahudgaiuNotARealAKeyygigfuigraiudgfasfhja", "seqNo":30}"#;
    let input = Input::from_json(json).unwrap();
    assert_eq!(Input{address: "pay:sov:AesjahdahudgaiuNotARealAKeyygigfuigraiudgfasfhja".to_string(), seq_no: 30}, input);
    ```

    ## From Object
    ### Required Fields
    * address
    * seq_no

    ### Optional Fields
    * signature
    * extra
    
    ```
    use sovtoken::utils::json_conversion::JsonDeserialize;
    use sovtoken::logic::input::Input;
    let json = r#"{
        "address": "pay:sov:AesjahdahudgaiuNotARealAKeyygigfuigraiudgfasfhja",
        "seqNo": 30,
        "signature": "239asdkj3298uadkljasd98u234ijasdlkj"
    }"#;
    let input = Input::from_json(json);
    ```

    # Serialization
    When Input is serialized, it is always serialized as an array:

    ```
    use sovtoken::utils::json_conversion::JsonSerialize;
    use sovtoken::logic::input::Input;
    let address = String::from("pay:sov:AesjahdahudgaiuNotARealAKeyygigfuigraiudgfasfhja");
    let input = Input::new(address, 30);

    let json = Input::to_json(&input).unwrap();
    assert_eq!(json, r#"{"address":"pay:sov:AesjahdahudgaiuNotARealAKeyygigfuigraiudgfasfhja","seqNo":30}"#);
    ```

*/
#[derive(Debug, Eq, PartialEq, Clone, Serialize)]
pub struct Input {
    pub address: String,
    #[serde(rename = "seqNo")]
    pub seq_no: TxnSeqNo
}

impl ToString for Input {
    fn to_string(&self) -> String {
        format!("{}{}", self.seq_no, self.address)
    }
}

impl Input {
    pub fn new(address: String, seq_no: TxnSeqNo) -> Input {
        return Input { address, seq_no};
    }
}

impl<'de> Deserialize<'de> for Input {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Input, D::Error> {
        struct InputVisitor;

        impl<'de> de::Visitor<'de> for InputVisitor {
            type Value = Input;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                return formatter.write_str("Expected an Input with address and seqNo.");
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                let txo = TXO::from_libindy_string(v)
                    .map_err(|ec| de::Error::custom(format!("Error when deserializing txo: error code {:?}", ec)))?;

                return Ok(Input::new(txo.address, txo.seq_no ))
            }

            fn visit_map<V: de::MapAccess<'de>>(self, mut map: V) -> Result<Input, V::Error> {
                let mut address = None;
                let mut seq_no = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        "address" => { address = map.next_value()?; },
                        "seqNo" => { seq_no =  map.next_value()?; },
                        x => { return Err(de::Error::unknown_field(x, FIELDS)) }
                    }
                }

                let address = address.ok_or(de::Error::missing_field("address"))?;
                let seq_no = seq_no.ok_or( de::Error::missing_field("seqNo"))?;

                return Ok(Input::new(address, seq_no));
            }
        }

        const FIELDS: &'static [&'static str] = &["address", "seqNo"];
        return deserializer.deserialize_any(InputVisitor);
    }
}


#[cfg(test)]
mod input_tests {
    use serde_json;

    use logic::input::{Input, InputConfig};
    use logic::parsers::common::TXO;
    use utils::json_conversion::{JsonDeserialize, JsonSerialize};
    use utils::base58::IntoBase58;


    fn json_value_to_string(json: serde_json::Value) -> String {
        return serde_json::to_string(&json).unwrap();
    }

    fn assert_invalid_deserialize(json: serde_json::Value, error_message_starts_with: &str) {
        let json_string = json_value_to_string(json);
        let invalid = Input::from_json(&json_string).unwrap_err();
        println!("{}", invalid);
        assert!(format!("{}", invalid).contains(error_message_starts_with));
    }

    fn assert_valid_deserialize(json: serde_json::Value, expected_input: Input) {
        let json_string = json_value_to_string(json);
        let input = Input::from_json(&json_string).unwrap();
        assert_eq!(input, expected_input);
    }

    fn assert_valid_serialize(input: Input, json: serde_json::Value) {
        let json_string = json_value_to_string(json);
        let input_serialized = Input::to_json(&input).unwrap();
        assert_eq!(input_serialized, json_string);
    }

    fn valid_input() -> Input {
        let address = String::from("pay:sov:a8QAXMjRwEGoGLmMFEc5sTcntZxEF1BpqAs8GoKFa9Ck81fo7");
        return Input::new(address, 30);
    }

    #[test]
    fn deserialize_invalid_input_object_without_seq_no() {
        let json = json!("txo:sov:".to_string() + &json!({
            "address": "pay:sov:a8QAXMjRwEGoGLmMFEc5sTcntZxEF1BpqAs8GoKFa9Ck81fo7",
        }).to_string().as_bytes().into_base58_check());
        assert_invalid_deserialize(json, "missing field `seqNo`");
    }

    #[test]
    fn deserialize_input_object_without_address() {
        let json = json!("txo:sov:".to_string() + &json!({
            "seqNo": 30,
        }).to_string().as_bytes().into_base58_check());
        assert_invalid_deserialize(json, "missing field `address`");
    }

    #[test]
    fn deserialize_input_object_with_keys() {
        let json = json!(
            TXO {
                address: "pay:sov:a8QAXMjRwEGoGLmMFEc5sTcntZxEF1BpqAs8GoKFa9Ck81fo7".to_string(),
                seq_no: 30
            }.to_libindy_string().unwrap()
        );
        let input = valid_input();
        assert_valid_deserialize(json, input);
    }

    #[test]
    fn serialize_input() {
        let input = Input::new(String::from("a8QAXMjRwEGoGLmMFEc5sTcntZxEF1BpqAs8GoKFa9Ck81fo7"), 5);
        let expected = json!({"address": "a8QAXMjRwEGoGLmMFEc5sTcntZxEF1BpqAs8GoKFa9Ck81fo7", "seqNo":5});
        assert_valid_serialize(input, expected);
    }

    // this test ensures that the deserialized JSON is serialized correctly
    #[test]
    fn serializing_payload_struct_output_config() {
        let input = Input::new(String::from("a8QAXMjRwEGoGLmMFEc5sTcntZxEF1BpqAs8GoKFa9Ck81fo7"), 30);

        let fee: InputConfig = InputConfig {
            ver: 1,
            inputs: vec![input],
        };
        assert_eq!(fee.to_json().unwrap(), r#"{"ver":1,"inputs":[{"address":"a8QAXMjRwEGoGLmMFEc5sTcntZxEF1BpqAs8GoKFa9Ck81fo7","seqNo":30}]}"#);
    }
}