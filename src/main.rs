pub mod command;

use clap::{crate_authors, crate_version, Clap};
use futures::executor::block_on;
use ic_agent::{
    agent,
    identity::BasicIdentity,
    Agent, Identity,
};
use ic_utils::interfaces::management_canister::{
    builders::CanisterInstall,
};
use ring::signature::Ed25519KeyPair;
use std::{fs::File, io::Read, path::PathBuf};
use candid::{Encode, Principal};
use crate::command::{StoreWASMArgs, WasmType};

#[derive(Clap, Clone)]
#[clap(
version = crate_version!(),
author = crate_authors!()
)]
pub struct Opts {
    #[clap(default_value = "http://localhost:8000/")]
    replica: String,

    #[clap(long)]
    pem: Option<PathBuf>,

    #[clap(long)]
    ttl: Option<humantime::Duration>,

    #[clap(subcommand)]
    subcommand: command::SubCommand,
}

fn create_identity(maybe_pem: Option<PathBuf>) -> impl Identity {
    if let Some(pem_path) = maybe_pem {
        BasicIdentity::from_pem_file(pem_path).expect("Could not read the key pair.")
    } else {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .expect("Could not generate a key pair.")
            .as_ref()
            .to_vec();

        BasicIdentity::from_key_pair(
            Ed25519KeyPair::from_pkcs8(&pkcs8_bytes).expect("Could not generate the key pair."),
        )
    }
}

#[tokio::main]
async fn main() {
    let opts: Opts = Opts::parse();

    let my_identity = create_identity(opts.pem.clone());
    let my_principal =  my_identity.sender().expect("not valid identity");
    println!("my identity is {}", my_principal);

    // let endpoit_url = String::from("https://ic0.app/");
    let endpoit_url = opts.replica.clone();

    let agent = Agent::builder()
        .with_transport(
            agent::http_transport::ReqwestHttpReplicaV2Transport::create(endpoit_url)
                .expect("Failed to create Transport for Agent"),
        )
        .with_boxed_identity(Box::new(my_identity))
        .build()
        .expect("Failed to build the Agent");

    match opts.clone().subcommand {
        command::SubCommand::Update(copts) => {
            let mut call_opts = copts.clone();
            let arg_value: Vec<u8> = match &copts.method_name[..] {
                "uploadAvatarWasm" => {
                    let mut buffer = Vec::<u8>::new();
                    let mut f = File::open("nft.wasm").expect("no wasm file");
                    f.read_to_end(&mut buffer).expect("read file error");
                    let wasmargs = StoreWASMArgs{ wasm_type: WasmType::AvatarNFT, wasm_module: buffer};
                    let arg_value = Encode!(&wasmargs).unwrap_or(vec![]);
                    call_opts.method_name = String::from("uploadWasm");
                    arg_value
                }
                "uploadNftWasm" => {
                    let mut buffer = Vec::<u8>::new();
                    let mut f = File::open("nft.wasm").expect("no wasm file");
                    f.read_to_end(&mut buffer).expect("read file error");
                    let wasmargs = StoreWASMArgs{ wasm_type: WasmType::VisaNFT, wasm_module: buffer};
                    let arg_value = Encode!(&wasmargs).unwrap_or(vec![]);
                    call_opts.method_name = String::from("uploadWasm");
                    arg_value
                }
                "uploadTokenWasm" => {
                    let mut buffer = Vec::<u8>::new();
                    let mut f = File::open("token.wasm").expect("no wasm file");
                    f.read_to_end(&mut buffer).expect("read file error");
                    let wasmargs = StoreWASMArgs{ wasm_type: WasmType::PABToken, wasm_module: buffer};
                    let arg_value = Encode!(&wasmargs).unwrap_or(vec![]);
                    call_opts.method_name = String::from("uploadWasm");
                    arg_value
                }
                "uploadAndersonWasm" => {
                    let mut buffer = Vec::<u8>::new();
                    let mut f = File::open("anderson.wasm").expect("no wasm file");
                    f.read_to_end(&mut buffer).expect("read file error");
                    let wasmargs = StoreWASMArgs{ wasm_type: WasmType::Life, wasm_module: buffer};
                    let arg_value = Encode!(&wasmargs).unwrap_or(vec![]);
                    call_opts.method_name = String::from("uploadWasm");
                    arg_value
                }
                "uploadBoardWasm" => {
                    let mut buffer = Vec::<u8>::new();
                    let mut f = File::open("board.wasm").expect("no wasm file");
                    f.read_to_end(&mut buffer).expect("read file error");
                    let wasmargs = StoreWASMArgs{ wasm_type: WasmType::Board, wasm_module: buffer};
                    let arg_value = Encode!(&wasmargs).unwrap_or(vec![]);
                    call_opts.method_name = String::from("uploadWasm");
                    arg_value
                }
                "DeployNFTContract" => {
                    let t = WasmType::VisaNFT;
                    let arg_value = Encode!(&t).unwrap_or(vec![]);
                    arg_value
                }
                "DeployAvatarNFTContract" => {
                    let t = WasmType::AvatarNFT;
                    let arg_value = Encode!(&t).unwrap_or(vec![]);
                    call_opts.method_name = String::from("DeployNFTContract");
                    arg_value
                }
                "DeployTokenContract" => {
                    let t = ();
                    let arg_value = Encode!(&t).unwrap_or(vec![]);
                    arg_value
                }
                "UpgradeAndersonContract" => {
                    let upcan = call_opts.up_canister.unwrap_or(Principal::anonymous());
                    let arg_value = Encode!(&upcan, &WasmType::Life).unwrap_or(vec![]);
                    call_opts.method_name = String::from("UpgradeCanister");
                    arg_value
                }
                "UpgradeBoardContract" => {
                    let upcan = call_opts.up_canister.unwrap_or(Principal::anonymous());
                    let arg_value = Encode!(&upcan, &WasmType::Board).unwrap_or(vec![]);
                    call_opts.method_name = String::from("UpgradeCanister");
                    arg_value
                }
                _ => { println!("update method not supported!"); return;}
            };
            let arg_value_str = easy_hasher::easy_hasher::Hash::from_vec(&arg_value).to_hex_string();
            call_opts.arg_value = Some(arg_value_str.clone());
            let future = command::call_update_method(&agent, &opts, &call_opts);
            let result  = block_on(future);
            command::show_result(result, &call_opts);
        }
        command::SubCommand::Query(copts) => {
            match &copts.method_name[..] {
                _ => println!("query method not supported!")
            }
        }
    }

}
