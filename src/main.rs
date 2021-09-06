pub mod command;

use clap::{crate_authors, crate_version, Clap};
use futures::executor::block_on;
use ic_agent::{
    agent,
    export::Principal,
    identity::BasicIdentity,
    Agent, Identity,
};
use ic_utils::interfaces::management_canister::{
    builders::CanisterInstall,
};
use ring::signature::Ed25519KeyPair;
use std::{fs::File, io::Read, path::PathBuf, str::FromStr};

#[derive(Clap)]
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

    let agent = Agent::builder()
        .with_transport(
            agent::http_transport::ReqwestHttpReplicaV2Transport::create(opts.replica.clone())
                .expect("Failed to create Transport for Agent"),
        )
        .with_boxed_identity(Box::new(my_identity))
        .build()
        .expect("Failed to build the Agent");

    let mut f = File::open("nft.wasm").expect("no wasm file");
    let mut buffer = Vec::<u8>::new();
    f.read_to_end(&mut buffer).expect("read file error");
    let code = easy_hasher::easy_hasher::Hash::from_vec(&buffer).to_hex_string();

    let copts = command::CallOpts{
        canister_id: Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap(),
        serialize: false,
        candid: Some(PathBuf::from_str("nais_canister.did").unwrap()),
        method_name: "uploadWasm".to_string(),
        arg: command::ArgType::Idl,
        output: command::ArgType::Idl,
        arg_value: Some(code),
    };

    let future = command::call_update_method(&agent, &opts, &copts);
    let result  = block_on(future);
    command::show_result(result, &copts);
}
