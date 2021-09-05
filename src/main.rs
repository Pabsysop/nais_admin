use candid::{
    parser::value::IDLValue,
    types::{Function, Type},
    CandidType, Decode, Deserialize, IDLArgs, IDLProg, TypeEnv,
};
use clap::{crate_authors, crate_version, AppSettings, Clap};
use ic_agent::{
    agent::{self, signed::SignedUpdate, Replied},
    agent::{
        agent_error::HttpErrorPayload,
        signed::{SignedQuery, SignedRequestStatus},
    },
    export::Principal,
    identity::BasicIdentity,
    Agent, AgentError, Identity,
};
use ic_utils::interfaces::management_canister::{
    builders::{CanisterInstall, CanisterSettings},
    MgmtMethod,
};
use ring::signature::Ed25519KeyPair;
use std::{
    collections::VecDeque, convert::TryFrom, io::BufRead, path::PathBuf, process::exit,
    str::FromStr,
};

#[derive(Clap)]
#[clap(
version = crate_version!(),
author = crate_authors!(),
global_setting = AppSettings::GlobalVersion,
global_setting = AppSettings::ColoredHelp
)]
struct Opts {
    /// Some input. Because this isn't an Option<T> it's required to be used
    #[clap(default_value = "http://localhost:8000/")]
    replica: String,

    /// An optional PEM file to read the identity from. If none is passed,
    /// a random identity will be created.
    #[clap(long)]
    pem: Option<PathBuf>,

    /// An optional field to set the expiry time on requests. Can be a human
    /// readable time (like `100s`) or a number of seconds.
    #[clap(long)]
    ttl: Option<humantime::Duration>,

    #[clap(subcommand)]
    subcommand: SubCommand,
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

fn main() {
    let opts: Opts = Opts::parse();

    let my_identity = create_identity(opts.pem);
    let my_principal =  my_identity.sender().expect("not valid identity");

    let agent = Agent::builder()
        .with_transport(
            agent::http_transport::ReqwestHttpReplicaV2Transport::create(opts.replica.clone())
                .context("Failed to create Transport for Agent")?,
        )
        .with_boxed_identity(Box::new(my_identity))
        .build()
        .context("Failed to build the Agent")?;

}
