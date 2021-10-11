use clap::Clap;
use anyhow::{bail, Context, Result};
use candid::{
    TypeEnv,
    types::Function,
    IDLProg,
    check_prog,
    IDLArgs,
    types::Type,
    parser::value::IDLValue,
    Decode,
    CandidType
};
use ic_utils::interfaces::management_canister::{
    MgmtMethod,
    builders::CanisterSettings
};
use ic_agent::{Agent, AgentError, NonceFactory, agent::{AgentImpl, agent_error::HttpErrorPayload, status::Status}, export::Principal};
use std::{
    path::PathBuf,
};
use std::str::FromStr;
use serde::Deserialize;
use crate::CanisterInstall;
use crate::Opts;

const DEFAULT_IC_GATEWAY: &str = "https://ic0.app";

#[derive(CandidType, Clone, Deserialize, Debug)]
pub enum WasmType {
    PABToken,
    Board,
    Life,
    AvatarNFT,
    VisaNFT
}

#[derive(CandidType, Deserialize)]
pub struct StoreWASMArgs {
    pub wasm_type: WasmType,
    #[serde(with = "serde_bytes")]
    pub wasm_module: Vec<u8>,
}

#[derive(CandidType, Deserialize)]
pub struct UpgradeArgs {
    pub canister: Principal,
    pub wasm_type: WasmType,
}

#[derive(Clap, Clone)]
pub enum SubCommand {
    Update(CallOpts),
    Query(CallOpts),
}

/// A subcommand for call canister
#[derive(Clap, Clone)]
pub struct CallOpts {
    #[clap(parse(try_from_str), required = true)]
    pub canister_id: Principal,

    /// just Output the serialization of a message to STDOUT.
    #[clap(long)]
    pub serialize: bool,

    /// Path to a candid file to analyze the argument. Otherwise candid will parse the
    /// argument without type hint.
    #[clap(long)]
    pub candid: Option<PathBuf>,

    #[clap(required = true)]
    pub method_name: String,

    #[clap(long, parse(try_from_str))]
    pub up_canister: Option<Principal>,

    /// The type of input (hex or IDL).
    #[clap(long, default_value = "raw")]
    pub arg: ArgType,

    /// The type of output (hex or IDL).
    #[clap(long, default_value = "idl")]
    pub output: ArgType,

    /// Argument to send, in Candid textual format.
    #[clap()]
    pub arg_value: Option<String>,
}


#[derive(Clap, Debug, Clone)]
pub enum ArgType {
    Idl,
    Raw,
}

impl std::str::FromStr for ArgType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "idl" => Ok(ArgType::Idl),
            "raw" => Ok(ArgType::Raw),
            other => Err(format!("invalid argument type: {}", other)),
        }
    }
}

/// Parse IDL file into TypeEnv. This is a best effort function: it will succeed if
/// the IDL file can be parsed and type checked in Rust parser, and has an
/// actor in the IDL file. If anything fails, it returns None.
pub fn get_candid_type(
    idl_path: &std::path::Path,
    method_name: &str,
) -> Result<Option<(TypeEnv, Function)>> {
    let (env, ty) = check_candid_file(idl_path).with_context(|| {
        format!(
            "Failed when checking candid file: {}",
            idl_path.to_string_lossy()
        )
    })?;
    match ty {
        None => Ok(None),
        Some(actor) => {
            let method = env
                .get_method(&actor, method_name)
                .with_context(|| format!("Failed to get method: {}", method_name))?
                .clone();
            Ok(Some((env, method)))
        }
    }
}

pub fn check_candid_file(idl_path: &std::path::Path) -> Result<(TypeEnv, Option<Type>)> {
    let idl_file = std::fs::read_to_string(idl_path)
        .with_context(|| format!("Failed to read Candid file: {}", idl_path.to_string_lossy()))?;
    let ast = idl_file.parse::<IDLProg>().with_context(|| {
        format!(
            "Failed to parse the Candid file: {}",
            idl_path.to_string_lossy()
        )
    })?;
    let mut env = TypeEnv::new();
    let actor = check_prog(&mut env, &ast).with_context(|| {
        format!(
            "Failed to type check the Candid file: {}",
            idl_path.to_string_lossy()
        )
    })?;
    Ok((env, actor))
}

fn blob_from_arguments(
    arguments: Option<&str>,
    arg_type: &ArgType,
    method_type: &Option<(candid::parser::typing::TypeEnv, candid::types::Function)>,
) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let arguments = if arguments == Some("-") {
        use std::io::Read;
        std::io::stdin().read_to_end(&mut buffer).unwrap();
        std::str::from_utf8(&buffer).ok()
    } else {
        arguments
    };

    match arg_type {
        ArgType::Raw => {
            let bytes = hex::decode(&arguments.unwrap_or(""))
                .context("Argument is not a valid hex string")?;
            Ok(bytes)
        }
        ArgType::Idl => {
            let arguments = arguments.unwrap_or("()");
            let args = arguments.parse::<IDLArgs>();
            let typed_args = match method_type {
                None => args
                    .context("Failed to parse arguments with no method type info")?
                    .to_bytes(),
                Some((env, func)) => {
                    let first_char = arguments.chars().next();
                    let is_candid_format = first_char.map_or(false, |c| c == '(');
                    // If parsing fails and method expects a single value, try parsing as IDLValue.
                    // If it still fails, and method expects a text type, send arguments as text.
                    let args = args.or_else(|e| {
                        if func.args.len() == 1 && !is_candid_format {
                            let is_quote = first_char.map_or(false, |c| c == '"');
                            if candid::types::Type::Text == func.args[0] && !is_quote {
                                Ok(IDLValue::Text(arguments.to_string()))
                            } else {
                                arguments.parse::<IDLValue>()
                            }
                                .map(|v| IDLArgs::new(&[v]))
                        } else {
                            Err(e)
                        }
                    });
                    args.context("Failed to parse arguments with method type info")?
                        .to_bytes_with_types(&env, &func.args)
                }
            }
                .context("Failed to serialize Candid values")?;
            Ok(typed_args)
        }
    }
}

fn print_idl_blob(
    blob: &[u8],
    output_type: &ArgType,
    method_type: &Option<(TypeEnv, Function)>,
) -> Result<()> {
    let hex_string = hex::encode(blob);
    match output_type {
        ArgType::Raw => {
            println!("{}", hex_string);
        }
        ArgType::Idl => {
            let result = match method_type {
                None => candid::IDLArgs::from_bytes(blob),
                Some((env, func)) => candid::IDLArgs::from_bytes_with_types(blob, &env, &func.rets),
            };
            println!(
                "{}",
                result.with_context(|| format!("Failed to deserialize blob 0x{}", hex_string))?
            );
        }
    }
    Ok(())
}

async fn fetch_root_key_from_non_ic(agent: &Agent, replica: &str) -> Result<()> {
    let normalized_replica = replica.strip_suffix("/").unwrap_or(replica);
    if normalized_replica != DEFAULT_IC_GATEWAY {
        agent
            .fetch_root_key()
            .await
            .context("Failed to fetch root key from replica")?;
    }
    Ok(())
}

pub fn get_effective_canister_id(
    is_management_canister: bool,
    method_name: &str,
    arg_value: &[u8],
    canister_id: Principal,
) -> Result<Principal> {
    if is_management_canister {
        let method_name = MgmtMethod::from_str(method_name).with_context(|| {
            format!(
                "Attempted to call an unsupported management canister method: {}",
                method_name
            )
        })?;
        match method_name {
            MgmtMethod::CreateCanister | MgmtMethod::RawRand => bail!(
                "{} can only be called via an inter-canister call.",
                method_name.as_ref()
            ),
            MgmtMethod::InstallCode => {
                let install_args = candid::Decode!(arg_value, CanisterInstall)
                    .context("Argument is not valid for CanisterInstall")?;
                Ok(install_args.canister_id)
            }
            MgmtMethod::StartCanister
            | MgmtMethod::StopCanister
            | MgmtMethod::CanisterStatus
            | MgmtMethod::DeleteCanister
            | MgmtMethod::DepositCycles
            | MgmtMethod::UninstallCode
            | MgmtMethod::ProvisionalTopUpCanister => {
                #[derive(CandidType, Deserialize)]
                struct In {
                    canister_id: Principal,
                }
                let in_args =
                    candid::Decode!(arg_value, In).context("Argument is not a valid Principal")?;
                Ok(in_args.canister_id)
            }
            MgmtMethod::ProvisionalCreateCanisterWithCycles => Ok(Principal::management_canister()),
            MgmtMethod::UpdateSettings => {
                #[derive(CandidType, Deserialize)]
                struct In {
                    canister_id: Principal,
                    settings: CanisterSettings,
                }
                let in_args = candid::Decode!(arg_value, In)
                    .context("Argument is not valid for UpdateSettings")?;
                Ok(in_args.canister_id)
            }
        }
    } else {
        Ok(canister_id)
    }
}

pub async fn query_status(agent: &AgentImpl<NonceFactory>) -> Result<Status, AgentError>{
    agent.status().await
}

pub fn print_signed_query(agent: &AgentImpl<NonceFactory>, opts: &Opts, t: &CallOpts){
    let maybe_candid_path = t.candid.as_ref();
    let expire_after: Option<std::time::Duration> = opts.ttl.map(|ht| ht.into());

    let method_type = match maybe_candid_path {
        None => None,
        Some(path) => get_candid_type(&path, &t.method_name).unwrap_or(None),
    };

    let arg = blob_from_arguments(t.arg_value.as_deref(), &t.arg, &method_type)
        .unwrap_or(vec![]);
    let is_management_canister = t.canister_id == Principal::management_canister();
    let effective_canister_id = get_effective_canister_id(
        is_management_canister,
        &t.method_name,
        &arg,
        t.canister_id,
    ).unwrap_or(Principal::anonymous());

    let mut builder = agent.query(&t.canister_id, &t.method_name);
    if let Some(d) = expire_after {
        builder.expire_after(d);
    }
    let signed_query = builder
        .with_arg(arg)
        .with_effective_canister_id(effective_canister_id)
        .sign();
    match signed_query {
        Err(e) => println!("{}", e),
        Ok(query) => {
            let serialized = serde_json::to_string(&query).unwrap();
            println!("{}", serialized);        
        }
    }
}

pub async fn print_signed_update(agent: &AgentImpl<NonceFactory>, opts: &Opts, t: &CallOpts){
    let maybe_candid_path = t.candid.as_ref();
    let expire_after: Option<std::time::Duration> = opts.ttl.map(|ht| ht.into());

    let method_type = match maybe_candid_path {
        None => None,
        Some(path) => get_candid_type(&path, &t.method_name).unwrap_or(None),
    };

    let arg = blob_from_arguments(t.arg_value.as_deref(), &t.arg, &method_type)
        .unwrap_or(vec![]);
    let is_management_canister = t.canister_id == Principal::management_canister();
    let effective_canister_id = get_effective_canister_id(
        is_management_canister,
        &t.method_name,
        &arg,
        t.canister_id,
    ).unwrap_or(Principal::anonymous());

    fetch_root_key_from_non_ic(&agent, &opts.replica).await.unwrap_or(());

    let mut builder = agent.update(&t.canister_id, &t.method_name);
    if let Some(d) = expire_after {
        builder.expire_after(d);
    }
    let signed_update = builder
        .with_arg(arg)
        .with_effective_canister_id(effective_canister_id)
        .sign();
    match signed_update {
        Err(e) => println!("{}", e),
        Ok(update) => {
            let serialized = serde_json::to_string(&update).unwrap();
            println!("{}", serialized);

            let signed_request_status = agent
            .sign_request_status(effective_canister_id, update.request_id);
            match signed_request_status {
                Err(e) => println!("{}", e),
                Ok(request_status) => {
                    let serialized = serde_json::to_string(&request_status).unwrap();
                    println!("{}", serialized);        
                }
            }
        }
    }

}

pub async fn call_query_method(agent: &AgentImpl<NonceFactory>, opts: &Opts, t: &CallOpts) 
-> Result<Vec<u8>, AgentError>
{
    let maybe_candid_path = t.candid.as_ref();
    let expire_after: Option<std::time::Duration> = opts.ttl.map(|ht| ht.into());

    let method_type = match maybe_candid_path {
        None => None,
        Some(path) => get_candid_type(&path, &t.method_name).unwrap_or(None),
    };

    let arg = blob_from_arguments(t.arg_value.as_deref(), &t.arg, &method_type)
        .unwrap_or(vec![]);
    let is_management_canister = t.canister_id == Principal::management_canister();
    let effective_canister_id = get_effective_canister_id(
        is_management_canister,
        &t.method_name,
        &arg,
        t.canister_id,
    ).unwrap_or(Principal::anonymous());

    let mut builder = agent.query(&t.canister_id, &t.method_name);
    if let Some(d) = expire_after {
        builder.expire_after(d);
    }

    builder
        .with_arg(&arg)
        .with_effective_canister_id(effective_canister_id)
        .call()
        .await

}

pub async fn call_update_method(agent: &AgentImpl<NonceFactory>, opts: &Opts, t: &CallOpts)
-> Result<Vec<u8>, AgentError>
{
    let maybe_candid_path = t.candid.as_ref();
    let expire_after: Option<std::time::Duration> = opts.ttl.map(|ht| ht.into());

    let method_type = match maybe_candid_path {
        None => None,
        Some(path) => get_candid_type(&path, &t.method_name).unwrap_or(None),
    };

    let arg = blob_from_arguments(t.arg_value.as_deref(), &t.arg, &method_type)
        .unwrap_or(vec![]);
    let is_management_canister = t.canister_id == Principal::management_canister();
    let effective_canister_id = get_effective_canister_id(
        is_management_canister,
        &t.method_name,
        &arg,
        t.canister_id,
    ).unwrap_or(Principal::anonymous());

    fetch_root_key_from_non_ic(&agent, &opts.replica).await.unwrap_or(());
    let mut builder = agent.update(&t.canister_id, &t.method_name);
    if let Some(d) = expire_after {
        builder.expire_after(d);
    }

    eprint!(".");
    let result = builder
        .with_arg(arg)
        .with_effective_canister_id(effective_canister_id)
        .call_and_wait(
            garcon::Delay::builder()
                .exponential_backoff(std::time::Duration::from_secs(1), 1.1)
                .side_effect(|| {
                    eprint!(".");
                    Ok(())
                })
                .timeout(std::time::Duration::from_secs(60 * 5))
                .build(),
        )
        .await;
    eprintln!();
    result
}

pub fn show_result(result:Result<Vec<u8>,AgentError>, t: &CallOpts){
    let maybe_candid_path = t.candid.as_ref();
    let method_type = match maybe_candid_path {
        None => None,
        Some(path) => get_candid_type(&path, &t.method_name).unwrap_or(None),
    };

    match result {
        Ok(blob) => {
            print_idl_blob(&blob, &t.output, &method_type).unwrap_or(());
        }
        Err(AgentError::TransportError(_)) => println!("AgentError::TransportError"),
        Err(AgentError::HttpError(HttpErrorPayload {
                                      status,
                                      content_type,
                                      content,
                                  })) => {
            let mut error_message =
                format!("Server returned an HTTP Error:\n  Code: {}\n", status);
            match content_type.as_deref() {
                None => error_message
                    .push_str(&format!("  Content: {}\n", hex::encode(content))),
                Some("text/plain; charset=UTF-8") | Some("text/plain") => {
                    error_message.push_str("  ContentType: text/plain\n");
                    error_message.push_str(&format!(
                        "  Content:     {}\n",
                        String::from_utf8_lossy(&content)
                    ));
                }
                Some(x) => {
                    error_message.push_str(&format!("  ContentType: {}\n", x));
                    error_message.push_str(&format!(
                        "  Content:     {}\n",
                        hex::encode(&content)
                    ));
                }
            }
            println!("{}", error_message);
        }
        Err(s) =>  println!("{}", s.to_string()),
    }
}
