use cosmwasm_std::{Api, Binary, CanonicalAddr, Env, Extern, HandleResponse, HandleResult, HumanAddr, log, Querier, StdError, StdResult, Storage, to_binary};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use secret_toolkit::permit::RevokedPermits;
use crate::mint_run::{SerialNumber, StoredMintRunInfo};
use crate::msg::{AccessLevel,Send, Burn, ContractStatus, HandleAnswer, Mint, ReceiverInfo, Transfer};
use crate::msg::ResponseStatus::Success;
use crate::query::{burn_list, check_status, get_token, mint_list, process_accesses, ProcessAccInfo, send_list, set_metadata_impl, store_royalties};
use crate::royalties::{RoyaltyInfo, StoredRoyaltyInfo};
use crate::state::{Config, CONFIG_KEY, DEFAULT_ROYALTY_KEY, json_may_load, json_save, load, may_load, MINTERS_KEY, Permission, PermissionType, PREFIX_ALL_PERMISSIONS, PREFIX_INFOS, PREFIX_MINT_RUN, PREFIX_MINT_RUN_NUM, PREFIX_OWNER_PRIV, PREFIX_PRIV_META, PREFIX_PUB_META, PREFIX_RECEIVERS, PREFIX_REVOKED_PERMITS, PREFIX_ROYALTY_INFO, PREFIX_VIEW_KEY, PRNG_SEED_KEY, ReceiveRegistration, remove, save};
use crate::token::{Metadata, Token};
use crate::utils::expiration::Expiration;
use crate::utils::viewing_key::ViewingKey;

/// Returns HandleResult
///
/// mint a new token
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
/// * `token_id` - optional token id, if not specified, use token index
/// * `owner` - optional owner of this token, if not specified, use the minter's address
/// * `public_metadata` - optional public metadata viewable by everyone
/// * `private_metadata` - optional private metadata viewable only by owner and whitelist
/// * `serial_number` - optional serial number information for this token
/// * `royalty_info` - optional royalties information for this token
/// * `transferable` - optionally true if this token is transferable
/// * `memo` - optional memo for the mint tx
#[allow(clippy::too_many_arguments)]
pub fn mint<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    token_id: Option<String>,
    owner: Option<HumanAddr>,
    public_metadata: Option<Metadata>,
    private_metadata: Option<Metadata>,
    serial_number: Option<SerialNumber>,
    royalty_info: Option<RoyaltyInfo>,
    transferable: Option<bool>,
    memo: Option<String>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let minters: Vec<CanonicalAddr> = may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_default();
    if !minters.contains(&sender_raw) {
        return Err(StdError::generic_err(
            "Only designated minters are allowed to mint",
        ));
    }
    let mints = vec![Mint {
        token_id,
        owner,
        public_metadata,
        private_metadata,
        serial_number,
        royalty_info,
        transferable,
        memo,
    }];
    let mut minted = mint_list(deps, &env, config, &sender_raw, mints)?;
    let minted_str = minted.pop().unwrap_or_default();
    Ok(HandleResponse {
        messages: vec![],
        log: vec![log("minted", &minted_str)],
        data: Some(to_binary(&HandleAnswer::MintNft {
            token_id: minted_str,
        })?),
    })
}

/// Returns HandleResult
///
/// mints many tokens
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `mints` - the list of mints to perform
pub fn batch_mint<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    mints: Vec<Mint>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let minters: Vec<CanonicalAddr> = may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_default();
    if !minters.contains(&sender_raw) {
        return Err(StdError::generic_err(
            "Only designated minters are allowed to mint",
        ));
    }
    let minted = mint_list(deps, &env, config, &sender_raw, mints)?;
    Ok(HandleResponse {
        messages: vec![],
        log: vec![log("minted", format!("{:?}", &minted))],
        data: Some(to_binary(&HandleAnswer::BatchMintNft {
            token_ids: minted,
        })?),
    })
}

/// Returns HandleResult
///
/// mints clones of a token
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
/// * `mint_run_id` - optional id used to track subsequent mint runs
/// * `quantity` - number of clones to mint
/// * `owner` - optional owner of this token, if not specified, use the minter's address
/// * `public_metadata` - optional public metadata viewable by everyone
/// * `private_metadata` - optional private metadata viewable only by owner and whitelist
/// * `royalty_info` - optional royalties information for these clones
/// * `memo` - optional memo for the mint txs
#[allow(clippy::too_many_arguments)]
pub fn mint_clones<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    mint_run_id: Option<&String>,
    quantity: u32,
    owner: Option<HumanAddr>,
    public_metadata: Option<Metadata>,
    private_metadata: Option<Metadata>,
    royalty_info: Option<RoyaltyInfo>,
    memo: Option<String>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let minters: Vec<CanonicalAddr> = may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_default();
    if !minters.contains(&sender_raw) {
        return Err(StdError::generic_err(
            "Only designated minters are allowed to mint",
        ));
    }
    if quantity == 0 {
        return Err(StdError::generic_err("Quantity can not be zero"));
    }
    let mint_run = mint_run_id
        .map(|i| {
            let key = i.as_bytes();
            let mut run_store = PrefixedStorage::new(PREFIX_MINT_RUN_NUM, &mut deps.storage);
            let last_num: u32 = may_load(&run_store, key)?.unwrap_or(0);
            let this_num: u32 = last_num.checked_add(1).ok_or_else(|| {
                StdError::generic_err(format!(
                    "Mint run ID {} has already reached its maximum possible value",
                    i
                ))
            })?;
            save(&mut run_store, key, &this_num)?;
            Ok(this_num)
        })
        .transpose()?;
    let mut serial_number = SerialNumber {
        mint_run,
        serial_number: 1,
        quantity_minted_this_run: Some(quantity),
    };
    let mut mints: Vec<Mint> = Vec::new();
    for _ in 0..quantity {
        mints.push(Mint {
            token_id: None,
            owner: owner.clone(),
            public_metadata: public_metadata.clone(),
            private_metadata: private_metadata.clone(),
            serial_number: Some(serial_number.clone()),
            royalty_info: royalty_info.clone(),
            transferable: Some(true),
            memo: memo.clone(),
        });
        serial_number.serial_number += 1;
    }
    let mut minted = mint_list(deps, &env, config, &sender_raw, mints)?;
    // if mint_list did not error, there must be at least one token id
    let first_minted = minted
        .first()
        .ok_or_else(|| StdError::generic_err("List of minted tokens is empty"))?
        .clone();
    let last_minted = minted
        .pop()
        .ok_or_else(|| StdError::generic_err("List of minted tokens is empty"))?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![
            log("first_minted", &first_minted),
            log("last_minted", &last_minted),
        ],
        data: Some(to_binary(&HandleAnswer::MintNftClones {
            first_minted,
            last_minted,
        })?),
    })
}

/// Returns HandleResult
///
/// sets new public and/or private metadata
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
/// * `token_id` - token id String slice of token whose metadata should be updated
/// * `public_metadata` - the optional new public metadata viewable by everyone
/// * `private_metadata` - the optional new private metadata viewable by everyone
pub fn set_metadata<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    token_id: &str,
    public_metadata: Option<Metadata>,
    private_metadata: Option<Metadata>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let custom_err = format!("Not authorized to update metadata of token {}", token_id);
    // if token supply is private, don't leak that the token id does not exist
    // instead just say they are not authorized for that token
    let opt_err = if config.token_supply_is_public {
        None
    } else {
        Some(&*custom_err)
    };
    let (token, idx) = get_token(&deps.storage, token_id, opt_err)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    if !(token.owner == sender_raw && config.owner_may_update_metadata) {
        let minters: Vec<CanonicalAddr> = may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_default();
        if !(minters.contains(&sender_raw) && config.minter_may_update_metadata) {
            return Err(StdError::generic_err(custom_err));
        }
    }
    if let Some(public) = public_metadata {
        set_metadata_impl(&mut deps.storage, &token, idx, PREFIX_PUB_META, &public)?;
    }
    if let Some(private) = private_metadata {
        set_metadata_impl(&mut deps.storage, &token, idx, PREFIX_PRIV_META, &private)?;
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetMetadata { status: Success })?),
    })
}

/// Returns HandleResult
///
/// sets new royalty information for a specified token or if no token ID is provided, sets new
/// royalty information as the contract's default
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
/// * `token_id` - optional token id String slice of token whose royalty info should be updated
/// * `royalty_info` - a optional reference to the new RoyaltyInfo
pub fn set_royalty_info<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    token_id: Option<&str>,
    royalty_info: Option<&RoyaltyInfo>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    // set a token's royalties
    if let Some(id) = token_id {
        let custom_err = "A token's RoyaltyInfo may only be set by the token creator when they are also the token owner";
        // if token supply is private, don't leak that the token id does not exist
        // instead just say they are not authorized for that token
        let opt_err = if config.token_supply_is_public {
            None
        } else {
            Some(custom_err)
        };
        let (token, idx) = get_token(&deps.storage, id, opt_err)?;
        if !token.transferable {
            return Err(StdError::generic_err(
                "Non-transferable tokens can not be sold, so royalties are meaningless",
            ));
        }
        let token_key = idx.to_le_bytes();
        let run_store = ReadonlyPrefixedStorage::new(PREFIX_MINT_RUN, &deps.storage);
        let mint_run: StoredMintRunInfo = load(&run_store, &token_key)?;
        if sender_raw != mint_run.token_creator || sender_raw != token.owner {
            return Err(StdError::generic_err(custom_err));
        }
        let default_roy = royalty_info.as_ref().map_or_else(
            || may_load::<StoredRoyaltyInfo, _>(&deps.storage, DEFAULT_ROYALTY_KEY),
            |_r| Ok(None),
        )?;
        let mut roy_store = PrefixedStorage::new(PREFIX_ROYALTY_INFO, &mut deps.storage);
        store_royalties(
            &mut roy_store,
            &deps.api,
            royalty_info,
            default_roy.as_ref(),
            &token_key,
        )?;
        // set default royalty
    } else {
        let minters: Vec<CanonicalAddr> = may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_default();
        if !minters.contains(&sender_raw) {
            return Err(StdError::generic_err(
                "Only designated minters can set default royalties for the contract",
            ));
        }
        store_royalties(
            &mut deps.storage,
            &deps.api,
            royalty_info,
            None,
            DEFAULT_ROYALTY_KEY,
        )?;
    };

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetRoyaltyInfo {
            status: Success,
        })?),
    })
}

/// Returns HandleResult
///
/// makes the sealed private metadata public
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
/// * `token_id` - token id String slice of token whose metadata should be updated
pub fn reveal<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    token_id: &str,
) -> HandleResult {
    check_status(config.status, priority)?;
    if !config.sealed_metadata_is_enabled {
        return Err(StdError::generic_err(
            "Sealed metadata functionality is not enabled for this contract",
        ));
    }
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let custom_err = format!("You do not own token {}", token_id);
    // if token supply is private, don't leak that the token id does not exist
    // instead just say they do not own that token
    let opt_err = if config.token_supply_is_public {
        None
    } else {
        Some(&*custom_err)
    };
    let (mut token, idx) = get_token(&deps.storage, token_id, opt_err)?;
    if token.unwrapped {
        return Err(StdError::generic_err(
            "This token has already been unwrapped",
        ));
    }
    if token.owner != sender_raw {
        return Err(StdError::generic_err(custom_err));
    }
    token.unwrapped = true;
    let token_key = idx.to_le_bytes();
    let mut info_store = PrefixedStorage::new(PREFIX_INFOS, &mut deps.storage);
    json_save(&mut info_store, &token_key, &token)?;
    if !config.unwrap_to_private {
        let mut priv_store = PrefixedStorage::new(PREFIX_PRIV_META, &mut deps.storage);
        let may_priv: Option<Metadata> = may_load(&priv_store, &token_key)?;
        if let Some(metadata) = may_priv {
            remove(&mut priv_store, &token_key);
            let mut pub_store = PrefixedStorage::new(PREFIX_PUB_META, &mut deps.storage);
            save(&mut pub_store, &token_key, &metadata)?;
        }
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Reveal { status: Success })?),
    })
}

/// Returns HandleResult
///
/// grants/revokes trasfer permission on a token
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
/// * `spender` - a reference to the address being granted permission
/// * `token_id` - string slice of the token id to grant permission to
/// * `expires` - optional Expiration for this approval
/// * `is_approve` - true if this is an Approve call
#[allow(clippy::too_many_arguments)]
pub fn approve_revoke<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    spender: &HumanAddr,
    token_id: &str,
    expires: Option<Expiration>,
    is_approve: bool,
) -> HandleResult {
    check_status(config.status, priority)?;
    let address_raw = deps.api.canonical_address(spender)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let custom_err = format!(
        "Not authorized to grant/revoke transfer permission for token {}",
        token_id
    );
    // if token supply is private, don't leak that the token id does not exist
    // instead just say they are not authorized for that token
    let opt_err = if config.token_supply_is_public {
        None
    } else {
        Some(&*custom_err)
    };
    let (token, idx) = get_token(&deps.storage, token_id, opt_err)?;
    let mut all_perm: Option<Vec<Permission>> = None;
    let mut from_oper = false;
    let transfer_idx = PermissionType::Transfer.to_usize();
    // if not called by the owner, check if message sender has operator status
    if token.owner != sender_raw {
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let may_list: Option<Vec<Permission>> = json_may_load(&all_store, token.owner.as_slice())?;
        if let Some(list) = may_list.clone() {
            if let Some(perm) = list.iter().find(|&p| p.address == sender_raw) {
                if let Some(exp) = perm.expirations[transfer_idx] {
                    if exp.is_expired(&env.block) {
                        return Err(StdError::generic_err(format!(
                            "Transfer authority for all tokens of {} has expired",
                            &deps.api.human_address(&token.owner)?
                        )));
                    } else {
                        from_oper = true;
                    }
                }
            }
        }
        if !from_oper {
            return Err(StdError::generic_err(custom_err));
        }
        all_perm = may_list;
    }
    let mut accesses: [Option<AccessLevel>; 3] = [None, None, None];
    let response: HandleAnswer;
    if is_approve {
        accesses[transfer_idx] = Some(AccessLevel::ApproveToken);
        response = HandleAnswer::Approve { status: Success };
    } else {
        accesses[transfer_idx] = Some(AccessLevel::RevokeToken);
        response = HandleAnswer::Revoke { status: Success };
    }
    let owner = token.owner.clone();
    let mut proc_info = ProcessAccInfo {
        token,
        idx,
        token_given: true,
        accesses,
        expires,
        from_oper,
    };
    process_accesses(
        &mut deps.storage,
        &env,
        &address_raw,
        &owner,
        &mut proc_info,
        all_perm,
    )?;
    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&response)?),
    };
    Ok(res)
}

/// Returns HandleResult
///
/// makes an address' token ownership private
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
pub fn make_owner_private<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    // only need to do this if the contract has public ownership
    if config.owner_is_public {
        let mut priv_store = PrefixedStorage::new(PREFIX_OWNER_PRIV, &mut deps.storage);
        save(&mut priv_store, sender_raw.as_slice(), &false)?
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::MakeOwnershipPrivate {
            status: Success,
        })?),
    })
}

/// Returns HandleResult
///
/// adds/revokes access for everyone
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
/// * `token_id` - optional token id to apply approvals to
/// * `view_owner` - optional access level for viewing token ownership
/// * `view_private_metadata` - optional access level for viewing private metadata
/// * `expires` - optional Expiration for this approval
#[allow(clippy::too_many_arguments)]
pub fn set_global_approval<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    token_id: Option<String>,
    view_owner: Option<AccessLevel>,
    view_private_metadata: Option<AccessLevel>,
    expires: Option<Expiration>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let token_given: bool;
    // use this "address" to represent global permission
    let global_raw = CanonicalAddr(Binary::from(b"public"));
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let mut custom_err = String::new();
    let (token, idx) = if let Some(id) = token_id {
        token_given = true;
        custom_err = format!("You do not own token {}", id);
        // if token supply is private, don't leak that the token id does not exist
        // instead just say they do not own that token
        let opt_err = if config.token_supply_is_public {
            None
        } else {
            Some(&*custom_err)
        };
        get_token(&deps.storage, &id, opt_err)?
    } else {
        token_given = false;
        (
            Token {
                owner: sender_raw.clone(),
                permissions: Vec::new(),
                unwrapped: false,
                transferable: true,
            },
            0,
        )
    };
    // if trying to set token permissions when you are not the owner
    if token_given && token.owner != sender_raw {
        return Err(StdError::generic_err(custom_err));
    }
    let mut accesses: [Option<AccessLevel>; 3] = [None, None, None];
    accesses[PermissionType::ViewOwner.to_usize()] = view_owner;
    accesses[PermissionType::ViewMetadata.to_usize()] = view_private_metadata;
    let mut proc_info = ProcessAccInfo {
        token,
        idx,
        token_given,
        accesses,
        expires,
        from_oper: false,
    };
    process_accesses(
        &mut deps.storage,
        &env,
        &global_raw,
        &sender_raw,
        &mut proc_info,
        None,
    )?;
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetGlobalApproval {
            status: Success,
        })?),
    })
}

/// Returns HandleResult
///
/// sets specified permissions for an address
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
/// * `address` - a reference to the address being granted permission
/// * `token_id` - optional token id to apply approvals to
/// * `view_owner` - optional access level for viewing token ownership
/// * `view_private_metadata` - optional access level for viewing private metadata
/// * `transfer` - optional access level for transferring tokens
/// * `expires` - optional Expiration for this approval
/// * `response_type` - which response to return for SetWhitelistedApproval, ApproveAll, or RevokeAll
#[allow(clippy::too_many_arguments)]
pub fn set_whitelisted_approval<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    address: &HumanAddr,
    token_id: Option<String>,
    view_owner: Option<AccessLevel>,
    view_private_metadata: Option<AccessLevel>,
    transfer: Option<AccessLevel>,
    expires: Option<Expiration>,
    response_type: SetAppResp,
) -> HandleResult {
    check_status(config.status, priority)?;
    let token_given: bool;
    let address_raw = deps.api.canonical_address(address)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let mut custom_err = String::new();
    let (token, idx) = if let Some(id) = token_id {
        token_given = true;
        custom_err = format!("You do not own token {}", id);
        // if token supply is private, don't leak that the token id does not exist
        // instead just say they do not own that token
        let opt_err = if config.token_supply_is_public {
            None
        } else {
            Some(&*custom_err)
        };
        get_token(&deps.storage, &id, opt_err)?
    } else {
        token_given = false;
        (
            Token {
                owner: sender_raw.clone(),
                permissions: Vec::new(),
                unwrapped: false,
                transferable: true,
            },
            0,
        )
    };
    // if trying to set token permissions when you are not the owner
    if token_given && token.owner != sender_raw {
        return Err(StdError::generic_err(custom_err));
    }
    let mut accesses: [Option<AccessLevel>; 3] = [None, None, None];
    accesses[PermissionType::ViewOwner.to_usize()] = view_owner;
    accesses[PermissionType::ViewMetadata.to_usize()] = view_private_metadata;
    accesses[PermissionType::Transfer.to_usize()] = transfer;
    let mut proc_info = ProcessAccInfo {
        token,
        idx,
        token_given,
        accesses,
        expires,
        from_oper: false,
    };
    process_accesses(
        &mut deps.storage,
        &env,
        &address_raw,
        &sender_raw,
        &mut proc_info,
        None,
    )?;
    let response = match response_type {
        SetAppResp::SetWhitelistedApproval => {
            HandleAnswer::SetWhitelistedApproval { status: Success }
        }
        SetAppResp::ApproveAll => HandleAnswer::ApproveAll { status: Success },
        SetAppResp::RevokeAll => HandleAnswer::RevokeAll { status: Success },
    };
    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&response)?),
    };
    Ok(res)
}

/// Returns HandleResult
///
/// burns many tokens
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `burns` - the list of burns to perform
pub fn batch_burn_nft<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    burns: Vec<Burn>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    burn_list(deps, &env.block, config, &sender_raw, burns)?;
    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::BatchBurnNft { status: Success })?),
    };
    Ok(res)
}

/// Returns HandleResult
///
/// burns a token
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `token_id` - token id String of token to be burnt
/// * `memo` - optional memo for the burn tx
pub fn burn_nft<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    token_id: String,
    memo: Option<String>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let burns = vec![Burn {
        token_ids: vec![token_id],
        memo,
    }];
    burn_list(deps, &env.block, config, &sender_raw, burns)?;
    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::BurnNft { status: Success })?),
    };
    Ok(res)
}

/// Returns HandleResult
///
/// transfer many tokens
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `transfers` - list of transfers to perform
pub fn batch_transfer_nft<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    transfers: Vec<Transfer>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let _m = send_list(deps, &env, config, &sender_raw, Some(transfers), None)?;

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::BatchTransferNft {
            status: Success,
        })?),
    };
    Ok(res)
}

/// Returns HandleResult
///
/// transfer a token
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `recipient` - the address receiving the token
/// * `token_id` - token id String of token to be transferred
/// * `memo` - optional memo for the mint tx
pub fn transfer_nft<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    recipient: HumanAddr,
    token_id: String,
    memo: Option<String>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let transfers = Some(vec![Transfer {
        recipient,
        token_ids: vec![token_id],
        memo,
    }]);
    let _m = send_list(deps, &env, config, &sender_raw, transfers, None)?;

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::TransferNft { status: Success })?),
    };
    Ok(res)
}

/// Returns HandleResult
///
/// sends tokens to contracts, and calls those contracts' ReceiveNft.  Will error if any
/// contract has not registered its ReceiveNft
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `sends` - list of SendNfts to perform
pub fn batch_send_nft<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    sends: Vec<Send>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let messages = send_list(deps, &env, config, &sender_raw, None, Some(sends))?;

    let res = HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::BatchSendNft { status: Success })?),
    };
    Ok(res)
}

/// Returns HandleResult
///
/// sends a token to a contract, and calls that contract's ReceiveNft.  Will error if the
/// contract has not registered its ReceiveNft
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `contract` - the address of the contract receiving the token
/// * `receiver_info` - optional code hash and BatchReceiveNft implementation status of
///                     the recipient contract
/// * `token_id` - ID String of the token that was sent
/// * `msg` - optional msg used to control ReceiveNft logic
/// * `memo` - optional memo for the mint tx
#[allow(clippy::too_many_arguments)]
pub fn send_nft<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    contract: HumanAddr,
    receiver_info: Option<ReceiverInfo>,
    token_id: String,
    msg: Option<Binary>,
    memo: Option<String>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let sends = Some(vec![Send {
        contract,
        receiver_info,
        token_ids: vec![token_id],
        msg,
        memo,
    }]);
    let messages = send_list(deps, &env, config, &sender_raw, None, sends)?;

    let res = HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SendNft { status: Success })?),
    };
    Ok(res)
}

/// Returns HandleResult
///
/// registers a contract's ReceiveNft
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `code_hash` - code hash String of the registering contract
/// * `impl_batch` - optionally true if the contract also implements BatchReceiveNft
pub fn register_receive_nft<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    code_hash: String,
    impl_batch: Option<bool>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let regrec = ReceiveRegistration {
        code_hash,
        impl_batch: impl_batch.unwrap_or(false),
    };
    let mut store = PrefixedStorage::new(PREFIX_RECEIVERS, &mut deps.storage);
    save(&mut store, sender_raw.as_slice(), &regrec)?;
    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::RegisterReceiveNft {
            status: Success,
        })?),
    };
    Ok(res)
}

/// Returns HandleResult
///
/// creates a viewing key
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `entropy` - string slice of the input String to be used as entropy in randomization
pub fn create_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    entropy: &str,
) -> HandleResult {
    check_status(config.status, priority)?;
    let prng_seed: Vec<u8> = load(&deps.storage, PRNG_SEED_KEY)?;
    let key = ViewingKey::new(&env, &prng_seed, entropy.as_ref());
    let message_sender = deps.api.canonical_address(&env.message.sender)?;
    let mut key_store = PrefixedStorage::new(PREFIX_VIEW_KEY, &mut deps.storage);
    save(&mut key_store, message_sender.as_slice(), &key.to_hashed())?;
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ViewingKey {
            key: format!("{}", key),
        })?),
    })
}

/// Returns HandleResult
///
/// sets the viewing key to the input String
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `key` - String to be used as the viewing key
pub fn set_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    key: String,
) -> HandleResult {
    check_status(config.status, priority)?;
    let vk = ViewingKey(key.clone());
    let message_sender = deps.api.canonical_address(&env.message.sender)?;
    let mut key_store = PrefixedStorage::new(PREFIX_VIEW_KEY, &mut deps.storage);
    save(&mut key_store, message_sender.as_slice(), &vk.to_hashed())?;
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ViewingKey { key })?),
    })
}

/// Returns HandleResult
///
/// add a list of minters
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `new_minters` - list of minter addresses to add
pub fn add_minters<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    new_minters: &[HumanAddr],
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    if config.admin != sender_raw {
        return Err(StdError::generic_err(
            "This is an admin command and can only be run from the admin address",
        ));
    }
    let mut minters: Vec<CanonicalAddr> = may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_default();
    let old_len = minters.len();
    for minter in new_minters {
        let minter_raw = deps.api.canonical_address(minter)?;
        if !minters.contains(&minter_raw) {
            minters.push(minter_raw);
        }
    }
    // only save if the list changed
    if old_len != minters.len() {
        save(&mut deps.storage, MINTERS_KEY, &minters)?;
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::AddMinters { status: Success })?),
    })
}

/// Returns HandleResult
///
/// remove a list of minters
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `no_minters` - list of minter addresses to remove
pub fn remove_minters<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    no_minters: &[HumanAddr],
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    if config.admin != sender_raw {
        return Err(StdError::generic_err(
            "This is an admin command and can only be run from the admin address",
        ));
    }
    let may_minters: Option<Vec<CanonicalAddr>> = may_load(&deps.storage, MINTERS_KEY)?;
    if let Some(mut minters) = may_minters {
        let old_len = minters.len();
        let no_raw: Vec<CanonicalAddr> = no_minters
            .iter()
            .map(|x| deps.api.canonical_address(x))
            .collect::<StdResult<Vec<CanonicalAddr>>>()?;
        minters.retain(|m| !no_raw.contains(m));
        let new_len = minters.len();
        if new_len > 0 {
            if old_len != new_len {
                save(&mut deps.storage, MINTERS_KEY, &minters)?;
            }
        } else {
            remove(&mut deps.storage, MINTERS_KEY);
        }
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::RemoveMinters { status: Success })?),
    })
}

/// Returns HandleResult
///
/// define the exact list of minters
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `human_minters` - exact list of minter addresses
pub fn set_minters<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    human_minters: &[HumanAddr],
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    if config.admin != sender_raw {
        return Err(StdError::generic_err(
            "This is an admin command and can only be run from the admin address",
        ));
    }
    // remove duplicates from the minters list
    let minters_raw: Vec<CanonicalAddr> = human_minters
        .iter()
        .map(|x| deps.api.canonical_address(x))
        .collect::<StdResult<Vec<CanonicalAddr>>>()?;
    let mut sortable: Vec<&[u8]> = minters_raw.iter().map(|x| x.as_slice()).collect();
    sortable.sort_unstable();
    sortable.dedup();
    let minters: Vec<CanonicalAddr> = sortable
        .iter()
        .map(|x| CanonicalAddr(Binary(x.to_vec())))
        .collect();
    if minters.is_empty() {
        remove(&mut deps.storage, MINTERS_KEY);
    } else {
        save(&mut deps.storage, MINTERS_KEY, &minters)?;
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetMinters { status: Success })?),
    })
}

/// Returns HandleResult
///
/// change the admin address
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `address` - new admin address
pub fn change_admin<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    address: &HumanAddr,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    if config.admin != sender_raw {
        return Err(StdError::generic_err(
            "This is an admin command and can only be run from the admin address",
        ));
    }
    let new_admin = deps.api.canonical_address(address)?;
    if new_admin != config.admin {
        config.admin = new_admin;
        save(&mut deps.storage, CONFIG_KEY, &config)?;
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ChangeAdmin { status: Success })?),
    })
}

/// Returns HandleResult
///
/// set the contract status level
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `level` - new ContractStatus
pub fn set_contract_status<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    level: ContractStatus,
) -> HandleResult {
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    if config.admin != sender_raw {
        return Err(StdError::generic_err(
            "This is an admin command and can only be run from the admin address",
        ));
    }
    let new_status = level.to_u8();
    if config.status != new_status {
        config.status = new_status;
        save(&mut deps.storage, CONFIG_KEY, &config)?;
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetContractStatus {
            status: Success,
        })?),
    })
}

/// Returns HandleResult
///
/// revoke the ability to use a specified permit
///
/// # Arguments
///
/// * `storage` - mutable reference to the contract's storage
/// * `sender` - a reference to the message sender
/// * `permit_name` - string slice of the name of the permit to revoke
pub fn revoke_permit<S: Storage>(
    storage: &mut S,
    sender: &HumanAddr,
    permit_name: &str,
) -> HandleResult {
    RevokedPermits::revoke_permit(storage, PREFIX_REVOKED_PERMITS, sender, permit_name);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::RevokePermit { status: Success })?),
    })
}
// enum used to return correct response from SetWhitelistedApproval
pub enum SetAppResp {
    SetWhitelistedApproval,
    ApproveAll,
    RevokeAll,
}