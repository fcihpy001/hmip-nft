// use cosmwasm_std::{
//     log, to_binary, Api, Binary, BlockInfo, CanonicalAddr, CosmosMsg, Env, Extern, HandleResponse,
//     HandleResult, HumanAddr, InitResponse, InitResult, Querier, QueryResult, ReadonlyStorage,
//     StdError, StdResult, Storage, WasmMsg,
// };
// use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
// use primitive_types::U256;
// /// This contract implements SNIP-721 standard:
// /// https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-721.md
// use std::collections::HashSet;
//
// use secret_toolkit::{
//     permit::{validate, Permit, RevokedPermits},
//     utils::{pad_handle_result, pad_query_result},
// };
//
// use crate::utils::expiration::Expiration;
// use crate::inventory::{Inventory, InventoryIter};
// use crate::mint_run::{SerialNumber, StoredMintRunInfo};
// use crate::msg::{
//     AccessLevel, BatchNftDossierElement, Burn, ContractStatus, Cw721Approval, Cw721OwnerOfResponse,
//     HandleAnswer, HandleMsg, InitMsg, Mint, QueryAnswer, QueryMsg, QueryWithPermit, ReceiverInfo,
//     ResponseStatus::Success, Send, Snip721Approval, Transfer, ViewerInfo,
// };
// use crate::receiver::{batch_receive_nft_msg, receive_nft_msg};
// use crate::royalties::{RoyaltyInfo, StoredRoyaltyInfo};
// use crate::state::{
//     get_txs, json_may_load, json_save, load, may_load, remove, save, store_burn, store_mint,
//     store_transfer, AuthList, Config, Permission, PermissionType, ReceiveRegistration, BLOCK_KEY,
//     CONFIG_KEY, CREATOR_KEY, DEFAULT_ROYALTY_KEY, MINTERS_KEY, MY_ADDRESS_KEY,
//     PREFIX_ALL_PERMISSIONS, PREFIX_AUTHLIST, PREFIX_INFOS, PREFIX_MAP_TO_ID, PREFIX_MAP_TO_INDEX,
//     PREFIX_MINT_RUN, PREFIX_MINT_RUN_NUM, PREFIX_OWNER_PRIV, PREFIX_PRIV_META, PREFIX_PUB_META,
//     PREFIX_RECEIVERS, PREFIX_REVOKED_PERMITS, PREFIX_ROYALTY_INFO, PREFIX_VIEW_KEY, PRNG_SEED_KEY,
// };
// use crate::token::{Metadata, Token};
// use crate::utils::rand::sha_256;
// use crate::utils::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};

use cosmwasm_std::{Api, CosmosMsg, Env, Extern, HandleResult, InitResponse, InitResult, Querier, QueryResult, Storage, to_binary, WasmMsg};
use secret_toolkit::utils::{pad_handle_result, pad_query_result};
use crate::handle::{add_minters, approve_revoke, batch_burn_nft, batch_mint, batch_send_nft, batch_transfer_nft, burn_nft, change_admin, create_key, make_owner_private, mint, mint_clones, register_receive_nft, remove_minters, reveal, revoke_permit, send_nft, set_contract_status, set_global_approval, set_key, set_metadata, set_minters, set_royalty_info, set_whitelisted_approval, SetAppResp, transfer_nft};
use crate::msg::{AccessLevel, ContractStatus, HandleMsg, InitMsg, QueryAnswer, QueryMsg, ViewerInfo};
use crate::query::{permit_queries, query_all_nft_info, query_all_tokens, query_approved_for_all, query_batch_nft_dossier, query_code_hash, query_config, query_contract_creator, query_contract_info, query_inventory_approvals, query_is_transferable, query_is_unwrapped, query_minters, query_nft_dossier, query_nft_info, query_num_owner_tokens, query_num_tokens, query_owner_of, query_private_meta, query_royalty, query_token_approvals, query_tokens, query_transactions, query_verify_approval, store_royalties};
use crate::state::{BLOCK_KEY, Config, CONFIG_KEY, CREATOR_KEY, DEFAULT_ROYALTY_KEY, load, MINTERS_KEY, MY_ADDRESS_KEY, PRNG_SEED_KEY, save};
use crate::utils::rand::sha_256;

/// pad handle responses and log attributes to blocks of 256 bytes to prevent leaking info based on
/// response size
pub const BLOCK_SIZE: usize = 256;
/// max number of token ids to keep in id list block
pub const ID_BLOCK_SIZE: u32 = 64;

////////////////////////////////////// Init ///////////////////////////////////////
/// Returns InitResult
///
/// Initializes the contract
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `msg` - InitMsg passed in with the instantiation message
pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> InitResult {
    let creator_raw = deps.api.canonical_address(&env.message.sender)?;
    save(&mut deps.storage, CREATOR_KEY, &creator_raw)?;
    save(
        &mut deps.storage,
        MY_ADDRESS_KEY,
        &deps.api.canonical_address(&env.contract.address)?,
    )?;
    let admin_raw = msg
        .admin
        .map(|a| deps.api.canonical_address(&a))
        .transpose()?
        .unwrap_or(creator_raw);
    let prng_seed: Vec<u8> = sha_256(base64::encode(msg.entropy).as_bytes()).to_vec();
    let init_config = msg.config.unwrap_or_default();

    let config = Config {
        name: msg.name,
        symbol: msg.symbol,
        admin: admin_raw.clone(),
        mint_cnt: 0,
        tx_cnt: 0,
        token_cnt: 0,
        status: ContractStatus::Normal.to_u8(),
        token_supply_is_public: init_config.public_token_supply.unwrap_or(false),
        owner_is_public: init_config.public_owner.unwrap_or(false),
        sealed_metadata_is_enabled: init_config.enable_sealed_metadata.unwrap_or(false),
        unwrap_to_private: init_config.unwrapped_metadata_is_private.unwrap_or(false),
        minter_may_update_metadata: init_config.minter_may_update_metadata.unwrap_or(true),
        owner_may_update_metadata: init_config.owner_may_update_metadata.unwrap_or(false),
        burn_is_enabled: init_config.enable_burn.unwrap_or(false),
    };

    let minters = vec![admin_raw];
    save(&mut deps.storage, CONFIG_KEY, &config)?;
    save(&mut deps.storage, MINTERS_KEY, &minters)?;
    save(&mut deps.storage, PRNG_SEED_KEY, &prng_seed)?;
    // TODO remove this after BlockInfo becomes available to queries
    save(&mut deps.storage, BLOCK_KEY, &env.block)?;

    if msg.royalty_info.is_some() {
        store_royalties(
            &mut deps.storage,
            &deps.api,
            msg.royalty_info.as_ref(),
            None,
            DEFAULT_ROYALTY_KEY,
        )?;
    }

    // perform the post init callback if needed
    let messages: Vec<CosmosMsg> = if let Some(callback) = msg.post_init_callback {
        let execute = WasmMsg::Execute {
            msg: callback.msg,
            contract_addr: callback.contract_address,
            callback_code_hash: callback.code_hash,
            send: callback.send,
        };
        vec![execute.into()]
    } else {
        Vec::new()
    };
    Ok(InitResponse {
        messages,
        log: vec![],
    })
}

///////////////////////////////////// Handle //////////////////////////////////////
/// Returns HandleResult
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `msg` - HandleMsg passed in with the execute message
pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> HandleResult {
    // TODO remove this after BlockInfo becomes available to queries
    save(&mut deps.storage, BLOCK_KEY, &env.block)?;
    let mut config: Config = load(&deps.storage, CONFIG_KEY)?;

    let response = match msg {
        HandleMsg::MintNft {
            token_id,
            owner,
            public_metadata,
            private_metadata,
            serial_number,
            royalty_info,
            transferable,
            memo,
            ..
        } => mint(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            token_id,
            owner,
            public_metadata,
            private_metadata,
            serial_number,
            royalty_info,
            transferable,
            memo,
        ),
        HandleMsg::BatchMintNft { mints, .. } => batch_mint(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            mints,
        ),
        HandleMsg::MintNftClones {
            mint_run_id,
            quantity,
            owner,
            public_metadata,
            private_metadata,
            royalty_info,
            memo,
            ..
        } => mint_clones(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            mint_run_id.as_ref(),
            quantity,
            owner,
            public_metadata,
            private_metadata,
            royalty_info,
            memo,
        ),
        HandleMsg::SetMetadata {
            token_id,
            public_metadata,
            private_metadata,
            ..
        } => set_metadata(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &token_id,
            public_metadata,
            private_metadata,
        ),
        HandleMsg::SetRoyaltyInfo {
            token_id,
            royalty_info,
            ..
        } => set_royalty_info(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            token_id.as_deref(),
            royalty_info.as_ref(),
        ),
        HandleMsg::Reveal { token_id, .. } => reveal(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &token_id,
        ),
        HandleMsg::MakeOwnershipPrivate { .. } => {
            make_owner_private(deps, env, &config, ContractStatus::StopTransactions.to_u8())
        }
        HandleMsg::SetGlobalApproval {
            token_id,
            view_owner,
            view_private_metadata,
            expires,
            ..
        } => set_global_approval(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            token_id,
            view_owner,
            view_private_metadata,
            expires,
        ),
        HandleMsg::SetWhitelistedApproval {
            address,
            token_id,
            view_owner,
            view_private_metadata,
            transfer,
            expires,
            ..
        } => set_whitelisted_approval(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &address,
            token_id,
            view_owner,
            view_private_metadata,
            transfer,
            expires,
            SetAppResp::SetWhitelistedApproval,
        ),
        HandleMsg::Approve {
            spender,
            token_id,
            expires,
            ..
        } => approve_revoke(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &spender,
            &token_id,
            expires,
            true,
        ),
        HandleMsg::Revoke {
            spender, token_id, ..
        } => approve_revoke(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &spender,
            &token_id,
            None,
            false,
        ),
        HandleMsg::ApproveAll {
            operator, expires, ..
        } => set_whitelisted_approval(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &operator,
            None,
            None,
            None,
            Some(AccessLevel::All),
            expires,
            SetAppResp::ApproveAll,
        ),
        HandleMsg::RevokeAll { operator, .. } => set_whitelisted_approval(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &operator,
            None,
            None,
            None,
            Some(AccessLevel::None),
            None,
            SetAppResp::RevokeAll,
        ),
        HandleMsg::TransferNft {
            recipient,
            token_id,
            memo,
            ..
        } => transfer_nft(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            recipient,
            token_id,
            memo,
        ),
        HandleMsg::BatchTransferNft { transfers, .. } => batch_transfer_nft(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            transfers,
        ),
        HandleMsg::SendNft {
            contract,
            receiver_info,
            token_id,
            msg,
            memo,
            ..
        } => send_nft(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            contract,
            receiver_info,
            token_id,
            msg,
            memo,
        ),
        HandleMsg::BatchSendNft { sends, .. } => batch_send_nft(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            sends,
        ),
        HandleMsg::RegisterReceiveNft {
            code_hash,
            also_implements_batch_receive_nft,
            ..
        } => register_receive_nft(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            code_hash,
            also_implements_batch_receive_nft,
        ),
        HandleMsg::BurnNft { token_id, memo, .. } => burn_nft(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            token_id,
            memo,
        ),
        HandleMsg::BatchBurnNft { burns, .. } => batch_burn_nft(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            burns,
        ),
        HandleMsg::CreateViewingKey { entropy, .. } => create_key(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &entropy,
        ),
        HandleMsg::SetViewingKey { key, .. } => set_key(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            key,
        ),
        HandleMsg::AddMinters { minters, .. } => add_minters(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &minters,
        ),
        HandleMsg::RemoveMinters { minters, .. } => remove_minters(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &minters,
        ),
        HandleMsg::SetMinters { minters, .. } => set_minters(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &minters,
        ),
        HandleMsg::ChangeAdmin { address, .. } => change_admin(
            deps,
            env,
            &mut config,
            ContractStatus::StopTransactions.to_u8(),
            &address,
        ),
        HandleMsg::SetContractStatus { level, .. } => {
            set_contract_status(deps, env, &mut config, level)
        }
        HandleMsg::RevokePermit { permit_name, .. } => {
            revoke_permit(&mut deps.storage, &env.message.sender, &permit_name)
        }
    };
    pad_handle_result(response, BLOCK_SIZE)
}

/////////////////////////////////////// Query /////////////////////////////////////
/// Returns QueryResult
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `msg` - QueryMsg passed in with the query call
pub fn query<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    let response = match msg {
        QueryMsg::ContractInfo {} => query_contract_info(&deps.storage),
        QueryMsg::ContractCreator {} => query_contract_creator(deps),
        QueryMsg::RoyaltyInfo { token_id, viewer } => {
            query_royalty(deps, token_id.as_deref(), viewer, None)
        }
        QueryMsg::ContractConfig {} => query_config(&deps.storage),
        QueryMsg::Minters {} => query_minters(deps),
        QueryMsg::NumTokens { viewer } => query_num_tokens(deps, viewer, None),
        QueryMsg::AllTokens {
            viewer,
            start_after,
            limit,
        } => query_all_tokens(deps, viewer, start_after, limit, None),
        QueryMsg::OwnerOf {
            token_id,
            viewer,
            include_expired,
        } => query_owner_of(deps, &token_id, viewer, include_expired, None),
        QueryMsg::NftInfo { token_id } => query_nft_info(&deps.storage, &token_id),
        QueryMsg::PrivateMetadata { token_id, viewer } => {
            query_private_meta(deps, &token_id, viewer, None)
        }
        QueryMsg::AllNftInfo {
            token_id,
            viewer,
            include_expired,
        } => query_all_nft_info(deps, &token_id, viewer, include_expired, None),
        QueryMsg::NftDossier {
            token_id,
            viewer,
            include_expired,
        } => query_nft_dossier(deps, token_id, viewer, include_expired, None),
        QueryMsg::BatchNftDossier {
            token_ids,
            viewer,
            include_expired,
        } => query_batch_nft_dossier(deps, token_ids, viewer, include_expired, None),
        QueryMsg::TokenApprovals {
            token_id,
            viewing_key,
            include_expired,
        } => query_token_approvals(deps, &token_id, Some(viewing_key), include_expired, None),
        QueryMsg::InventoryApprovals {
            address,
            viewing_key,
            include_expired,
        } => {
            let viewer = Some(ViewerInfo {
                address,
                viewing_key,
            });
            query_inventory_approvals(deps, viewer, include_expired, None)
        }
        QueryMsg::ApprovedForAll {
            owner,
            viewing_key,
            include_expired,
        } => query_approved_for_all(deps, Some(&owner), viewing_key, include_expired, None),
        QueryMsg::Tokens {
            owner,
            viewer,
            viewing_key,
            start_after,
            limit,
        } => query_tokens(deps, &owner, viewer, viewing_key, start_after, limit, None),
        QueryMsg::NumTokensOfOwner {
            owner,
            viewer,
            viewing_key,
        } => query_num_owner_tokens(deps, &owner, viewer, viewing_key, None),
        QueryMsg::VerifyTransferApproval {
            token_ids,
            address,
            viewing_key,
        } => {
            let viewer = Some(ViewerInfo {
                address,
                viewing_key,
            });
            query_verify_approval(deps, token_ids, viewer, None)
        }
        QueryMsg::IsUnwrapped { token_id } => query_is_unwrapped(&deps.storage, &token_id),
        QueryMsg::IsTransferable { token_id } => query_is_transferable(&deps.storage, &token_id),
        QueryMsg::ImplementsNonTransferableTokens {} => {
            to_binary(&QueryAnswer::ImplementsNonTransferableTokens { is_enabled: true })
        }
        QueryMsg::ImplementsTokenSubtype {} => {
            to_binary(&QueryAnswer::ImplementsTokenSubtype { is_enabled: true })
        }
        QueryMsg::TransactionHistory {
            address,
            viewing_key,
            page,
            page_size,
        } => {
            let viewer = Some(ViewerInfo {
                address,
                viewing_key,
            });
            query_transactions(deps, viewer, page, page_size, None)
        }
        QueryMsg::RegisteredCodeHash { contract } => query_code_hash(deps, &contract),
        QueryMsg::WithPermit { permit, query } => permit_queries(deps, permit, query),
    };
    pad_query_result(response, BLOCK_SIZE)
}
