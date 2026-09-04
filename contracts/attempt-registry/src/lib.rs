#![no_std]

//! Stellar / Soroban port of Axis AttemptRegistry.
//!
//! Dual-auth: the user must `require_auth`, and the server must pre-sign the
//! submit message with an ed25519 key (Axis uses EIP-191 / ECDSA on Base).
//!
//! Submit message (183 bytes), signed raw by the server (no extra prefix):
//!   b"AXIS_STELLAR_ATTEMPT_V1"          // 23
//!   || network_id                       // 32  env.ledger().network_id()
//!   || contract_id                      // 32  C... payload
//!   || data_id                          // 16  u128 BE
//!   || task_id                          // 16  u128 BE
//!   || user_id                          // 32  G... pubkey or C... hash
//!   || score                            // 16  u128 BE
//!   || simulation_time                  // 16  u128 BE  (milliseconds)

use soroban_sdk::{
    address_payload::AddressPayload, contract, contracterror, contractevent, contractimpl,
    contracttype, panic_with_error, Address, Bytes, BytesN, Env, Vec,
};

const DOMAIN: &[u8] = b"AXIS_STELLAR_ATTEMPT_V1";

const INSTANCE_TTL_THRESHOLD: u32 = 100;
const INSTANCE_TTL_EXTEND_TO: u32 = 518_400;
const PERSISTENT_TTL_THRESHOLD: u32 = 100;
const PERSISTENT_TTL_EXTEND_TO: u32 = 518_400;

#[contract]
pub struct AttemptRegistry;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    RecordAlreadyExists = 1,
    RecordNotFound = 2,
    InvalidSigner = 3,
    EmptyBatch = 4,
    Paused = 5,
    InvalidAddress = 6,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataRecord {
    pub data_id: u128,
    pub task_id: u128,
    pub user: Address,
    pub score: u128,
    pub simulation_time: u128,
    pub timestamp: u64,
    pub invalidated: bool,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Owner,
    ServerSigner,
    Paused,
    TotalRecords,
    Record(u128),
    UserCount(Address),
    UserAt(Address, u32),
}

#[contractevent(topics = ["record_sub"])]
pub struct RecordSubmitted {
    pub data_id: u128,
    pub task_id: u128,
    pub user: Address,
    pub score: u128,
    pub simulation_time: u128,
}

#[contractevent(topics = ["record_inv"])]
pub struct RecordInvalidated {
    pub data_id: u128,
    pub admin: Address,
}

#[contractevent(topics = ["signer_set"])]
pub struct ServerSignerUpdated {
    pub old_signer: BytesN<32>,
    pub new_signer: BytesN<32>,
}

fn bump_instance(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
}

fn bump_persistent(env: &Env, key: &DataKey) {
    env.storage().persistent().extend_ttl(
        key,
        PERSISTENT_TTL_THRESHOLD,
        PERSISTENT_TTL_EXTEND_TO,
    );
}

fn require_owner(env: &Env) -> Address {
    let owner: Address = env.storage().instance().get(&DataKey::Owner).unwrap();
    owner.require_auth();
    owner
}

fn require_not_paused(env: &Env) {
    let paused: bool = env
        .storage()
        .instance()
        .get(&DataKey::Paused)
        .unwrap_or(false);
    if paused {
        panic_with_error!(env, Error::Paused);
    }
}

fn address_id32(env: &Env, address: &Address) -> BytesN<32> {
    match address.to_payload() {
        Some(AddressPayload::AccountIdPublicKeyEd25519(pk)) => pk,
        Some(AddressPayload::ContractIdHash(hash)) => hash,
        None => panic_with_error!(env, Error::InvalidAddress),
    }
}

fn append_u128(buf: &mut Bytes, value: u128) {
    buf.extend_from_array(&value.to_be_bytes());
}

fn append_id32(env: &Env, buf: &mut Bytes, id: &BytesN<32>) {
    buf.append(&Bytes::from_array(env, &id.to_array()));
}

pub fn build_submit_message(
    env: &Env,
    user: &Address,
    data_id: u128,
    task_id: u128,
    score: u128,
    simulation_time: u128,
) -> Bytes {
    let mut msg = Bytes::from_slice(env, DOMAIN);
    append_id32(env, &mut msg, &env.ledger().network_id());
    append_id32(env, &mut msg, &address_id32(env, &env.current_contract_address()));
    append_u128(&mut msg, data_id);
    append_u128(&mut msg, task_id);
    append_id32(env, &mut msg, &address_id32(env, user));
    append_u128(&mut msg, score);
    append_u128(&mut msg, simulation_time);
    msg
}

fn load_record(env: &Env, data_id: u128) -> Option<DataRecord> {
    let key = DataKey::Record(data_id);
    let record: Option<DataRecord> = env.storage().persistent().get(&key);
    if record.is_some() {
        bump_persistent(env, &key);
    }
    record
}

fn invalidate_one(env: &Env, admin: &Address, data_id: u128) {
    let key = DataKey::Record(data_id);
    let mut record: DataRecord = env
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or_else(|| panic_with_error!(env, Error::RecordNotFound));
    record.invalidated = true;
    env.storage().persistent().set(&key, &record);
    bump_persistent(env, &key);
    RecordInvalidated {
        data_id,
        admin: admin.clone(),
    }
    .publish(env);
}

#[contractimpl]
impl AttemptRegistry {
    pub fn __constructor(env: Env, owner: Address, server_signer: BytesN<32>) {
        if server_signer == BytesN::from_array(&env, &[0u8; 32]) {
            panic_with_error!(&env, Error::InvalidSigner);
        }
        env.storage().instance().set(&DataKey::Owner, &owner);
        env.storage()
            .instance()
            .set(&DataKey::ServerSigner, &server_signer);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage().instance().set(&DataKey::TotalRecords, &0u128);
        bump_instance(&env);
    }

    /// Same bytes the server must ed25519-sign. Useful for backend encoding checks.
    pub fn submit_message(
        env: Env,
        user: Address,
        data_id: u128,
        task_id: u128,
        score: u128,
        simulation_time: u128,
    ) -> Bytes {
        build_submit_message(&env, &user, data_id, task_id, score, simulation_time)
    }

    pub fn submit_record(
        env: Env,
        user: Address,
        data_id: u128,
        task_id: u128,
        score: u128,
        simulation_time: u128,
        server_signature: BytesN<64>,
    ) {
        require_not_paused(&env);
        user.require_auth();

        let record_key = DataKey::Record(data_id);
        if env.storage().persistent().has(&record_key) {
            panic_with_error!(&env, Error::RecordAlreadyExists);
        }

        let server_signer: BytesN<32> = env.storage().instance().get(&DataKey::ServerSigner).unwrap();
        let message = build_submit_message(&env, &user, data_id, task_id, score, simulation_time);
        env.crypto()
            .ed25519_verify(&server_signer, &message, &server_signature);

        let record = DataRecord {
            data_id,
            task_id,
            user: user.clone(),
            score,
            simulation_time,
            timestamp: env.ledger().timestamp(),
            invalidated: false,
        };
        env.storage().persistent().set(&record_key, &record);
        bump_persistent(&env, &record_key);

        let count_key = DataKey::UserCount(user.clone());
        let count: u32 = env.storage().persistent().get(&count_key).unwrap_or(0);
        let at_key = DataKey::UserAt(user.clone(), count);
        env.storage().persistent().set(&at_key, &data_id);
        env.storage().persistent().set(&count_key, &(count + 1));
        bump_persistent(&env, &at_key);
        bump_persistent(&env, &count_key);

        let total: u128 = env.storage().instance().get(&DataKey::TotalRecords).unwrap();
        env.storage()
            .instance()
            .set(&DataKey::TotalRecords, &(total + 1));
        bump_instance(&env);

        RecordSubmitted {
            data_id,
            task_id,
            user,
            score,
            simulation_time,
        }
        .publish(&env);
    }

    pub fn invalidate_record(env: Env, data_id: u128) {
        let admin = require_owner(&env);
        invalidate_one(&env, &admin, data_id);
        bump_instance(&env);
    }

    pub fn batch_invalidate(env: Env, data_ids: Vec<u128>) {
        if data_ids.is_empty() {
            panic_with_error!(&env, Error::EmptyBatch);
        }
        let admin = require_owner(&env);
        for id in data_ids.iter() {
            invalidate_one(&env, &admin, id);
        }
        bump_instance(&env);
    }

    pub fn set_server_signer(env: Env, new_signer: BytesN<32>) {
        require_owner(&env);
        if new_signer == BytesN::from_array(&env, &[0u8; 32]) {
            panic_with_error!(&env, Error::InvalidSigner);
        }
        let old_signer: BytesN<32> = env.storage().instance().get(&DataKey::ServerSigner).unwrap();
        env.storage()
            .instance()
            .set(&DataKey::ServerSigner, &new_signer);
        bump_instance(&env);
        ServerSignerUpdated {
            old_signer,
            new_signer,
        }
        .publish(&env);
    }

    pub fn transfer_owner(env: Env, new_owner: Address) {
        require_owner(&env);
        env.storage().instance().set(&DataKey::Owner, &new_owner);
        bump_instance(&env);
    }

    pub fn pause(env: Env) {
        require_owner(&env);
        env.storage().instance().set(&DataKey::Paused, &true);
        bump_instance(&env);
    }

    pub fn unpause(env: Env) {
        require_owner(&env);
        env.storage().instance().set(&DataKey::Paused, &false);
        bump_instance(&env);
    }

    pub fn verify_record(env: Env, data_id: u128) -> (bool, bool) {
        match load_record(&env, data_id) {
            Some(record) => (true, !record.invalidated),
            None => (false, false),
        }
    }

    pub fn get_record(env: Env, data_id: u128) -> DataRecord {
        load_record(&env, data_id)
            .unwrap_or_else(|| panic_with_error!(&env, Error::RecordNotFound))
    }

    pub fn get_user_records(env: Env, user: Address) -> Vec<u128> {
        let count_key = DataKey::UserCount(user.clone());
        let count: u32 = env.storage().persistent().get(&count_key).unwrap_or(0);
        if count > 0 {
            bump_persistent(&env, &count_key);
        }
        let mut ids = Vec::new(&env);
        for i in 0..count {
            let at_key = DataKey::UserAt(user.clone(), i);
            let id: u128 = env.storage().persistent().get(&at_key).unwrap();
            bump_persistent(&env, &at_key);
            ids.push_back(id);
        }
        ids
    }

    pub fn get_user_record_count(env: Env, user: Address) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::UserCount(user))
            .unwrap_or(0)
    }

    pub fn record_exists(env: Env, data_id: u128) -> bool {
        env.storage().persistent().has(&DataKey::Record(data_id))
    }

    pub fn total_records(env: Env) -> u128 {
        env.storage()
            .instance()
            .get(&DataKey::TotalRecords)
            .unwrap_or(0)
    }

    pub fn server_signer(env: Env) -> BytesN<32> {
        env.storage().instance().get(&DataKey::ServerSigner).unwrap()
    }

    pub fn owner(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Owner).unwrap()
    }

    pub fn paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }
}

mod test;
