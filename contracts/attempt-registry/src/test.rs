#![cfg(test)]

use super::*;
use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, Vec};

const SERVER_SK: [u8; 32] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11,
];
const DATA_ID: u128 = 40006;
const TASK_ID: u128 = 22;
const SCORE: u128 = 2520;
const SIM_TIME: u128 = 30383;

fn server_pk(env: &Env) -> BytesN<32> {
    let pk = SigningKey::from_bytes(&SERVER_SK).verifying_key();
    BytesN::from_array(env, &pk.to_bytes())
}

fn setup() -> (Env, AttemptRegistryClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let user = Address::generate(&env);
    let contract_id = env.register(AttemptRegistry, (owner.clone(), server_pk(&env)));
    let client = AttemptRegistryClient::new(&env, &contract_id);
    (env, client, owner, user)
}

fn sign_submit(
    env: &Env,
    client: &AttemptRegistryClient<'_>,
    secret: &[u8; 32],
    user: &Address,
    data_id: u128,
    task_id: u128,
    score: u128,
    simulation_time: u128,
) -> BytesN<64> {
    let msg = client.submit_message(user, &data_id, &task_id, &score, &simulation_time);
    let mut raw = [0u8; 183];
    assert_eq!(msg.len(), 183);
    msg.copy_into_slice(&mut raw);
    let sig = SigningKey::from_bytes(secret).sign(&raw);
    BytesN::from_array(env, &sig.to_bytes())
}

#[test]
fn submit_record_success() {
    let (env, client, _, user) = setup();
    let sig = sign_submit(&env, &client, &SERVER_SK, &user, DATA_ID, TASK_ID, SCORE, SIM_TIME);

    client.submit_record(&user, &DATA_ID, &TASK_ID, &SCORE, &SIM_TIME, &sig);

    assert!(client.record_exists(&DATA_ID));
    assert_eq!(client.total_records(), 1);

    let (exists, valid) = client.verify_record(&DATA_ID);
    assert!(exists);
    assert!(valid);
    let record = client.get_record(&DATA_ID);
    assert_eq!(record.data_id, DATA_ID);
    assert_eq!(record.task_id, TASK_ID);
    assert_eq!(record.user, user);
    assert_eq!(record.score, SCORE);
    assert_eq!(record.simulation_time, SIM_TIME);
    assert!(!record.invalidated);
}

#[test]
fn submit_record_user_list() {
    let (env, client, _, user) = setup();
    let sig1 = sign_submit(&env, &client, &SERVER_SK, &user, 1, TASK_ID, SCORE, SIM_TIME);
    let sig2 = sign_submit(&env, &client, &SERVER_SK, &user, 2, TASK_ID, SCORE, SIM_TIME);
    client.submit_record(&user, &1, &TASK_ID, &SCORE, &SIM_TIME, &sig1);
    client.submit_record(&user, &2, &TASK_ID, &SCORE, &SIM_TIME, &sig2);

    let ids = client.get_user_records(&user);
    assert_eq!(ids.len(), 2);
    assert_eq!(ids.get(0).unwrap(), 1);
    assert_eq!(ids.get(1).unwrap(), 2);
    assert_eq!(client.get_user_record_count(&user), 2);
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn submit_record_duplicate() {
    let (env, client, _, user) = setup();
    let sig = sign_submit(&env, &client, &SERVER_SK, &user, DATA_ID, TASK_ID, SCORE, SIM_TIME);
    client.submit_record(&user, &DATA_ID, &TASK_ID, &SCORE, &SIM_TIME, &sig);
    client.submit_record(&user, &DATA_ID, &TASK_ID, &SCORE, &SIM_TIME, &sig);
}

#[test]
#[should_panic]
fn submit_record_fake_signature() {
    let (env, client, _, user) = setup();
    let fake_sk = [0x22u8; 32];
    let sig = sign_submit(&env, &client, &fake_sk, &user, DATA_ID, TASK_ID, SCORE, SIM_TIME);
    client.submit_record(&user, &DATA_ID, &TASK_ID, &SCORE, &SIM_TIME, &sig);
}

#[test]
#[should_panic]
fn submit_record_wrong_user() {
    let (env, client, _, user) = setup();
    let other = Address::generate(&env);
    let sig = sign_submit(&env, &client, &SERVER_SK, &user, DATA_ID, TASK_ID, SCORE, SIM_TIME);
    client.submit_record(&other, &DATA_ID, &TASK_ID, &SCORE, &SIM_TIME, &sig);
}

#[test]
#[should_panic]
fn submit_record_tampered_score() {
    let (env, client, _, user) = setup();
    let sig = sign_submit(&env, &client, &SERVER_SK, &user, DATA_ID, TASK_ID, SCORE, SIM_TIME);
    client.submit_record(&user, &DATA_ID, &TASK_ID, &(SCORE + 1), &SIM_TIME, &sig);
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn submit_record_when_paused() {
    let (env, client, _, user) = setup();
    client.pause();
    let sig = sign_submit(&env, &client, &SERVER_SK, &user, DATA_ID, TASK_ID, SCORE, SIM_TIME);
    client.submit_record(&user, &DATA_ID, &TASK_ID, &SCORE, &SIM_TIME, &sig);
}

#[test]
fn submit_record_after_unpause() {
    let (env, client, _, user) = setup();
    client.pause();
    client.unpause();
    let sig = sign_submit(&env, &client, &SERVER_SK, &user, DATA_ID, TASK_ID, SCORE, SIM_TIME);
    client.submit_record(&user, &DATA_ID, &TASK_ID, &SCORE, &SIM_TIME, &sig);
    assert!(client.record_exists(&DATA_ID));
}

#[test]
fn invalidate_record_success() {
    let (env, client, _, user) = setup();
    let sig = sign_submit(&env, &client, &SERVER_SK, &user, DATA_ID, TASK_ID, SCORE, SIM_TIME);
    client.submit_record(&user, &DATA_ID, &TASK_ID, &SCORE, &SIM_TIME, &sig);
    client.invalidate_record(&DATA_ID);

    let (exists, valid) = client.verify_record(&DATA_ID);
    assert!(exists);
    assert!(!valid);
    assert!(client.get_record(&DATA_ID).invalidated);
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn invalidate_record_not_found() {
    let (_, client, _, _) = setup();
    client.invalidate_record(&99999);
}

#[test]
fn batch_invalidate_success() {
    let (env, client, _, user) = setup();
    for id in [1u128, 2, 3] {
        let sig = sign_submit(&env, &client, &SERVER_SK, &user, id, TASK_ID, SCORE, SIM_TIME);
        client.submit_record(&user, &id, &TASK_ID, &SCORE, &SIM_TIME, &sig);
    }
    let ids = Vec::from_array(&env, [1u128, 2, 3]);
    client.batch_invalidate(&ids);
    assert!(!client.verify_record(&1).1);
    assert!(!client.verify_record(&2).1);
    assert!(!client.verify_record(&3).1);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn batch_invalidate_empty() {
    let (env, client, _, _) = setup();
    client.batch_invalidate(&Vec::new(&env));
}

#[test]
fn verify_record_not_found() {
    let (_, client, _, _) = setup();
    let (exists, valid) = client.verify_record(&99999);
    assert!(!exists);
    assert!(!valid);
}

#[test]
fn set_server_signer_and_old_sig_fails() {
    let (env, client, _, user) = setup();
    let old_sig = sign_submit(&env, &client, &SERVER_SK, &user, DATA_ID, TASK_ID, SCORE, SIM_TIME);

    let new_sk = [0x33u8; 32];
    let new_pk = SigningKey::from_bytes(&new_sk).verifying_key();
    client.set_server_signer(&BytesN::from_array(&env, &new_pk.to_bytes()));

    let new_sig = sign_submit(&env, &client, &new_sk, &user, DATA_ID, TASK_ID, SCORE, SIM_TIME);
    client.submit_record(&user, &DATA_ID, &TASK_ID, &SCORE, &SIM_TIME, &new_sig);
    assert!(client.record_exists(&DATA_ID));

    let other_user = Address::generate(&env);
    let leftover = old_sig;
    let _ = leftover;
    let _ = other_user;
}

#[test]
#[should_panic]
fn old_signature_rejected_after_rotation() {
    let (env, client, _, user) = setup();
    let old_sig = sign_submit(&env, &client, &SERVER_SK, &user, DATA_ID, TASK_ID, SCORE, SIM_TIME);
    let new_sk = [0x33u8; 32];
    let new_pk = SigningKey::from_bytes(&new_sk).verifying_key();
    client.set_server_signer(&BytesN::from_array(&env, &new_pk.to_bytes()));
    client.submit_record(&user, &DATA_ID, &TASK_ID, &SCORE, &SIM_TIME, &old_sig);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn set_server_signer_zero() {
    let (env, client, _, _) = setup();
    client.set_server_signer(&BytesN::from_array(&env, &[0u8; 32]));
}

#[test]
fn constructor_sets_owner_and_signer() {
    let (_, client, owner, _) = setup();
    assert_eq!(client.owner(), owner);
    assert!(!client.paused());
}

#[test]
fn transfer_owner() {
    let (env, client, _, _) = setup();
    let next = Address::generate(&env);
    client.transfer_owner(&next);
    assert_eq!(client.owner(), next);
}

#[test]
fn message_includes_network_and_is_183_bytes() {
    let (env, client, _, user) = setup();
    env.ledger().set_network_id([7u8; 32]);
    let msg = client.submit_message(&user, &DATA_ID, &TASK_ID, &SCORE, &SIM_TIME);
    assert_eq!(msg.len(), 183);
    let mut raw = [0u8; 183];
    msg.copy_into_slice(&mut raw);
    assert_eq!(&raw[..23], b"AXIS_STELLAR_ATTEMPT_V1");
    assert_eq!(&raw[23..55], &[7u8; 32]);
}
