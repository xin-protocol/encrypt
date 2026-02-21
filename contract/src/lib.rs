#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, Env};

#[contract]
pub struct AllowlistContract;

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Admin,
    AllowedUser(Address),
    Name,
}

#[contractimpl]
impl AllowlistContract {
    pub fn init(env: Env, admin: Address, name: Bytes) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("Already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Name, &name);
    }

    pub fn add(env: Env, account: Address) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).expect("Not initialized");
        admin.require_auth();
        env.storage().persistent().set(&DataKey::AllowedUser(account), &true);
    }

    pub fn remove(env: Env, account: Address) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).expect("Not initialized");
        admin.require_auth();
        env.storage().persistent().remove(&DataKey::AllowedUser(account));
    }

    pub fn is_allowed(env: Env, account: Address) -> bool {
        env.storage().persistent().has(&DataKey::AllowedUser(account))
    }
}
