use soroban_sdk::{contracttype, Address, Env, Symbol};

#[contracttype]
pub struct ObjectAccess {
    pub granted: bool,
    pub expiry_ledger: Option<u32>,
    pub delegated_from: Option<Address>,
}

pub fn grant_object_access(env: &Env, admin: &Address, object_id: &Symbol, account: &Address, expiry_ledger: Option<u32>) {
    admin.require_auth();
    let key = (object_id.clone(), account.clone());
    env.storage().persistent().set(&key, &ObjectAccess {
        granted: true,
        expiry_ledger,
        delegated_from: None,
    });
}

pub fn revoke_object_access(env: &Env, admin: &Address, object_id: &Symbol, account: &Address) {
    admin.require_auth();
    let key = (object_id.clone(), account.clone());
    env.storage().persistent().remove(&key);
}

pub fn check_object_access(env: &Env, object_id: &Symbol, account: &Address) -> bool {
    let key = (object_id.clone(), account.clone());
    if let Some(access) = env.storage().persistent().get::<_, ObjectAccess>(&key) {
        if let Some(expiry) = access.expiry_ledger {
            if env.ledger().sequence() > expiry {
                return false;
            }
        }
        return access.granted;
    }
    false
}

pub fn emit_access_granted(env: &Env, caller: &Address, object_id: &Symbol) {
    env.events().publish(("AccessGranted",), (caller.clone(), object_id.clone()));
}

pub fn emit_access_denied(env: &Env, caller: &Address, object_id: &Symbol) {
    env.events().publish(("AccessDenied",), (caller.clone(), object_id.clone()));
}
