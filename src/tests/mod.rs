//! Call-RBAC unit test environment.
use super::*;
use crate as call_rbac;
use frame_support::traits::{ConstU16, ConstU32, ConstU64};
use frame_system::EnsureRoot;
use pallet_balances::Call as BalancesCall;
use sp_core::H256;
use sp_runtime::{
    traits::{BlakeTwo256, IdentityLookup},
    BuildStorage,
};

mod access;
mod calls;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub struct Test
    {
        Balances: pallet_balances::{Pallet, Call, Config<T>, Storage, Event<T>},
        System: frame_system::{Pallet, Call, Config<T>, Storage, Event<T>},
        CallRBAC: call_rbac::{Pallet, Call, Storage, Event<T>},
    }
);

#[derive(
    Encode,
    Decode,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    MaxEncodedLen,
    TypeInfo,
    RuntimeDebug,
)]
pub enum TestId {
    Foo,
    Bar,
    Baz,
}

impl pallet_balances::Config for Test {
    type MaxLocks = ();
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    type Balance = u64;
    type DustRemoval = ();
    type RuntimeEvent = RuntimeEvent;
    type ExistentialDeposit = ConstU64<1>;
    type AccountStore = System;
    type WeightInfo = ();
    type RuntimeHoldReason = TestId;
    type FreezeIdentifier = TestId;
    type MaxFreezes = (); //ConstU32<2>
    type MaxHolds = ();
}

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Nonce = u32;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type Block = Block;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = ConstU64<250>;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<u64>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ConstU16<42>;
    type OnSetCode = ();
    type MaxConsumers = frame_support::traits::ConstU32<16>;
}

impl call_rbac::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type SuperUser = EnsureRoot<u64>;
    type ValidateCall = CallRBAC;
    type RuntimeCall = RuntimeCall;
    type RuntimeOrigin = RuntimeOrigin;
    type PalletsOrigin = OriginCaller;
    type MaxCalls = ConstU32<10>;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    pallet_balances::GenesisConfig::<Test> {
        balances: vec![(1, 10), (2, 10)],
    }
    .assimilate_storage(&mut storage)
    .unwrap();
    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| System::set_block_number(1));
    ext.into()
}

pub fn call_transfer(dest: u64, value: u64) -> RuntimeCall {
    RuntimeCall::Balances(BalancesCall::transfer_allow_death { dest, value })
}
