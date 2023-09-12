use codec::{Decode, Encode};
use frame_support::pallet_prelude::*;
use scale_info::TypeInfo;

#[derive(PartialEq, Eq, Copy, Clone, MaxEncodedLen, Encode, Decode, TypeInfo, RuntimeDebug)]
pub enum Role {
    Executer,
    Admin,
}
