#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::pallet_prelude::{MaxEncodedLen, RuntimeDebug};
pub use pallet::*;
use scale_info::TypeInfo;

// #[cfg(test)]
// mod mock;
// #[cfg(test)]
// mod tests;

// Any runtime call can be encoded into two bytes which represent the pallet and call index.
// We use this to uniquely match a user call with calls permitted for the user
type CallIndex = (u8, u8);

#[derive(PartialEq, Eq, Copy, Clone, MaxEncodedLen, Encode, Decode, TypeInfo, RuntimeDebug)]
pub enum Role {
    Executer,
    Admin,
}

pub trait ValidateCall<T: pallet::Config> {
    fn validate_call(who: &T::AccountId, call: &<T as Config>::RuntimeCall) -> bool;
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::dispatch::GetDispatchInfo;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::Dispatchable;
    use sp_std::vec::Vec;

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    pub trait WeightInfo {
        fn grant_access() -> Weight;
        fn revoke_access() -> Weight;
        fn set_calls(x: u32) -> Weight;
        fn execute_call() -> Weight;
    }

    impl WeightInfo for () {
        fn grant_access() -> Weight {
            Weight::default()
        }
        fn revoke_access() -> Weight {
            Weight::default()
        }
        fn set_calls(_: u32) -> Weight {
            Weight::default()
        }
        fn execute_call() -> Weight {
            Weight::default()
        }
    }

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The super user origin.
        type SuperUser: EnsureOrigin<Self::RuntimeOrigin>;
        /// The overarching event type
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        /// Call weight information
        type WeightInfo: WeightInfo;
        /// Validate the call
        type ValidateCall: ValidateCall<Self>;
        /// A dispatchable call.
        type RuntimeCall: Parameter
            + Dispatchable<RuntimeOrigin = Self::RuntimeOrigin>
            + GetDispatchInfo
            + From<frame_system::Call<Self>>;
        /// The max number of calls for a single org
        #[pallet::constant]
        type MaxCalls: Get<u32>;
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Org granted Account access defined by Role
        AccessGranted(u64, T::AccountId, Role),
        /// Org revoked Account access defined by Role
        AccessRevoked(u64, T::AccountId, Role),
        /// Org granted access to calls
        CallsUpdated(u64),
    }

    #[pallet::error]
    pub enum Error<T> {
        /// A permission does not exist in storage.
        PermissionDNE,
        /// Invalid call
        InvalidCall,
        /// Only super can set admin
        OnlySuperSetsAdmin,
        /// Caller is not admin
        CallerNotAdmin,
        /// Number of calls exceeds `set_call` input limits
        TooManyCalls,
        /// Encoding call as (u8, u8) failed
        EncodingFailed,
    }

    /// Id, Account => Option<Role>
    #[pallet::storage]
    pub type Roles<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        u64,
        Blake2_128Concat,
        T::AccountId,
        Role,
        OptionQuery,
    >;

    /// Account, Id => Option<()>
    #[pallet::storage]
    pub type Permissions<T: Config> =
        StorageDoubleMap<_, Blake2_128Concat, T::AccountId, Blake2_128Concat, u64, (), OptionQuery>;

    /// Id => Vec<CallIndex>
    #[pallet::storage]
    pub type AllowedCalls<T: Config> =
        StorageMap<_, Blake2_128Concat, u64, Vec<CallIndex>, ValueQuery>;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::grant_access())]
        pub fn grant_access(
            origin: OriginFor<T>,
            org: u64,
            who: T::AccountId,
            role: Role,
        ) -> DispatchResult {
            let is_admin_not_super = Self::ensure_origin(origin, org)?;
            if is_admin_not_super {
                ensure!(!matches!(role, Role::Admin), Error::<T>::OnlySuperSetsAdmin);
            }
            if let Some(prev_role) = Roles::<T>::get(org, &who) {
                ensure!(
                    !matches!(prev_role, Role::Admin),
                    Error::<T>::OnlySuperSetsAdmin
                );
                Self::deposit_event(Event::AccessRevoked(org, who.clone(), prev_role));
            } else {
                if matches!(role, Role::Executer) {
                    Permissions::<T>::insert(&who, org, ());
                }
            }
            Roles::<T>::insert(org, &who, role);
            Self::deposit_event(Event::AccessGranted(org, who, role));
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::revoke_access())]
        pub fn revoke_access(origin: OriginFor<T>, org: u64, who: T::AccountId) -> DispatchResult {
            let is_admin_not_super = Self::ensure_origin(origin, org)?;
            let role = Roles::<T>::get(org, &who).ok_or(Error::<T>::PermissionDNE)?;
            if is_admin_not_super {
                ensure!(!matches!(role, Role::Admin), Error::<T>::OnlySuperSetsAdmin);
            }
            Permissions::<T>::remove(&who, org);
            Roles::<T>::remove(org, &who);
            Self::deposit_event(Event::AccessRevoked(org, who, role));
            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::set_calls(calls.len() as u32))]
        pub fn set_calls(
            origin: OriginFor<T>,
            org: u64,
            calls: Vec<<T as Config>::RuntimeCall>,
        ) -> DispatchResult {
            T::SuperUser::ensure_origin(origin)?;
            ensure!(
                calls.len() <= T::MaxCalls::get() as usize,
                Error::<T>::TooManyCalls
            );
            AllowedCalls::<T>::insert(org, Self::calls_to_indices(&calls)?);
            Self::deposit_event(Event::CallsUpdated(org));
            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(
			T::WeightInfo::execute_call()
				.saturating_add(call.get_dispatch_info().weight)
		)]
        pub fn execute_call(
            origin: OriginFor<T>,
            call: Box<<T as Config>::RuntimeCall>,
        ) -> DispatchResult {
            let who = ensure_signed(origin.clone())?;
            ensure!(
                T::ValidateCall::validate_call(&who, &call),
                Error::<T>::InvalidCall
            );
            call.clone().dispatch(origin).map_err(|e| e.error)?;
            Ok(())
        }
    }

    impl<T: Config> ValidateCall<T> for Pallet<T> {
        fn validate_call(who: &T::AccountId, call: &<T as Config>::RuntimeCall) -> bool {
            let Ok(call_index) = Self::call_to_index(call) else {
                return false;
            };
            for (id, _) in Permissions::<T>::iter_prefix(&who) {
                if AllowedCalls::<T>::get(id).contains(&call_index) {
                    return true;
                }
            }
            false
        }
    }

    impl<T: Config> Pallet<T> {
        /// From pallet-lottery
        /// Converts a vector of calls into a vector of call indices.
        fn calls_to_indices(
            calls: &[<T as Config>::RuntimeCall],
        ) -> Result<Vec<CallIndex>, DispatchError> {
            let mut indices = Vec::new();
            for c in calls.into_iter() {
                let index = Self::call_to_index(c)?;
                // TODO: use btreeSet and convert to vec before returning
                if !indices.contains(&index) {
                    indices.push(index);
                }
            }
            Ok(indices)
        }
        /// From pallet-lottery
        /// Convert a call to call indices by encoding the call and taking the first two bytes.
        fn call_to_index(call: &<T as Config>::RuntimeCall) -> Result<CallIndex, DispatchError> {
            let encoded_call = call.encode();
            if encoded_call.len() < 2 {
                return Err(Error::<T>::EncodingFailed.into());
            }
            Ok((encoded_call[0], encoded_call[1]))
        }
        /// Ensures origin is SuperUser or an org Admin.
        /// Returns:
        /// Ok(true) if an org Admin
        /// Ok(false) if super user
        /// Err(e) if neither
        fn ensure_origin(origin: OriginFor<T>, org: u64) -> Result<bool, DispatchError> {
            if let Err(e) = T::SuperUser::ensure_origin(origin.clone()) {
                let caller = ensure_signed(origin)?;
                let Some(role) = Roles::<T>::get(org, caller) else {
                    return Err(e.into());
                };
                ensure!(matches!(role, Role::Admin), Error::<T>::CallerNotAdmin);
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }
}
