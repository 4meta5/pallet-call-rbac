//! # Call Role-Based Access Control
//!
//! This pallet implements role-based access control over
//! dispatchable calls. The configured `SuperUser` sets the list of calls+origins available to an access level (`id`). Within each access level, there are 2 roles:
//! 1. **Admin**: may add/remove accounts to the `Executor` role for the access level
//! 2. **Executor**: may execute dispatchable calls accessible to the access level
//! Only the `SuperUser` has the authority to add/remove accounts to the `Admin` role for any access level.
#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::pallet_prelude::*;
pub use pallet::*;
use scale_info::TypeInfo;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

// Any runtime call can be encoded into two bytes which represent the pallet and call index.
// We use this to uniquely match a user call with calls permitted for the user.
type CallIndex = (u8, u8);

#[derive(PartialEq, Eq, Copy, Clone, MaxEncodedLen, Encode, Decode, TypeInfo, RuntimeDebug)]
pub enum Role {
    Executer,
    Admin,
}

#[derive(PartialEq, Eq, Clone, MaxEncodedLen, Encode, Decode, TypeInfo, RuntimeDebug)]
pub struct CallOrigin<Call, Origin> {
    pub call: Call,
    pub origin: Origin,
}

pub trait ValidateCall<T: pallet::Config> {
    fn validate_call(
        who: &T::AccountId,
        call: &<T as Config>::RuntimeCall,
    ) -> Result<<T as Config>::RuntimeOrigin, DispatchError>;
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::dispatch::{GetDispatchInfo, PostDispatchInfo};
    use frame_support::traits::{CallerTrait, OriginTrait};
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::Dispatchable;
    use sp_std::{collections::btree_set::BTreeSet, vec::Vec};

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

    pub type CallAndOrigin<T> =
        CallOrigin<<T as Config>::RuntimeCall, <T as Config>::PalletsOrigin>;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        /// Call weight information
        type WeightInfo: WeightInfo;
        /// The super user origin.
        type SuperUser: EnsureOrigin<<Self as frame_system::Config>::RuntimeOrigin>;
        /// Validate the call executed through this pallet
        type ValidateCall: ValidateCall<Self>;
        /// A dispatchable call.
        type RuntimeCall: Parameter
            + Dispatchable<
                RuntimeOrigin = <Self as Config>::RuntimeOrigin,
                PostInfo = PostDispatchInfo,
            > + GetDispatchInfo
            + From<frame_system::Call<Self>>;
        /// The aggregated origin which the dispatch will take.
        type RuntimeOrigin: OriginTrait<PalletsOrigin = Self::PalletsOrigin>
            + From<Self::PalletsOrigin>
            + IsType<<Self as frame_system::Config>::RuntimeOrigin>;
        /// The caller origin, overarching type of all pallets origins.
        type PalletsOrigin: From<frame_system::RawOrigin<Self::AccountId>>
            + CallerTrait<Self::AccountId>
            + MaxEncodedLen;
        /// The max number of calls for a single ID
        #[pallet::constant]
        type MaxCalls: Get<u32>;
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Id granted Account access defined by Role
        AccessGranted(u64, T::AccountId, Role),
        /// Id revoked Account access defined by Role
        AccessRevoked(u64, T::AccountId, Role),
        /// Id granted access to calls
        CallsUpdated(u64),
    }

    #[pallet::error]
    pub enum Error<T> {
        /// A role does not exist in storage
        AccessDNE,
        /// Invalid call
        InvalidCall,
        /// Admin only grants access to Executer role
        AdminOnlyGrantsExecuterAccess,
        /// Admin only revokes access to Executer role
        AdminOnlyRevokesExecuterAccess,
        /// Only super can set admin
        OnlySuperSetsAdmin,
        /// Access can be granted only if it does not exist
        AlreadyGrantedAccess,
        /// Caller is not admin
        CallerNotAdmin,
        /// Number of calls exceeds `set_call` input limits
        TooManyCalls,
        /// Encoding call as (u8, u8) failed
        EncodingFailed,
        /// Origin not set to dispatch call
        CallOriginNotSet,
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

    /// CallIndex => Origin
    #[pallet::storage]
    pub type CallOrigins<T: Config> =
        StorageMap<_, Blake2_128Concat, CallIndex, <T as Config>::PalletsOrigin, OptionQuery>;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// For input `who` grants access to calls allowed by Executors of input `id`
        /// Only succeeds if (i) the caller is SuperUser or (ii) the caller is an `id` Admin and `who` is an `id` Executor
        /// Fails if `who` already occupies a role for `id`
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::grant_access())]
        pub fn grant_access(
            origin: OriginFor<T>,
            id: u64,
            who: T::AccountId,
            role: Role,
        ) -> DispatchResult {
            let is_admin_not_super = Self::ensure_origin(origin, id)?;
            if is_admin_not_super {
                ensure!(
                    matches!(role, Role::Executer),
                    Error::<T>::AdminOnlyGrantsExecuterAccess
                );
            }
            ensure!(
                Roles::<T>::get(id, &who).is_none(),
                Error::<T>::AlreadyGrantedAccess
            );
            if matches!(role, Role::Executer) {
                Permissions::<T>::insert(&who, id, ());
            }
            Roles::<T>::insert(id, &who, role);
            Self::deposit_event(Event::AccessGranted(id, who, role));
            Ok(())
        }

        /// For input `who` revoke access to calls allowed by Executors of input `id`
        /// Only succeeds if (i) the caller is SuperUser or (ii) the caller is an `id` Admin and `who` is an `id` Executor.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::revoke_access())]
        pub fn revoke_access(origin: OriginFor<T>, id: u64, who: T::AccountId) -> DispatchResult {
            let is_admin_not_super = Self::ensure_origin(origin, id)?;
            let role = Roles::<T>::get(id, &who).ok_or(Error::<T>::AccessDNE)?;
            if is_admin_not_super {
                ensure!(
                    matches!(role, Role::Executer),
                    Error::<T>::AdminOnlyRevokesExecuterAccess
                );
            }
            if matches!(role, Role::Executer) {
                Permissions::<T>::remove(&who, id);
            }
            Roles::<T>::remove(id, &who);
            Self::deposit_event(Event::AccessRevoked(id, who, role));
            Ok(())
        }

        /// Set calls accessible to Executors of the input `id`
        /// Calls must be passed in with their respective dispatch origins
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::set_calls(calls.len() as u32))]
        pub fn set_calls(
            origin: OriginFor<T>,
            id: u64,
            calls: Vec<CallAndOrigin<T>>,
        ) -> DispatchResult {
            T::SuperUser::ensure_origin(origin)?;
            ensure!(
                calls.len() <= T::MaxCalls::get() as usize,
                Error::<T>::TooManyCalls
            );
            AllowedCalls::<T>::insert(id, Self::calls_to_indices(&calls)?);
            Self::deposit_event(Event::CallsUpdated(id));
            Ok(())
        }

        /// Dispatch call from its origin iff caller is a member of Executor for an Id that has access to the call.
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
            let dispatch_origin = T::ValidateCall::validate_call(&who, &call)?;
            call.dispatch(dispatch_origin).map_err(|e| e.error)?;
            Ok(())
        }
    }

    impl<T: Config> ValidateCall<T> for Pallet<T> {
        /// Return Ok(dispatch_origin) if input account is permitted to make the
        /// call due to membership as an Executer with the permitted ID
        fn validate_call(
            who: &T::AccountId,
            call: &<T as Config>::RuntimeCall,
        ) -> Result<<T as Config>::RuntimeOrigin, DispatchError> {
            let Ok(call_index) = Self::call_to_index(call) else {
                return Err(Error::<T>::EncodingFailed.into());
            };
            for (id, _) in Permissions::<T>::iter_prefix(&who) {
                if AllowedCalls::<T>::get(id).contains(&call_index) {
                    let origin =
                        CallOrigins::<T>::get(&call_index).ok_or(Error::<T>::CallOriginNotSet)?;
                    return Ok(origin.into());
                }
            }
            Err(Error::<T>::InvalidCall.into())
        }
    }
    // Private functions
    impl<T: Config> Pallet<T> {
        /// Converts a vector of calls into a vector of call indices.
        /// Inserts origin into storage for every call index.
        fn calls_to_indices(calls: &[CallAndOrigin<T>]) -> Result<Vec<CallIndex>, DispatchError> {
            let mut indices = BTreeSet::new();
            for CallOrigin { call, origin } in calls.into_iter() {
                let index = Self::call_to_index(call)?;
                if indices.insert(index) {
                    CallOrigins::<T>::insert(index, origin);
                }
            }
            Ok(indices.into_iter().collect())
        }
        /// Convert a call to call indices by encoding the call and taking the first two bytes.
        fn call_to_index(call: &<T as Config>::RuntimeCall) -> Result<CallIndex, DispatchError> {
            let encoded_call = call.encode();
            if encoded_call.len() < 2 {
                return Err(Error::<T>::EncodingFailed.into());
            }
            Ok((encoded_call[0], encoded_call[1]))
        }
        /// Ensures origin is SuperUser or an id Admin.
        /// Returns:
        /// Ok(true) if an id Admin (and not a super user)
        /// Ok(false) if super user
        /// Err(e) if neither super nor id Admin
        fn ensure_origin(origin: OriginFor<T>, id: u64) -> Result<bool, DispatchError> {
            if let Err(e) = T::SuperUser::ensure_origin(origin.clone()) {
                let caller = ensure_signed(origin)?;
                let Some(role) = Roles::<T>::get(id, caller) else {
                    return Err(e.into());
                };
                ensure!(matches!(role, Role::Admin), Error::<T>::CallerNotAdmin);
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }
    // Public functions (i.e. RuntimeAPI)
    impl<T: Config> Pallet<T> {
        /// Return allowed calls for input account
        pub fn get_allowed_calls(who: &T::AccountId) -> Vec<CallIndex> {
            let mut allowed_calls = BTreeSet::new();
            for (id, _) in Permissions::<T>::iter_prefix(&who) {
                let calls = AllowedCalls::<T>::get(id);
                for c in calls {
                    allowed_calls.insert(c);
                }
            }
            allowed_calls.into_iter().collect()
        }
    }
}
