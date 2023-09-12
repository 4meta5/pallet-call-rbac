#![cfg_attr(not(feature = "std"), no_std)]
pub use pallet::*;

mod role;
use role::*;

// #[cfg(test)]
// mod mock;
// #[cfg(test)]
// mod tests;

pub trait ValidateCall<T: pallet::Config> {
    fn validate_call(who: &T::AccountId, call: &<T as Config>::RuntimeCall) -> bool;
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::dispatch::GetDispatchInfo;
    use frame_support::pallet_prelude::*;
    use frame_system::ensure_signed;
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::Dispatchable;
    use sp_std::vec::Vec;

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    pub trait WeightInfo {
        fn grant_access() -> Weight;
        fn revoke_access() -> Weight;
        fn execute_call() -> Weight;
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
    }

    /// Access control permissions from Org, Account => Some(Role)
    #[pallet::storage]
    pub type Permissions<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        u64,
        Blake2_128Concat,
        T::AccountId,
        Role,
        OptionQuery,
    >;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::grant_access())]
        pub fn set_access(
            origin: OriginFor<T>,
            org: u64,
            who: T::AccountId,
            role: Role,
        ) -> DispatchResult {
            let by_super = Self::ensure_origin(origin, org)?;
            if !by_super {
                ensure!(!matches!(role, Role::Admin), Error::<T>::OnlySuperSetsAdmin);
            }
            if let Some(prev_role) = Permissions::<T>::get(org, &who) {
                ensure!(
                    !matches!(prev_role, Role::Admin),
                    Error::<T>::OnlySuperSetsAdmin
                );
                Self::deposit_event(Event::AccessRevoked(org, who.clone(), prev_role));
            }
            Permissions::<T>::insert(org, &who, role);
            Self::deposit_event(Event::AccessGranted(org, who, role));
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::revoke_access())]
        pub fn revoke_access(origin: OriginFor<T>, org: u64, who: T::AccountId) -> DispatchResult {
            let by_super = Self::ensure_origin(origin, org)?;
            let role = Permissions::<T>::get(org, &who).ok_or(Error::<T>::PermissionDNE)?;
            if !by_super {
                ensure!(!matches!(role, Role::Admin), Error::<T>::OnlySuperSetsAdmin);
            }
            Permissions::<T>::remove(org, &who);
            Self::deposit_event(Event::AccessRevoked(org, who, role));
            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::revoke_access())]
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

            // emit event
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
            todo!()
        }
    }

    impl<T: Config> Pallet<T> {
        fn ensure_origin(origin: OriginFor<T>, org: u64) -> Result<bool, DispatchError> {
            if let Err(e) = T::SuperUser::ensure_origin(origin.clone()) {
                let caller = ensure_signed(origin)?;
                let Some(role) = Permissions::<T>::get(org, caller) else {
                    return Err(e.into());
                };
                ensure!(matches!(role, Role::Admin), Error::<T>::CallerNotAdmin);
                Ok(false)
            } else {
                Ok(true)
            }
        }
    }
}
