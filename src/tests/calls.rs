//! Call-RBAC set_calls and execute_call unit tests.
use super::*;
use frame_support::{assert_noop, assert_ok};
use frame_system::RawOrigin;

#[test]
fn set_calls_emits_event() {
    new_test_ext().execute_with(|| {
        assert_ok!(CallRBAC::set_calls(RawOrigin::Root.into(), 0, vec![]));
        System::assert_last_event(Event::<Test>::CallsUpdated(0).into());
        assert_ok!(CallRBAC::set_calls(RawOrigin::Root.into(), 1, vec![]));
        System::assert_last_event(Event::<Test>::CallsUpdated(1).into());
    });
}

#[test]
fn set_call_only_for_super_user_origin() {
    new_test_ext().execute_with(|| {
        assert_ok!(CallRBAC::set_calls(
            RawOrigin::Root.into(),
            0,
            vec![CallOrigin {
                call: call_transfer(2, 3),
                origin: RawOrigin::Signed(1).into(),
            }]
        ));
        assert_noop!(
            CallRBAC::set_calls(RawOrigin::Signed(1).into(), 0, vec![]),
            frame_support::error::BadOrigin
        );
    });
}

#[test]
fn set_calls_updates_storage() {
    new_test_ext().execute_with(|| {
        assert_ok!(CallRBAC::set_calls(
            RawOrigin::Root.into(),
            0,
            vec![CallOrigin {
                call: call_transfer(2, 3),
                origin: RawOrigin::Signed(1).into(),
            }]
        ));
        assert_eq!(
            CallOrigins::<Test>::get(0, call_transfer(2, 3)),
            Some(RawOrigin::Signed(1).into())
        );
        assert_ok!(CallRBAC::set_calls(RawOrigin::Root.into(), 0, vec![]));
        assert_eq!(CallOrigins::<Test>::get(0, call_transfer(2, 3)), None);
    });
}

#[test]
fn execute_call_works_for_executor_not_admin() {
    new_test_ext().execute_with(|| {
        assert_ok!(CallRBAC::set_calls(
            RawOrigin::Root.into(),
            0,
            vec![CallOrigin {
                call: call_transfer(2, 3),
                origin: RawOrigin::Signed(1).into(),
            }]
        ));
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            1,
            Role::Admin
        ));
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Signed(1).into(),
            0,
            2,
            Role::Executer
        ));
        assert_noop!(
            CallRBAC::execute_call(RawOrigin::Signed(1).into(), Box::new(call_transfer(2, 3))),
            Error::<Test>::CallNotPermitted
        );
        assert_eq!(Balances::free_balance(&1), 10);
        assert_eq!(Balances::free_balance(&2), 10);
        assert_ok!(CallRBAC::execute_call(
            RawOrigin::Signed(2).into(),
            Box::new(call_transfer(2, 3))
        ));
        assert_eq!(Balances::free_balance(&1), 7);
        assert_eq!(Balances::free_balance(&2), 13);
    });
}
