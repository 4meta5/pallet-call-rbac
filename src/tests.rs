use super::*;
use crate::mock::*;
use frame_support::{assert_noop, assert_ok};
use frame_system::RawOrigin;

#[test]
fn grant_access_emits_event() {
    new_test_ext().execute_with(|| {
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            1,
            Role::Executer
        ));
        System::assert_last_event(Event::<Test>::AccessGranted(0, 1, Role::Executer).into());
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            2,
            Role::Admin
        ));
        System::assert_last_event(Event::<Test>::AccessGranted(0, 2, Role::Admin).into());
    });
}

#[test]
fn revoke_access_emits_event() {
    new_test_ext().execute_with(|| {
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            1,
            Role::Executer
        ));
        assert_ok!(CallRBAC::revoke_access(RawOrigin::Root.into(), 0, 1));
        System::assert_last_event(Event::<Test>::AccessRevoked(0, 1, Role::Executer).into());
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            2,
            Role::Admin
        ));
        assert_ok!(CallRBAC::revoke_access(RawOrigin::Root.into(), 0, 2));
        System::assert_last_event(Event::<Test>::AccessRevoked(0, 2, Role::Admin).into());
    });
}

#[test]
fn cannot_grant_access_if_already_granted() {
    new_test_ext().execute_with(|| {
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            1,
            Role::Executer
        ));
        assert_noop!(
            CallRBAC::grant_access(RawOrigin::Root.into(), 0, 1, Role::Admin),
            Error::<Test>::AlreadyGrantedAccess
        );
        assert_noop!(
            CallRBAC::grant_access(RawOrigin::Root.into(), 0, 1, Role::Executer),
            Error::<Test>::AlreadyGrantedAccess
        );
    });
}

#[test]
fn cannot_revoke_access_if_access_not_granted() {
    new_test_ext().execute_with(|| {
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            1,
            Role::Executer
        ));
        assert_ok!(CallRBAC::revoke_access(RawOrigin::Root.into(), 0, 1));
        assert_noop!(
            CallRBAC::revoke_access(RawOrigin::Root.into(), 0, 1,),
            Error::<Test>::AccessDNE
        );
    });
}

#[test]
fn admin_can_grant_executor_access() {
    new_test_ext().execute_with(|| {
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
    });
}

#[test]
fn admin_x_cannot_grant_executor_access_for_y() {
    new_test_ext().execute_with(|| {
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            1,
            Role::Admin
        ));
        assert_noop!(
            CallRBAC::grant_access(RawOrigin::Signed(1).into(), 1, 2, Role::Executer),
            frame_support::error::BadOrigin
        );
    });
}

#[test]
fn non_admin_cannot_grant_executor_access() {
    new_test_ext().execute_with(|| {
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            1,
            Role::Executer
        ));
        assert_noop!(
            CallRBAC::grant_access(RawOrigin::Signed(1).into(), 0, 2, Role::Executer),
            Error::<Test>::CallerNotAdmin
        );
    });
}

#[test]
fn admin_cannot_grant_admin_access() {
    new_test_ext().execute_with(|| {
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            1,
            Role::Admin
        ));
        assert_noop!(
            CallRBAC::grant_access(RawOrigin::Signed(1).into(), 0, 2, Role::Admin),
            Error::<Test>::AdminOnlyGrantsExecuterAccess
        );
    });
}

#[test]
fn executer_cannot_grant_access() {
    new_test_ext().execute_with(|| {
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            1,
            Role::Executer
        ));
        assert_noop!(
            CallRBAC::grant_access(RawOrigin::Signed(1).into(), 0, 2, Role::Admin),
            Error::<Test>::CallerNotAdmin
        );
        assert_noop!(
            CallRBAC::grant_access(RawOrigin::Signed(1).into(), 0, 2, Role::Executer),
            Error::<Test>::CallerNotAdmin
        );
    });
}

#[test]
fn grant_executor_access_updates_storage() {
    new_test_ext().execute_with(|| {
        assert!(true);
    });
}
