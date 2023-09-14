//! Call-RBAC revoke_access and grant_access unit tests
use super::*;
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
fn admin_can_revoke_executor_access() {
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
        assert_ok!(CallRBAC::revoke_access(RawOrigin::Signed(1).into(), 0, 2));
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
fn admin_x_cannot_revoke_access_for_y() {
    new_test_ext().execute_with(|| {
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            1,
            Role::Admin
        ));
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            1,
            2,
            Role::Admin
        ));
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            1,
            3,
            Role::Executer
        ));
        assert_noop!(
            CallRBAC::revoke_access(RawOrigin::Signed(1).into(), 1, 2),
            frame_support::error::BadOrigin
        );
        assert_noop!(
            CallRBAC::revoke_access(RawOrigin::Signed(1).into(), 1, 3),
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
fn non_admin_cannot_revoke_executor_access() {
    new_test_ext().execute_with(|| {
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            1,
            Role::Executer
        ));
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            2,
            Role::Executer
        ));
        assert_noop!(
            CallRBAC::revoke_access(RawOrigin::Signed(1).into(), 0, 2),
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
fn admin_cannot_revoke_admin_access() {
    new_test_ext().execute_with(|| {
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            1,
            Role::Admin
        ));
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            2,
            Role::Admin
        ));
        assert_noop!(
            CallRBAC::revoke_access(RawOrigin::Signed(1).into(), 0, 2),
            Error::<Test>::AdminOnlyRevokesExecuterAccess
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
fn executer_cannot_revoke_access() {
    new_test_ext().execute_with(|| {
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            1,
            Role::Executer
        ));
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            2,
            Role::Executer
        ));
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            3,
            Role::Admin
        ));
        assert_noop!(
            CallRBAC::revoke_access(RawOrigin::Signed(1).into(), 0, 2),
            Error::<Test>::CallerNotAdmin
        );
        assert_noop!(
            CallRBAC::revoke_access(RawOrigin::Signed(1).into(), 0, 3),
            Error::<Test>::CallerNotAdmin
        );
    });
}

#[test]
fn grant_access_updates_storage() {
    new_test_ext().execute_with(|| {
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            1,
            Role::Executer
        ));
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            2,
            Role::Admin
        ));
        assert_eq!(Roles::<Test>::get(0, 1).unwrap(), Role::Executer);
        assert!(Roles::<Test>::get(1, 1).is_none());
        assert_eq!(Roles::<Test>::get(0, 2).unwrap(), Role::Admin);
        // executor has call permissions
        assert!(Permissions::<Test>::get(1, 0).is_some());
        // executor only has call permissions for `id` 0
        assert!(Permissions::<Test>::get(1, 1).is_none());
        // admin does not have call permissions
        assert!(Permissions::<Test>::get(2, 0).is_none());
    });
}

#[test]
fn revoke_access_updates_storage() {
    new_test_ext().execute_with(|| {
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            1,
            Role::Executer
        ));
        assert_ok!(CallRBAC::grant_access(
            RawOrigin::Root.into(),
            0,
            2,
            Role::Admin
        ));
        assert_ok!(CallRBAC::revoke_access(RawOrigin::Root.into(), 0, 1));
        assert_ok!(CallRBAC::revoke_access(RawOrigin::Root.into(), 0, 2));
        assert!(Roles::<Test>::get(1, 0).is_none());
        assert!(Roles::<Test>::get(2, 0).is_none());
        assert!(Permissions::<Test>::get(1, 0).is_none());
    });
}
