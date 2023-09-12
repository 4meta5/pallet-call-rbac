# Role-Based Access Control Substrate Pallet

1. pros and cons of role-based access control
2. distributed role-based access control

> Borrows heavily from frame-lottery! If the borrowed code could be imported without changing the code in frame-lottery to expose it, then frame-lottery would be a dependency and the code would be used from there.

## Configuration Instructions

## Alternative Implementation Considerations

* explain why not all extrinsics have events
* use signed extension for tx pool level verification
    * explain pros/cons
* generate OpenGov-usable origin + assign in runtime explicitly (is not as limited)
* impl_for_tupl to stack ValidateCall filters
* choose resistant hash function for storage trie balancing

## Use Case Examples

* control over deployment/updates of specific smart contracts
* easily revoke access, timed access, etc

