# Call Role-Based Access Control

> intro to role-based access control in general

> intro to explaining calls and origins in substrate

> bring them together and explain why access to calls dispatched from origins is useful
> this is really an extension of utility::dispatch_as which allows more easily fine tuning the rules for allowing access to calls

## Decentralized?

* explain why SuperOrigin determines the extent of decentralization

## Attacks?

If you started reading this and immediately thought "uh-oh this is not a good idea, this is very dangerous", then we at least agree on the latter part.

> explain how abuse can be mitigated by the SuperUser origin, governance is the check just like it is for utility::as_dispatch

## Use Case Examples

* managing deployment and upgrades for smart contracts
* temporarily granting access to specific functions i.e. decentralized hedge fund granting limited trade functionality to its traders
* delegating access to free calls such that caller is refunded via pot
# lil-homey
