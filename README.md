# laminas-accesscontrol

[![Build Status](https://travis-ci.org/alichry/laminas-accesscontrol.svg?branch=master)](https://travis-ci.org/alichry/laminas-accesscontrol)

This module is aimed at providing a simple interface that can run queries againt an access control list pertaining an application's controller or a controller's action as a the target resource. This is should not be used directly, use [https://github.com/alichry/laminas-authorization](alichry/laminas-authorization)

## Interfaces and implementations
The base interface for an AccessControlList is `AccessControlListInterface` that
provides 3 methods:  

- identityHasPermission(identity, permission)
- identityHasRole(identity, role)
- getAccessStatus(identity, resourceIdentifier)

An access status, `Status`, is the result of consulting the underlying
`ListAdapterInterface` and `ResourceManagerInterface`. Multiple status codes
exists:  

- Unauthorized, `Status::UNAUTHORIZED`: The given identity is not authorized, i.e.
does not have specified permission or role for the controller/action.
- Unauthenticated, `Status::UNAUTHENTICATED`: The given identity is null and,
therefore, is invalid. This implies that the identity "null" is unauthenticated.
This is practically a short-circuit between `alichry/laminas-authorization` and
`alichry/laminas-accesscontrol` since the passed identity is null, and is usually
retrieved from an `AuthenticationService` from `laminas/laminas-autthentication`.
- Rejected, `Status::REJECTED`: If controller/action has "reject all", or 
inferred policy is "reject all"
- Public, `Status::PUBLIC`: Publicly accessible, no need for authentication or
authorization
- Ok, `Status::OK`: The given identity is authorized but not necessarily
authenticated, i.e. given identity does have specified permission or role for 
the controller/action. This does not imply if the user is authenticated.
Checking if authenticated is the purpose of `alichry/laminas-authorization`

## ArrayAccessControlList
`ArrayAccessControlList` relies on passed list of identities,
permissions, roles and controllers access levels to infer access statuses.  

There exists 2 modes:

- Strict, `ArrayListAdapter::MODE_STRICT` mode: All identities must be defined in
the list, a referenced identity that is not defined will result in an exception
thrown. A referenced identity role must be also defined in the roles list.
Referenced permisions in identity list should be also included in the permission
list. An exception will be thrown if an entry is missing.
- Chill, `ArrayListAdapter::MODE_CHILL` mode: Some identities can be omitted from
the configuration, this will lead `ArrayAccessControlList` to assume that the
omitted identity has no permissions at all. No exception will be thrown if a
permission is referenced in the identity list but not in the permission list.

Policies deal with the default access level for missing entriies in the resources list

- Reject: if the target resource is not found, then reject all requests.
- Authenticate: if the target resource is not found, then assume it requires authentication.
- Accept: if the target resource is not found, then assume it is publicly accessible.

### Example

```
<?php

use AliChry\Laminas\AccessControl\ArrayAccessControlList as ACL;
use AliChry\Laminas\AccessControl\Lists\ArrayListAdapter as LA;
use AliChry\Laminas\AccessControl\Resource\ResourceIdentifier;

$controllers = [
    TestController::class => ACL::ACCESS_ALL,
    TestAuthController::class => ACL::ACCESS_AUTHENTICATED_ONLY,
    TestMultipleController::class => [
        // actions
        'get' => ACL::ACCESS_ALL,
        'disable' => ACL::ACCESS_REJECT_ALL,
        'admin' => ACL::role('admin'),
        'edit' => ACL::permission('edit')
    ]
];
$identities = [
    'admin@test.com' => [
        'roles' => [
            'admin'
        ],
        'permissions' => []
    ]
];
$roles = [
    'admin' => [
        'special-admin-perm'
    ]
];
$permissions = [
    'special-admin-perm',
    'edit'
];

$acl = new ACL(
    LA::MODE_STRICT,
    ACL::POLICY_REJECT,
    $controllers,
    $identities,
    $roles,
    $permissions
);

$unauthStatus = $acl->getAccessStatus(
    'admin@test.com',
    new ResourceIdentifier(
        TestMultipleController::class,
        'edit'
    )
);

echo 'Code: ' . $unauthStatus->getCode() . PHP_EOL; // Code: -3 (UNAUTHORIZED)
echo 'Identity: ' . $unauthStatus->getIdentity() . PHP_EOL; // Identity: admin@test.com
echo 'Messages: ' . implode(', ', $unauthStatus->getMessages()) . PHP_EOL; // Identity "admin@test.com" requires perm:edit

$okStatus = $acl->getAccessStatus(
    'admin@test.com',
    new ResourceIdentifier(
        TestMultipleController::class,
        'admin'
    )
);

echo 'Code: ' . $okStatus->getCode() . PHP_EOL; // Code: 1 (OK)
echo 'Identity: ' . $okStatus->getIdentity() . PHP_EOL; // Identity: admin@test.com
echo 'Messages: ' . implode(', ', $okStatus->getMessages()) . PHP_EOL; //
```

## IdentityAccessControlList
`IdentityAccessControlList` is not concerned with arrays to infer access statuses.
It depends on an instance of `ResourceManagerInterface` and passed identities
should be an instance of `IdentityInteface`.  

The passed resource manager will provide the policy (access level) of each
resource (controller/action). If a resource requires authentication or
authorization, we check by calling the implemented methods `hasPermission` or
`hasRole` of the passed `IdentityInterface` instance.  

This is helpful in an ORM environment, such as Doctrine ORM. After creating
the Identity or User entity type, all is left is also implementing the methods
`hasRole` and `hasPermission` which can be inferred by consulting other ORM
entity types or by providing your custom implementation.

## AccessControlList
`AccessControlList` is a generic ACL that depends on instances of 
`ResourceManager` and `ListAdapterInterface`. Only one implementation of
`ListAdapterInterface` exists, `ArrayListAdapter`, which is utilized by
`ArrayAccessControlList`
