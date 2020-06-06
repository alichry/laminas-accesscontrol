# Laminas Access Control
This module is aimed at providing a simple interface that can run queries againt an access control list pertaining an application's controller or a controller's action as a the target resource. This is should not be used directly, use [https://github.com/alichry/laminas-authorization](alichry/laminas-authorization)

# Implementation
Currently, there exists only 1 implementation of the `ListAdapterInterface`. `AccessControlList` is built around arrays to store the identities, controllers (resources), permissions and roles. `AccessControlList` defines modes and policiies that is influences the list's behavior when dealing with missing entries.  
AccessControlList's mode is concerned with whether to allow missing entries from the list.  
There exists 2 modes:

- Strict mode: All identities must be defined in the list, a referenced identity that is not defined will result in an exception thrown. A referenced identity role must be also defined in the roles list. Referenced permisions in identity list should be also included in the permission list. An exception will be thrown if an entry is missing.
- Chill mode: Some identities can be omitted from the configuration, this will lead `AccessControlList` to assume that the omitted identity has no permissions at all. No exception will be thrown if a permission is referenced in the identity list but not in the permission list.

Policies deal with the default access level for missing entriies in the resources list

- Reject: if the target resource is not found, then reject all requests.
- Authenticate: if the target resource is not found, then assume it requires authentication.
- Accept: if the target resource is not found, then assume it is publicly accessible.

## Example

```
<?php
$controllers = [
    TestController::class => AccessControlList::ACCESS_ALL,
    TestAuthController::class => AccessControlList::ACCESS_AUTHENTICATED_ONLY,
    TestMultipleController::class => [
        // actions
        'get' => AccessControlList::ACCESS_ALL,
        'disable' => AccessControlList::ACCESS_REJECT_ALL,
        'admin' => AccessControlList::role('admin'),
        'edit' => AccessControlList::permission('edit')
    ]
];
$identities = [
    'admin' => [
        'roles' => [
            'admin'
        ],
        'permissions' => [
            'edit'
        ]
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

$acl = new AccessControlList(
    AccessControlList::MODE_STRICT,
    AccessControlList::POLICY_REJECT,
    $controllers,
    $identities,
    $roles,
    $permissions
);

$status = $acl->getAccessStatus(
    'admin@test.com',
    TestMultipleController::class,
    'edit'
);
```

## Todo
- Implement an ORM-based access control list that will retrieve the resources and identities from the database instead.
- Test factories
- Release

