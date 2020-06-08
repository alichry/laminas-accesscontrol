<?php
/**
 * Copyright (c) 2019, 2020 Ali Cherry
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

declare(strict_types=1);

namespace AliChry\Laminas\AccessControl\Test;

use PHPUnit\Framework\TestCase;
use AliChry\Laminas\AccessControl\AccessControlException;
use AliChry\Laminas\AccessControl\Status;
use AliChry\Laminas\AccessControl\AccessControlList;

// TODO: For methods that are not mode/policy dependent,
//       maybe create an enumerator that will generate ACL objects
//       for all possible permutations.

final class AccessControlListTest extends TestCase
{
    private $identities = [
        'user1' => [
            'roles' => [
                'admin',
            ],
            'permissions' => [
                'view1',
                'edit1'
            ]
        ],
        'user2' => [
            'permissions' => [
                'view1'
            ]
        ],
        'user3' => [
            'roles' => [
                'user'
            ]
        ],
        'user4' => [
            'roles' => [
                'role-not-in-roles'
            ],
            'permissions' => [
                'perm-not-in-perms'
            ]
        ],
        'user5' => [
            'permissions' => [
                'perm-not-in-perms'
            ]
        ],
        'bad-identity' => 1
    ];
    private $controllers = [
        'PublicController' => AccessControlList::ACCESS_ALL,
        'ClosedController' => AccessControlList::ACCESS_REJECT_ALL,
        'AuthRequiredController' =>
            AccessControlList::ACCESS_AUTHENTICATED_ONLY,
        'AdminController' => 'role:admin',
        'UserController' => 'role:user',
        'Edit1Controller' => 'perm:edit1',
        'View1Controller' => 'perm:view1',
        'SpecialAdminController' => 'perm:special-admin-perm',
        'SpecialUserController' => 'perm:special-user-perm',
        'MultiplePermissionsController' => [
            'allAction' => AccessControlList::ACCESS_ALL,
            'closedAction' => AccessControlList::ACCESS_REJECT_ALL,
            'authedAction' => AccessControlList::ACCESS_AUTHENTICATED_ONLY,
            'view1Action' => 'perm:view1',
            'edit1Action' => 'perm:edit1',
            'userRoleAction' => 'role:user',
            'adminRoleAction' => 'role:admin',
            'specialAdminAction' => 'perm:special-admin-perm',
            'specialUserAction' => 'perm:special-user-perm',
            'badAccessAction' => 1,
            'notFoundPermAction' => 'perm:not-found-perm',
            'notFoundRoleAction' => 'role:not-found-role',
            'foundButUndefinedRoleAction' => 'role:role-not-in-roles',
            'foundButUndefinedPermAction' => 'perm:perm-not-in-perms',
            'undefinedPermAction' => 'perm:undefined-perm',
            'undefinedRoleAction' => 'role:undefined-role'
        ],
        'BadAccessController' => 'baddie'
    ];

    private $roles = [
        'admin' => [
            'special-admin-perm'
        ],
        'user' => [
            'special-user-perm'
        ],
        // not found role is a role not granted to any identity
        'not-found-role' => [
            'not-found-perm'
        ],
        'bad-role' => 1,
    ];
    private $permissions = [
        'view1',
        'edit1',
        'special-admin-perm',
        'special-user-perm',
        // not found perm is a perm not granted to any identity
        'not-found-perm'
    ];

    public function testMode()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            []
        );
        $this->assertEquals(AccessControlList::MODE_STRICT, $acl->getMode());
        $acl->setMode(AccessControlList::MODE_CHILL);
        $this->assertEquals(AccessControlList::MODE_CHILL, $acl->getMode());
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(AccessControlException::ACL_INVALID_MODE);
        $acl->setMode(2);
    }

    public function testPolicy()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            []
        );
        $this->assertEquals(AccessControlList::POLICY_REJECT, $acl->getPolicy());
        $acl->setPolicy(AccessControlList::POLICY_ACCEPT);
        $this->assertEquals(AccessControlList::POLICY_ACCEPT, $acl->getPolicy());
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(AccessControlException::ACL_INVALID_POLICY);
        $acl->setPolicy(3);
    }

    public function testControllers()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            []
        );
        $this->assertEquals([], $acl->getControllers());
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            $this->controllers
        );
        $this->assertEquals($this->controllers, $acl->getControllers());
    }

    public function testIdentities()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            []
        );
        $this->assertEquals([], $acl->getIdentities());
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            $this->identities
        );
        $this->assertEquals($this->identities, $acl->getIdentities());
    }

    public function testRoles()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            []
        );
        $this->assertEquals([], $acl->getRoles());
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            [],
            $this->roles
        );
        $this->assertEquals($this->roles, $acl->getRoles());
    }

    public function testPermissions()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            []
        );
        $this->assertEquals([], $acl->getPermissions());
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            [],
            [],
            $this->permissions
        );
        $this->assertEquals($this->permissions, $acl->getPermissions());
    }

    public function testGetRolePermissionsWithUndefinedRole()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            []
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(AccessControlException::ACL_ROLE_NOT_DEFINED);
        $acl->getRolePermissions('undefined-role');
    }

    public function testGetRolePermissionsWithBadRole()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            [],
            $this->roles
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(AccessControlException::ACL_BAD_ROLE);
        $acl->getRolePermissions('bad-role');
    }

    public function testGetRolePermissions()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            [],
            $this->roles
        );
        $this->assertEquals(
            $this->roles['admin'],
            $acl->getRolePermissions('admin')
        );
        $this->assertEquals(
            $this->roles['user'],
            $acl->getRolePermissions('user')
        );
    }

    public function testRoleHasPermissionWithUndefinedRole()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            $this->identities
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(AccessControlException::ACL_ROLE_NOT_DEFINED);
        $acl->roleHasPermission('user1', 'undefined-role');
    }

    public function testRoleHasPermissionWithBadRole()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            [],
            $this->roles,
            $this->identities
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(AccessControlException::ACL_ROLE_NOT_DEFINED);
        $acl->roleHasPermission('user1', 'bad-role');
    }

    public function testRoleHasPermissionWithStrictModeAndUndefinedPermission()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            [],
            $this->roles
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_PERMISSION_NOT_DEFINED
        );
        $acl->roleHasPermission('admin', 'undefined-permission');
    }

    public function testRoleHasPermissionWithChillModeAndUndefinedPermission()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_CHILL,
            AccessControlList::POLICY_REJECT,
            [],
            [],
            $this->roles
        );
        $this->assertEquals(
            false,
            $acl->roleHasPermission('admin', 'undefined-permission')
        );
    }

    public function testRoleHasPermission()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            [],
            $this->roles,
            $this->permissions
        );
        $this->assertEquals(
            true,
            $acl->roleHasPermission('admin', 'special-admin-perm')
        );
        $this->assertEquals(
            true,
            $acl->roleHasPermission('user', 'special-user-perm')
        );
        $this->assertEquals(
            false,
            $acl->roleHasPermission('admin', 'view1')
        );
    }

    public function testGetIdentityWithStrictModeAndUndefinedIdentity()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            []
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_IDENTITY_NOT_DEFINED
        );
        $acl->getIdentity('undefined-identity');
    }

    public function testGetIdentityWithChillModeAndUndefinedIdentity()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_CHILL,
            AccessControlList::POLICY_REJECT,
            []
        );
        $this->assertEquals(
            [],
            $acl->getIdentity('undefined-identity')
        );
    }

    public function testGetIdentityWithBadIdentity()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            $this->identities
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(AccessControlException::ACL_BAD_IDENTITY);
        $acl->getIdentity('bad-identity');

        $this->assertEquals(
            null,
            $acl->getIdentity('bad-identity', false)
        );
    }

    public function testGetIdentity()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            $this->identities
        );
        $this->assertEquals(
            $this->identities['user1'],
            $acl->getIdentity('user1')
        );
        $this->assertEquals(
            $this->identities['user2'],
            $acl->getIdentity('user2')
        );
        $this->assertEquals(
            $this->identities['user3'],
            $acl->getIdentity('user3')
        );
    }

    public function testGetIdentityRolesWithStrictModeAndUndefinedIdentity()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            []
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_IDENTITY_NOT_DEFINED
        );
        $acl->getIdentityRoles('undefined-identity');
    }

    public function testGetIdentityRolesWithChillModeAndUndefinedIdentity()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_CHILL,
            AccessControlList::POLICY_REJECT,
            []
        );
        $this->assertEquals(
            [],
            $acl->getIdentityRoles('undefined-identity')
        );
    }

    public function testGetIdentityRolesWithBadIdentity()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            $this->identities
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(AccessControlException::ACL_BAD_IDENTITY);
        $acl->getIdentityRoles('bad-identity');

        $this->assertEquals(
            [],
            $acl->getIdentityRoles('bad-identity', false)
        );
    }

    public function testGetIdentityRoles()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            $this->identities
        );
        $this->assertEquals(
            $this->identities['user1']['roles'] ?? [],
            $acl->getIdentityRoles('user1')
        );
        $this->assertEquals(
            $this->identities['user2']['roles'] ?? [],
            $acl->getIdentityRoles('user2')
        );
        $this->assertEquals(
            $this->identities['user3']['roles'] ?? [],
            $acl->getIdentityRoles('user3')
        );
    }

    public function testGetIdentityPermissionsWithStrictModeAndUndefinedIdentity()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            []
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_IDENTITY_NOT_DEFINED
        );
        $acl->getIdentityPermissions('undefined-identity');
    }

    public function testGetIdentityPermissionsWithChillModeAndUndefinedIdentity()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_CHILL,
            AccessControlList::POLICY_REJECT,
            []
        );
        $this->assertEquals(
            [],
            $acl->getIdentityPermissions('undefined-identity')
        );

    }

    public function testGetIdentityPermissionsWithBadIdentity()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            $this->identities
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(AccessControlException::ACL_BAD_IDENTITY);
        $acl->getIdentityPermissions('bad-identity');

        $this->assertEquals(
            [],
            $acl->getIdentityPermissions('bad-identity', false)
        );
    }

    public function testGetIdentityPermissions()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            $this->identities,
            $this->roles,
            $this->permissions
        );
        $this->assertNotEquals([], $this->identities);
        $this->assertEquals(
            $this->getUserPermissions('user1'),
            $acl->getIdentityPermissions('user1')
        );
        $this->assertEquals(
            $this->getUserPermissions('user2'),
            $acl->getIdentityPermissions('user2')
        );
        $this->assertEquals(
            $this->getUserPermissions('user3'),
            $acl->getIdentityPermissions('user3')
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_ROLE_NOT_DEFINED
        );
        $acl->getIdentityPermissions('user4');
    }

    public function testIdentityHasPermissionWithStrictModeAndUndefinedIdentity()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            $this->identities,
            [],
            $this->permissions
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_IDENTITY_NOT_DEFINED
        );
        $acl->identityHasPermission('undefined-identity', 'view1');
    }

    public function testIdentityHasPermissionWithChillModeAndUndefinedIdentity()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_CHILL,
            AccessControlList::POLICY_REJECT,
            []
        );
        $this->assertEquals(
            false,
            $acl->identityHasPermission('undefined-identity', 'view1')
        );
    }

    public function testIdentityHasPermissionWithBadIdentity()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            $this->identities,
            [],
            $this->permissions
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_BAD_IDENTITY
        );
        $acl->identityHasPermission('bad-identity', 'view1');
    }

    public function testIdentityHasPermissionWithStrictModeAndUndefinedPermission()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            $this->identities
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_PERMISSION_NOT_DEFINED
        );
        $acl->identityHasPermission('user1', 'undefined-permission');
    }

    public function testIdentityHasPermissionWithStrictModeAndUnlistedPermission()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            $this->identities,
            $this->roles,
            $this->permissions
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_PERMISSION_NOT_DEFINED
        );
        $acl->IdentityHasPermission('user4', 'perm-not-in-perms');
    }

    public function testIdentityHasPermissionWithChillModeAndUndefinedPermission()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_CHILL,
            AccessControlList::POLICY_REJECT,
            [],
            $this->identities,
            $this->roles,
            $this->permissions
        );
        $this->assertEquals(
            false,
            $acl->IdentityHasPermission('user1', 'undefined-perm')
        );
    }

    public function testIdentityHasPermission()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            $this->identities,
            $this->roles,
            $this->permissions
        );
        $this->assertEquals(
            true,
            $acl->identityHasPermission('user1', 'view1')
        );
        $this->assertEquals(
            true,
            $acl->identityHasPermission('user1', 'edit1')
        );
        $this->assertEquals(
            true,
            $acl->identityHasPermission('user1', 'special-admin-perm')
        );
        $this->assertEquals(
            true,
            $acl->identityHasPermission('user2', 'view1')
        );
        $this->assertEquals(
            true,
            $acl->identityHasPermission('user3', 'special-user-perm')
        );
    }

    public function testIdentityHasRoleWithStrictModeAndUndefinedIdentity()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            []
        );
        $this->expectException(
            AccessControlException::class
        );
        $this->expectExceptionCode(
            AccessControlException::ACL_IDENTITY_NOT_DEFINED
        );
        $acl->identityHasRole('undefined-identity', 'admin');
    }

    public function testIdentityHasRoleWithChillModeAndUndefinedIdentity()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_CHILL,
            AccessControlList::POLICY_REJECT,
            []
        );
        $this->assertEquals(
            false,
            $acl->identityHasRole('undefined-identity', 'admin')
        );
    }

    public function testIdentityHasRoleWithBadIdentity()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            $this->identities
        );
        $this->expectException(
            AccessControlException::class
        );
        $this->expectExceptionCode(
            AccessControlException::ACL_BAD_IDENTITY
        );
        $acl->identityHasRole('bad-identity', 'admin');
    }

    public function testIdentityHasRoleWithStrictModeAndFoundButUndefinedRole()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            $this->identities,
            $this->roles
        );
        $this->expectExceptionCode(
            AccessControlException::class
        );
        $this->expectExceptionCode(
            AccessControlException::ACL_ROLE_NOT_DEFINED
        );
        $acl->identityHasRole('user4', 'role-not-in-roles');
    }

    public function testIdentityHasRoleWithChillModeAndFoundButUndefinedRole()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_CHILL,
            AccessControlList::POLICY_REJECT,
            [],
            $this->identities,
            $this->roles
        );
       $this->assertEquals(
           true,
           $acl->identityHasRole('user4', 'role-not-in-roles')
       );
    }

    public function testIdentityHasRole()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            [],
            $this->identities,
            $this->roles,
            $this->permissions
        );
        $this->assertEquals(
            true,
            $acl->identityHasRole('user1', 'admin')
        );
        $this->assertEquals(
            true,
            $acl->identityHasRole('user3', 'user')
        );
        $this->assertEquals(
            false,
            $acl->identityHasRole('user1', 'user')
        );
    }

    public function testGetControllerAccessWithStrictModeAndUndefinedController()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            []
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_CONTROLLER_NOT_DEFINED)
        ;
        $acl->getControllerAccess('undefined-controller');
    }

    public function testGetControllerAccessWithChillModeAndUndefinedController()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_CHILL,
            AccessControlList::POLICY_REJECT,
            []
        );
        $this->assertEquals(
            AccessControlList::ACCESS_REJECT_ALL,
            $acl->getControllerAccess('undefined-controller')
        );
        $acl->setPolicy(AccessControlList::POLICY_AUTENTICATE);
        $this->assertEquals(
            AccessControlList::ACCESS_AUTHENTICATED_ONLY,
            $acl->getControllerAccess('undefined-controller')
        );

        $acl->setPolicy(AccessControlList::POLICY_ACCEPT);
        $this->assertEquals(
            AccessControlList::ACCESS_ALL,
            $acl->getControllerAccess('undefined-controller')
        );

    }

    // with undefined action and multiple actions defined in controllers list
    public function testGetControllerAccessWithStrictModeAndUndefinedAction()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            $this->controllers
        );
        $this->expectExceptionCode(
            AccessControlException::ACL_ACTION_NOT_DEFINED
        );
        $this->expectException(AccessControlException::class);
        $acl->getControllerAccess(
            'MultiplePermissionsController',
            'undefinedAction'
        );
    }

    // with undefined ction and multiple actions defined in controllers list
    public function testGetControllerAccessWithChillModeAndUndefinedAction()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_CHILL,
            AccessControlList::POLICY_REJECT,
            $this->controllers
        );

        $this->assertEquals(
            AccessControlList::ACCESS_REJECT_ALL,
            $acl->getControllerAccess(
                'MultiplePermissionsController',
                'undefinedAction'
            )
        );

        $acl->setPolicy(AccessControlList::POLICY_ACCEPT);
        $this->assertEquals(
            AccessControlList::ACCESS_ALL,
            $acl->getControllerAccess(
                'MultiplePermissionsController',
                'undefinedAction'
            )
        );

        $acl->setPolicy(AccessControlList::POLICY_AUTENTICATE);
        $this->assertEquals(
            AccessControlList::ACCESS_AUTHENTICATED_ONLY,
            $acl->getControllerAccess(
                'MultiplePermissionsController',
                'undefinedAction'
            )
        );
    }

    public function testGetControllerAccessWithBadControllerAccess()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            $this->controllers
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_INVALID_ACCESS_FORMAT
        );
        $acl->getControllerAccess('BadAccessController');
    }

    public function testGetControllerAccessWithBadActionAccess()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            $this->controllers
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_INVALID_ACCESS_FORMAT
        );
        $acl->getControllerAccess(
            'MultiplePermissionsController',
            'badAccessAction'
        );
    }

    public function testGetControllerAccess()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            $this->controllers
        );
        $this->assertEquals(
            $this->controllers['PublicController'],
            $acl->getControllerAccess('PublicController')
        );
        $this->assertEquals(
            $this->controllers['ClosedController'],
            $acl->getControllerAccess('ClosedController')
        );
        $this->assertEquals(
            $this->controllers['AuthRequiredController'],
            $acl->getControllerAccess('AuthRequiredController')
        );
        $this->assertEquals(
            $this->controllers['AdminController'],
            $acl->getControllerAccess('AdminController')
        );
        $this->assertEquals(
            $this->controllers['UserController'],
            $acl->getControllerAccess('UserController')
        );
        $this->assertEquals(
            $this->controllers['Edit1Controller'],
            $acl->getControllerAccess('Edit1Controller')
        );
        $this->assertEquals(
            $this->controllers['View1Controller'],
            $acl->getControllerAccess('View1Controller')
        );
        $this->assertEquals(
            $this->controllers['SpecialAdminController'],
            $acl->getControllerAccess('SpecialAdminController')
        );
        $this->assertEquals(
            $this->controllers['SpecialUserController'],
            $acl->getControllerAccess('SpecialUserController')
        );
        $this->assertEquals(
            $this->controllers['MultiplePermissionsController']['allAction'],
            $acl->getControllerAccess(
                'MultiplePermissionsController',
                'allAction'
            )
        );
        $this->assertEquals(
            $this->controllers['MultiplePermissionsController']['closedAction'],
            $acl->getControllerAccess(
                'MultiplePermissionsController',
                'closedAction'
            )
        );
        $this->assertEquals(
            $this->controllers['MultiplePermissionsController']['authedAction'],
            $acl->getControllerAccess(
                'MultiplePermissionsController',
                'authedAction'
            )
        );
        $this->assertEquals(
            $this->controllers['MultiplePermissionsController']['view1Action'],
            $acl->getControllerAccess(
                'MultiplePermissionsController',
                'view1Action'
            )
        );
        $this->assertEquals(
            $this->controllers['MultiplePermissionsController']['edit1Action'],
            $acl->getControllerAccess(
                'MultiplePermissionsController',
                'edit1Action'
            )
        );
        $this->assertEquals(
            $this->controllers['MultiplePermissionsController']['userRoleAction'],
            $acl->getControllerAccess(
                'MultiplePermissionsController',
                'userRoleAction'
            )
        );
        $this->assertEquals(
            $this->controllers['MultiplePermissionsController']['adminRoleAction'],
            $acl->getControllerAccess(
                'MultiplePermissionsController',
                'adminRoleAction'
            )
        );
        $this->assertEquals(
            $this->controllers['MultiplePermissionsController']['specialAdminAction'],
            $acl->getControllerAccess(
                'MultiplePermissionsController',
                'specialAdminAction'
            )
        );
        $this->assertEquals(
            $this->controllers['MultiplePermissionsController']['specialUserAction'],
            $acl->getControllerAccess(
                'MultiplePermissionsController',
                'specialUserAction'
            )
        );
    }

    public function testGetAccessStatusWithStrictModeAndUndefinedController()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            []
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_CONTROLLER_NOT_DEFINED)
        ;
        $acl->getAccessStatus(null, 'undefined-controller');
    }

    public function testGetAccessStatusWithChillModeAndUndefinedController()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_CHILL,
            AccessControlList::POLICY_REJECT,
            []
        );

        $statusRejected = $acl->getAccessStatus('user1', 'undefined-controller');
        $this->assertEquals(
            Status::REJECTED,
            $statusRejected->getCode()
        );
        $this->assertEquals(
            'user1',
            $statusRejected->getIdentity()
        );

        $acl->setPolicy(AccessControlList::POLICY_AUTENTICATE);
        $statusAuthenticate = $acl->getAccessStatus(
            'user1',
            'undefined-controller'
        );
        $this->assertEquals(
            Status::OK,
            $statusAuthenticate->getCode()
        );
        $this->assertEquals(
            'user1',
            $statusAuthenticate->getIdentity()
        );

        $acl->setPolicy(AccessControlList::POLICY_ACCEPT);
        $statusAccept = $acl->getAccessStatus('user1', 'undefined-controller');
        $this->assertEquals(
            Status::PUBLIC,
            $statusAccept->getCode()
        );
        $this->assertEquals(
            'user1',
            $statusAccept->getIdentity()
        );
    }

    // with undefined action and multiple actions defined in controllers list
    public function testGetAccessStatusWithStrictModeAndUndefinedAction()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            $this->controllers
        );
        $this->expectExceptionCode(
            AccessControlException::ACL_ACTION_NOT_DEFINED
        );
        $this->expectException(AccessControlException::class);
        $acl->getAccessStatus(
            null,
            'MultiplePermissionsController',
            'undefinedAction'
        );
    }

    // with undefined ction and multiple actions defined in controllers list
    public function testGetAccessStatusWithChillModeAndUndefinedAction()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_CHILL,
            AccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities
        );

        $statusRejected = $acl->getAccessStatus(
            'user1',
            'MultiplePermissionsController',
            'undefinedAction'
        );

        $this->assertEquals(
            Status::REJECTED,
            $statusRejected->getCode()
        );
        $this->assertEquals(
            'user1',
            $statusRejected->getIdentity()
        );

        $acl->setPolicy(AccessControlList::POLICY_ACCEPT);
        $statusAccepted = $acl->getAccessStatus(
            'user1',
            'MultiplePermissionsController',
            'undefinedAction'
        );
        $this->assertEquals(
            Status::PUBLIC,
            $statusAccepted->getCode()
        );
        $this->assertEquals(
            'user1',
            $statusAccepted->getIdentity()
        );

        $acl->setPolicy(AccessControlList::POLICY_AUTENTICATE);
        $statusAuth = $acl->getAccessStatus(
            'user1',
            'MultiplePermissionsController',
            'undefinedAction'
        );
        $this->assertEquals(
            Status::OK,
            $statusAuth->getCode()
        );
        $this->assertEquals(
            'user1',
            $statusAuth->getIdentity()
        );
    }

    public function testGetAccessStatusWithBadControllerAccess()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            $this->controllers
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_INVALID_ACCESS_FORMAT
        );
        $acl->getAccessStatus(null, 'BadAccessController');
    }

    public function testGetAccessStatusWithBadActionAccess()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            $this->controllers
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_INVALID_ACCESS_FORMAT
        );
        $acl->getAccessStatus(
            null,
            'MultiplePermissionsController',
            'badAccessAction'
        );
    }

    public function testGetAccessStatusWithStrictModeAndUndefinedIdentity()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities,
            [],
            $this->permissions
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_IDENTITY_NOT_DEFINED
        );
        $acl->getAccessStatus('undefined-identity', 'AdminController');
    }

    public function testGetAccessStatusWithChillModeAndUndefinedIdentity()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_CHILL,
            AccessControlList::POLICY_REJECT,
            $this->controllers,
            [],
            [],
            $this->permissions
        );
        $statusUnauth = $acl->getAccessStatus(
            'undefined-identity',
            'AdminController'
        );
        $this->assertEquals(
            Status::UNAUTHORIZED,
            $statusUnauth->getCode()
        );
        $this->assertEquals(
            'undefined-identity',
            $statusUnauth->getIdentity()
        );
    }

    public function testGetAccessStatusWithBadIdentity()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities,
            [],
            $this->permissions
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_BAD_IDENTITY
        );
        $acl->getAccessStatus('bad-identity', 'AdminController');
    }

    public function testGetAccessStatusWithStrictModeAndUndefinedPermission()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_PERMISSION_NOT_DEFINED
        );
        $acl->getAccessStatus(
            'user1',
            'MultiplePermissionsController',
            'undefinedPermAction'
        );
    }

    public function testGetAccessStatusWithChillModeAndUndefinedPermission()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_CHILL,
            AccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities,
            $this->roles
        );
        $status = $acl->getAccessStatus(
            'user1',
            'MultiplePermissionsController',
            'undefinedPermAction'
        );;
        $this->assertEquals(
            Status::UNAUTHORIZED,
            $status->getCode()
        );
        $this->assertEquals(
            'user1',
            $status->getIdentity()
        );
    }

    public function testGetAccessStatusWithUndefinedRole()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities
        );
        $status = $acl->getAccessStatus(
            'user1',
            'MultiplePermissionsController',
            'undefinedRoleAction'
        );;
        $this->assertEquals(
            Status::UNAUTHORIZED,
            $status->getCode()
        );
        $this->assertEquals(
            'user1',
            $status->getIdentity()
        );

        $acl->setMode(AccessControlList::MODE_CHILL);
        $status = $acl->getAccessStatus(
            'user1',
            'MultiplePermissionsController',
            'undefinedRoleAction'
        );;
        $this->assertEquals(
            Status::UNAUTHORIZED,
            $status->getCode()
        );
        $this->assertEquals(
            'user1',
            $status->getIdentity()
        );
    }

    public function testGetAccessStatusWithNotFoundRole()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities
        );

        $status = $acl->getAccessStatus(
            'user1',
            'MultiplePermissionsController',
            'notFoundRoleAction'
        );
        $this->assertEquals(
            Status::UNAUTHORIZED,
            $status->getCode()
        );
        $this->assertEquals(
            'user1',
            $status->getIdentity()
        );
    }

    public
    function testGetAccessStatusWithStrictModeAndFoundButUndefinedPermission()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities
        );
        $this->expectExceptionCode(
            AccessControlException::class
        );
        $this->expectExceptionCode(
            AccessControlException::ACL_PERMISSION_NOT_DEFINED
        );
        $acl->getAccessStatus(
            'user4',
            'MultiplePermissionsController',
            'foundButUndefinedPermAction'
        );;
    }

    public
    function testGetAccessStatusWithChillModeAndFoundButUndefinedPermission()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_CHILL,
            AccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities
        );
        $status = $acl->getAccessStatus(
            'user5',
            'MultiplePermissionsController',
            'foundButUndefinedPermAction'
        );;
        $this->assertEquals(
            Status::OK,
            $status->getCode()
        );
        $this->assertEquals(
            'user5',
            $status->getIdentity()
        );
    }

    public function testGetAccessStatusWithStrictModeAndFoundButUndefinedRole()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities,
            $this->roles
        );
        $this->expectExceptionCode(
            AccessControlException::class
        );
        $this->expectExceptionCode(
            AccessControlException::ACL_ROLE_NOT_DEFINED
        );
        $acl->getAccessStatus(
            'user4',
            'MultiplePermissionsController',
            'foundButUndefinedRoleAction'
        );;
    }

    public function testGetAccessStatusWithChillModeAndFoundButUndefinedRole()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_CHILL,
            AccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities,
            $this->roles
        );
        $status = $acl->getAccessStatus(
            'user4',
            'MultiplePermissionsController',
            'foundButUndefinedRoleAction'
        );;
        $this->assertEquals(
            Status::OK,
            $status->getCode()
        );
        $this->assertEquals(
            'user4',
            $status->getIdentity()
        );
    }

    public function testGetAccessStatus()
    {
        $acl = new AccessControlList(
            AccessControlList::MODE_STRICT,
            AccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities,
            $this->roles,
            $this->permissions
        );
        $commonCases = [
            [
                'status' => Status::PUBLIC,
                'controller' => 'PublicController'
            ],
            [
                'status' => Status::REJECTED,
                'controller' => 'ClosedController'
            ],
            [
                'status' => Status::OK,
                'controller' => 'AuthRequiredController'
            ],
            [
                'status' => Status::PUBLIC,
                'controller' => 'MultiplePermissionsController',
                'action' => 'allAction'
            ],
            [
                'status' => Status::REJECTED,
                'controller' => 'MultiplePermissionsController',
                'action' => 'closedAction'
            ],
            [
                'status' => Status::OK,
                'controller' => 'MultiplePermissionsController',
                'action' => 'authedAction'
            ]
        ];
        $tests = [
            'user1'  => [
                [
                    'status' => Status::OK,
                    'controller' => 'AdminController'
                ],
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'UserController'
                ],
                [
                    'status' => Status::OK,
                    'controller' => 'Edit1Controller'
                ],
                [
                    'status' => Status::OK,
                    'controller' => 'View1Controller'
                ],
                [
                    'status' => Status::OK,
                    'controller' => 'SpecialAdminController'
                ],
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'SpecialUserController'
                ],
                [
                    'status' => Status::OK,
                    'controller' => 'MultiplePermissionsController',
                    'action' => 'edit1Action'
                ],
                [
                    'status' => Status::OK,
                    'controller' => 'MultiplePermissionsController',
                    'action' => 'view1Action'
                ],
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'MultiplePermissionsController',
                    'action' => 'userRoleAction'
                ],
                [
                    'status' => Status::OK,
                    'controller' => 'MultiplePermissionsController',
                    'action' => 'adminRoleAction'
                ],
                [
                    'status' => Status::OK,
                    'controller' => 'MultiplePermissionsController',
                    'action' => 'specialAdminAction'
                ],
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'MultiplePermissionsController',
                    'action' => 'specialUserAction'
                ]
            ],
            'user2' => [
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'AdminController'
                ],
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'UserController'
                ],
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'Edit1Controller'
                ],
                [
                    'status' => Status::OK,
                    'controller' => 'View1Controller'
                ],
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'SpecialAdminController'
                ],
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'SpecialUserController'
                ],
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'MultiplePermissionsController',
                    'action' => 'edit1Action'
                ],
                [
                    'status' => Status::OK,
                    'controller' => 'MultiplePermissionsController',
                    'action' => 'view1Action'
                ],
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'MultiplePermissionsController',
                    'action' => 'userRoleAction'
                ],
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'MultiplePermissionsController',
                    'action' => 'adminRoleAction'
                ],
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'MultiplePermissionsController',
                    'action' => 'specialAdminAction'
                ],
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'MultiplePermissionsController',
                    'action' => 'specialUserAction'
                ]
            ],
            'user3' => [
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'AdminController'
                ],
                [
                    'status' => Status::OK,
                    'controller' => 'UserController'
                ],
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'Edit1Controller'
                ],
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'View1Controller'
                ],
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'SpecialAdminController'
                ],
                [
                    'status' => Status::OK,
                    'controller' => 'SpecialUserController'
                ],
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'MultiplePermissionsController',
                    'action' => 'edit1Action'
                ],
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'MultiplePermissionsController',
                    'action' => 'view1Action'
                ],
                [
                    'status' => Status::OK,
                    'controller' => 'MultiplePermissionsController',
                    'action' => 'userRoleAction'
                ],
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'MultiplePermissionsController',
                    'action' => 'adminRoleAction'
                ],
                [
                    'status' => Status::UNAUTHORIZED,
                    'controller' => 'MultiplePermissionsController',
                    'action' => 'specialAdminAction'
                ],
                [
                    'status' => Status::OK,
                    'controller' => 'MultiplePermissionsController',
                    'action' => 'specialUserAction'
                ]
            ]
        ];
        $total = 0;
        foreach ($tests as $identity => $identityCases) {
            $cases = \array_merge($commonCases, $identityCases);
            foreach ($cases as $testCase) {
                $total++;
                $status = $acl->getAccessStatus(
                    $identity,
                    $testCase['controller'],
                    $testCase['action'] ?? null
                );
                $this->assertEquals(
                    $testCase['status'],
                    $status->getCode()
                );
                $this->assertEquals(
                    $identity,
                    $status->getIdentity()
                );
            }
        }
    }

    private function getUserPermissions($user)
    {
        $userPermissions = $this->identities[$user]['permissions'] ?? [];
        if (!isset($this->identities[$user]['roles'])) {
            return $userPermissions;
        }
        foreach ($this->identities[$user]['roles'] as $role) {
            $userPermissions = \array_merge(
                $userPermissions,
                $this->roles[$role] ?? []
            );
        }
        return $userPermissions;
    }
}