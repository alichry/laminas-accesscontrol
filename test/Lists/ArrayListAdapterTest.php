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

namespace AliChry\Laminas\AccessControl\Test\Lists;

use AliChry\Laminas\AccessControl\Lists\ArrayListAdapter;
use PHPUnit\Framework\TestCase;
use AliChry\Laminas\AccessControl\AccessControlException;

use function array_merge;

class ArrayListAdapterTest extends TestCase
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

    /**
     * @throws AccessControlException
     */
    public function testMode()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT
        );
        $this->assertEquals(ArrayListAdapter::MODE_STRICT, $list->getMode());
        $list->setMode(ArrayListAdapter::MODE_CHILL);
        $this->assertEquals(ArrayListAdapter::MODE_CHILL, $list->getMode());
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(AccessControlException::ACL_INVALID_MODE);
        $list->setMode(2);
    }

    /**
     * @throws AccessControlException
     */
    public function testIdentities()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT
        );
        $this->assertEquals([], $list->getIdentities());
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            $this->identities
        );
        $this->assertEquals($this->identities, $list->getIdentities());
    }

    /**
     * @throws AccessControlException
     */
    public function testRoles()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT
        );
        $this->assertEquals([], $list->getRoles());
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            null,
            $this->roles
        );
        $this->assertEquals($this->roles, $list->getRoles());
    }

    /**
     * @throws AccessControlException
     */
    public function testPermissions()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT
        );
        $this->assertEquals([], $list->getPermissions());
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            null,
            null,
            $this->permissions
        );
        $this->assertEquals($this->permissions, $list->getPermissions());
    }
    /**
     * ##################################################
     * ##################################################
     * ##################################################
     * ##################################################
     * ##################################################
     */

    /**
     * @throws AccessControlException
     */
    public function testGetRolePermissionsWithUndefinedRole()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(AccessControlException::ACL_ROLE_NOT_DEFINED);
        $list->getRolePermissions('undefined-role');
    }

    /**
     * @throws AccessControlException
     */
    public function testGetRolePermissionsWithBadRole()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            [],
            $this->roles
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(AccessControlException::ACL_BAD_ROLE);
        $list->getRolePermissions('bad-role');
    }

    /**
     * @throws AccessControlException
     */
    public function testGetRolePermissions()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            [],
            $this->roles
        );
        $this->assertEquals(
            $this->roles['admin'],
            $list->getRolePermissions('admin')
        );
        $this->assertEquals(
            $this->roles['user'],
            $list->getRolePermissions('user')
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testRoleHasPermissionWithUndefinedRole()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            $this->identities
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(AccessControlException::ACL_ROLE_NOT_DEFINED);
        $list->roleHasPermission('user1', 'undefined-role');
    }

    /**
     * @throws AccessControlException
     */
    public function testRoleHasPermissionWithBadRole()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            [],
            $this->roles,
            $this->identities
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(AccessControlException::ACL_ROLE_NOT_DEFINED);
        $list->roleHasPermission('user1', 'bad-role');
    }

    /**
     * @throws AccessControlException
     */
    public function testRoleHasPermissionWithStrictModeAndUndefinedPermission()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            [],
            $this->roles
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_PERMISSION_NOT_DEFINED
        );
        $list->roleHasPermission('admin', 'undefined-permission');
    }

    /**
     * @throws AccessControlException
     */
    public function testRoleHasPermissionWithChillModeAndUndefinedPermission()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_CHILL,
            [],
            $this->roles
        );
        $this->assertEquals(
            false,
            $list->roleHasPermission('admin', 'undefined-permission')
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testRoleHasPermission()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            [],
            $this->roles,
            $this->permissions
        );
        $this->assertEquals(
            true,
            $list->roleHasPermission('admin', 'special-admin-perm')
        );
        $this->assertEquals(
            true,
            $list->roleHasPermission('user', 'special-user-perm')
        );
        $this->assertEquals(
            false,
            $list->roleHasPermission('admin', 'view1')
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testGetIdentityWithStrictModeAndUndefinedIdentity()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_IDENTITY_NOT_DEFINED
        );
        $list->getIdentity('undefined-identity');
    }

    /**
     * @throws AccessControlException
     */
    public function testGetIdentityWithChillModeAndUndefinedIdentity()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_CHILL
        );
        $this->assertEquals(
            [],
            $list->getIdentity('undefined-identity')
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testGetIdentityWithBadIdentity()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            $this->identities
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(AccessControlException::ACL_BAD_IDENTITY);
        $list->getIdentity('bad-identity');

        $this->assertEquals(
            null,
            $list->getIdentity('bad-identity')
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testGetIdentity()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            $this->identities
        );
        $this->assertEquals(
            $this->identities['user1'],
            $list->getIdentity('user1')
        );
        $this->assertEquals(
            $this->identities['user2'],
            $list->getIdentity('user2')
        );
        $this->assertEquals(
            $this->identities['user3'],
            $list->getIdentity('user3')
        );
    }

    public function testGetIdentityRolesWithStrictModeAndUndefinedIdentity()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_IDENTITY_NOT_DEFINED
        );
        $list->getIdentityRoles('undefined-identity');
    }

    /**
     * @throws AccessControlException
     */
    public function testGetIdentityRolesWithChillModeAndUndefinedIdentity()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_CHILL
        );
        $this->assertEquals(
            [],
            $list->getIdentityRoles('undefined-identity')
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testGetIdentityRolesWithBadIdentity()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            $this->identities
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(AccessControlException::ACL_BAD_IDENTITY);
        $list->getIdentityRoles('bad-identity');

        $this->assertEquals(
            [],
            $list->getIdentityRoles('bad-identity')
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testGetIdentityRoles()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            $this->identities
        );
        $this->assertEquals(
            $this->identities['user1']['roles'] ?? [],
            $list->getIdentityRoles('user1')
        );
        $this->assertEquals(
            $this->identities['user2']['roles'] ?? [],
            $list->getIdentityRoles('user2')
        );
        $this->assertEquals(
            $this->identities['user3']['roles'] ?? [],
            $list->getIdentityRoles('user3')
        );
    }

    /**
     * @throws AccessControlException
     */
    public
    function testGetIdentityPermissionsWithStrictModeAndUndefinedIdentity()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_IDENTITY_NOT_DEFINED
        );
        $list->getIdentityPermissions('undefined-identity');
    }

    /**
     * @throws AccessControlException
     */
    public function testGetIdentityPermissionsWithChillModeAndUndefinedIdentity()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_CHILL
        );
        $this->assertEquals(
            [],
            $list->getIdentityPermissions('undefined-identity')
        );

    }

    /**
     * @throws AccessControlException
     */
    public function testGetIdentityPermissionsWithBadIdentity()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            $this->identities
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(AccessControlException::ACL_BAD_IDENTITY);
        $list->getIdentityPermissions('bad-identity');

        $this->assertEquals(
            [],
            $list->getIdentityPermissions('bad-identity')
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testGetIdentityPermissions()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            $this->identities,
            $this->roles,
            $this->permissions
        );
        $this->assertNotEquals([], $this->identities);
        $this->assertEquals(
            $this->getUserPermissions('user1'),
            $list->getIdentityPermissions('user1')
        );
        $this->assertEquals(
            $this->getUserPermissions('user2'),
            $list->getIdentityPermissions('user2')
        );
        $this->assertEquals(
            $this->getUserPermissions('user3'),
            $list->getIdentityPermissions('user3')
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_ROLE_NOT_DEFINED
        );
        $list->getIdentityPermissions('user4');
    }

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasPermissionWithStrictModeAndUndefinedIdentity()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            $this->identities,
            [],
            $this->permissions
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_IDENTITY_NOT_DEFINED
        );
        $list->identityHasPermission('undefined-identity', 'view1');
    }

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasPermissionWithChillModeAndUndefinedIdentity()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_CHILL
        );
        $this->assertEquals(
            false,
            $list->identityHasPermission('undefined-identity', 'view1')
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasPermissionWithBadIdentity()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            $this->identities,
            [],
            $this->permissions
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_BAD_IDENTITY
        );
        $list->identityHasPermission('bad-identity', 'view1');
    }

    /**
     * @throws AccessControlException
     */
    public
    function testIdentityHasPermissionWithStrictModeAndUndefinedPermission()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            $this->identities
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_PERMISSION_NOT_DEFINED
        );
        $list->identityHasPermission('user1', 'undefined-permission');
    }

    /**
     * @throws AccessControlException
     */
    public
    function testIdentityHasPermissionWithStrictModeAndUnlistedPermission()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            $this->identities,
            $this->roles,
            $this->permissions
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_PERMISSION_NOT_DEFINED
        );
        $list->IdentityHasPermission('user4', 'perm-not-in-perms');
    }

    /**
     * @throws AccessControlException
     */
    public
    function testIdentityHasPermissionWithChillModeAndUndefinedPermission()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_CHILL,
            $this->identities,
            $this->roles,
            $this->permissions
        );
        $this->assertEquals(
            false,
            $list->IdentityHasPermission('user1', 'undefined-perm')
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasPermission()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            $this->identities,
            $this->roles,
            $this->permissions
        );
        $this->assertEquals(
            true,
            $list->identityHasPermission('user1', 'view1')
        );
        $this->assertEquals(
            true,
            $list->identityHasPermission('user1', 'edit1')
        );
        $this->assertEquals(
            true,
            $list->identityHasPermission('user1', 'special-admin-perm')
        );
        $this->assertEquals(
            true,
            $list->identityHasPermission('user2', 'view1')
        );
        $this->assertEquals(
            true,
            $list->identityHasPermission('user3', 'special-user-perm')
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasRoleWithStrictModeAndUndefinedIdentity()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT
        );
        $this->expectException(
            AccessControlException::class
        );
        $this->expectExceptionCode(
            AccessControlException::ACL_IDENTITY_NOT_DEFINED
        );
        $list->identityHasRole('undefined-identity', 'admin');
    }

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasRoleWithChillModeAndUndefinedIdentity()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_CHILL
        );
        $this->assertEquals(
            false,
            $list->identityHasRole('undefined-identity', 'admin')
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasRoleWithBadIdentity()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            $this->identities
        );
        $this->expectException(
            AccessControlException::class
        );
        $this->expectExceptionCode(
            AccessControlException::ACL_BAD_IDENTITY
        );
        $list->identityHasRole('bad-identity', 'admin');
    }

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasRoleWithStrictModeAndFoundButUndefinedRole()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            $this->identities,
            $this->roles
        );
        $this->expectExceptionCode(
            AccessControlException::class
        );
        $this->expectExceptionCode(
            AccessControlException::ACL_ROLE_NOT_DEFINED
        );
        $list->identityHasRole('user4', 'role-not-in-roles');
    }

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasRoleWithChillModeAndFoundButUndefinedRole()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_CHILL,
            $this->identities,
            $this->roles
        );
        $this->assertEquals(
            true,
            $list->identityHasRole('user4', 'role-not-in-roles')
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasRole()
    {
        $list = new ArrayListAdapter(
            ArrayListAdapter::MODE_STRICT,
            $this->identities,
            $this->roles,
            $this->permissions
        );
        $this->assertEquals(
            true,
            $list->identityHasRole('user1', 'admin')
        );
        $this->assertEquals(
            true,
            $list->identityHasRole('user3', 'user')
        );
        $this->assertEquals(
            false,
            $list->identityHasRole('user1', 'user')
        );
    }

    /**
     * @param string $user
     * @return array
     */
    private function getUserPermissions($user)
    {
        $userPermissions = $this->identities[$user]['permissions'] ?? [];
        if (! isset($this->identities[$user]['roles'])) {
            return $userPermissions;
        }
        foreach ($this->identities[$user]['roles'] as $role) {
            $userPermissions = array_merge(
                $userPermissions,
                $this->roles[$role] ?? []
            );
        }
        return $userPermissions;
    }
}