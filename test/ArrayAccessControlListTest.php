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

use AliChry\Laminas\AccessControl\Lists\ArrayListAdapter;
use AliChry\Laminas\AccessControl\Resource\ResourceIdentifier;
use PHPUnit\Framework\TestCase;
use AliChry\Laminas\AccessControl\AccessControlException;
use AliChry\Laminas\AccessControl\Status;
use AliChry\Laminas\AccessControl\ArrayAccessControlList;
use function array_merge;

// TODO: For methods that are not mode/policy dependent,
//       maybe create an enumerator that will generate ACL objects
//       for all possible permutations.

final class ArrayAccessControlListTest extends TestCase
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
        'PublicController' => ArrayAccessControlList::ACCESS_ALL,
        'ClosedController' => ArrayAccessControlList::ACCESS_REJECT_ALL,
        'AuthRequiredController' =>
            ArrayAccessControlList::ACCESS_AUTHENTICATED_ONLY,
        'AdminController' => 'role:admin',
        'UserController' => 'role:user',
        'Edit1Controller' => 'perm:edit1',
        'View1Controller' => 'perm:view1',
        'SpecialAdminController' => 'perm:special-admin-perm',
        'SpecialUserController' => 'perm:special-user-perm',
        'MultiplePermissionsController' => [
            'allAction' => ArrayAccessControlList::ACCESS_ALL,
            'closedAction' => ArrayAccessControlList::ACCESS_REJECT_ALL,
            'authedAction' => ArrayAccessControlList::ACCESS_AUTHENTICATED_ONLY,
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
            'undefinedRoleAction' => 'role:undefined-role',
            'invalidPermAction' => 'thissigncanthelpmebecauseicantread',
            'invalidPrefixAction' => 'badprefix:test'
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
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT
        );
        $this->assertEquals(
            ArrayListAdapter::MODE_STRICT,
            $acl->getArrayListAdapter()->getMode()
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testPolicy()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT
        );
        $this->assertEquals(
            ArrayAccessControlList::POLICY_REJECT,
            $acl->getPolicy()
        );
        $acl->setPolicy(ArrayAccessControlList::POLICY_ACCEPT);
        $this->assertEquals(
            ArrayAccessControlList::POLICY_ACCEPT,
            $acl->getPolicy()
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(AccessControlException::ACL_INVALID_POLICY);
        $acl->setPolicy(3);
    }

    /**
     * @throws AccessControlException
     */
    public function testControllers()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT
        );
        $this->assertEquals([], $acl->getControllers());
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            $this->controllers
        );
        $this->assertEquals($this->controllers, $acl->getControllers());
    }

    /**
     * @throws AccessControlException
     */
    public function testRoles()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT
        );
        $this->assertEquals([], $acl->getArrayListAdapter()->getRoles());
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            null,
            null,
            $this->roles
        );
        $this->assertEquals(
            $this->roles,
            $acl->getArrayListAdapter()->getRoles()
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testPermissions()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT
        );
        $this->assertEquals([], $acl->getArrayListAdapter()->getPermissions());
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            null,
            null,
            null,
            $this->permissions
        );
        $this->assertEquals(
            $this->permissions,
            $acl->getArrayListAdapter()->getPermissions()
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasPermissionWithStrictModeAndUndefinedIdentity()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            null,
            $this->identities,
            null,
            $this->permissions
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_IDENTITY_NOT_DEFINED
        );
        $acl->identityHasPermission('undefined-identity', 'view1');
    }

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasPermissionWithChillModeAndUndefinedIdentity()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_CHILL,
            ArrayAccessControlList::POLICY_REJECT,
            null
        );
        $this->assertEquals(
            false,
            $acl->identityHasPermission('undefined-identity', 'view1')
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasPermissionWithBadIdentity()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            null,
            $this->identities,
            null,
            $this->permissions
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_BAD_IDENTITY
        );
        $acl->identityHasPermission('bad-identity', 'view1');
    }

    /**
     * @throws AccessControlException
     */
    public
    function testIdentityHasPermissionWithStrictModeAndUndefinedPermission()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            null,
            $this->identities
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_PERMISSION_NOT_DEFINED
        );
        $acl->identityHasPermission('user1', 'undefined-permission');
    }

    /**
     * @throws AccessControlException
     */
    public
    function testIdentityHasPermissionWithStrictModeAndUnlistedPermission()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            null,
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

    /**
     * @throws AccessControlException
     */
    public
    function testIdentityHasPermissionWithChillModeAndUndefinedPermission()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_CHILL,
            ArrayAccessControlList::POLICY_REJECT,
            null,
            $this->identities,
            $this->roles,
            $this->permissions
        );
        $this->assertEquals(
            false,
            $acl->IdentityHasPermission('user1', 'undefined-perm')
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasPermission()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            null,
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

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasRoleWithStrictModeAndUndefinedIdentity()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT
        );
        $this->expectException(
            AccessControlException::class
        );
        $this->expectExceptionCode(
            AccessControlException::ACL_IDENTITY_NOT_DEFINED
        );
        $acl->identityHasRole('undefined-identity', 'admin');
    }

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasRoleWithChillModeAndUndefinedIdentity()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_CHILL,
            ArrayAccessControlList::POLICY_REJECT
        );
        $this->assertEquals(
            false,
            $acl->identityHasRole('undefined-identity', 'admin')
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasRoleWithBadIdentity()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            null,
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

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasRoleWithStrictModeAndFoundButUndefinedRole()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            null,
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

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasRoleWithChillModeAndFoundButUndefinedRole()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_CHILL,
            ArrayAccessControlList::POLICY_REJECT,
            null,
            $this->identities,
            $this->roles
        );
       $this->assertEquals(
           true,
           $acl->identityHasRole('user4', 'role-not-in-roles')
       );
    }

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasRole()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            null,
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
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_CONTROLLER_NOT_DEFINED)
        ;
        $acl->getControllerAccess('undefined-controller');
    }

    /**
     * @throws AccessControlException
     */
    public function testGetControllerAccessWithChillModeAndUndefinedController()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_CHILL,
            ArrayAccessControlList::POLICY_REJECT
        );
        $this->assertEquals(
            ArrayAccessControlList::ACCESS_REJECT_ALL,
            $acl->getControllerAccess('undefined-controller')
        );
        $acl->setPolicy(ArrayAccessControlList::POLICY_AUTHENTICATE);
        $this->assertEquals(
            ArrayAccessControlList::ACCESS_AUTHENTICATED_ONLY,
            $acl->getControllerAccess('undefined-controller')
        );

        $acl->setPolicy(ArrayAccessControlList::POLICY_ACCEPT);
        $this->assertEquals(
            ArrayAccessControlList::ACCESS_ALL,
            $acl->getControllerAccess('undefined-controller')
        );

    }

    // with undefined action and multiple actions defined in controllers list
    /**
     * @throws AccessControlException
     */
    public function testGetControllerAccessWithStrictModeAndUndefinedAction()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
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
    /**
     * @throws AccessControlException
     */
    public function testGetControllerAccessWithChillModeAndUndefinedAction()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_CHILL,
            ArrayAccessControlList::POLICY_REJECT,
            $this->controllers
        );

        $this->assertEquals(
            ArrayAccessControlList::ACCESS_REJECT_ALL,
            $acl->getControllerAccess(
                'MultiplePermissionsController',
                'undefinedAction'
            )
        );

        $acl->setPolicy(ArrayAccessControlList::POLICY_ACCEPT);
        $this->assertEquals(
            ArrayAccessControlList::ACCESS_ALL,
            $acl->getControllerAccess(
                'MultiplePermissionsController',
                'undefinedAction'
            )
        );

        $acl->setPolicy(ArrayAccessControlList::POLICY_AUTHENTICATE);
        $this->assertEquals(
            ArrayAccessControlList::ACCESS_AUTHENTICATED_ONLY,
            $acl->getControllerAccess(
                'MultiplePermissionsController',
                'undefinedAction'
            )
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testGetControllerAccessWithBadControllerAccess()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            $this->controllers
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_INVALID_ACCESS_FORMAT
        );
        $acl->getControllerAccess('BadAccessController');
    }

    /**
     * @throws AccessControlException
     */
    public function testGetControllerAccessWithBadActionAccess()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
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

    /**
     * @throws AccessControlException
     */
    public function testGetControllerAccess()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
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
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_CONTROLLER_NOT_DEFINED)
        ;
        $acl->getAccessStatus(null, new ResourceIdentifier('undefined-controller'));
    }

    /**
     * @throws AccessControlException
     */
    public function testGetAccessStatusWithChillModeAndUndefinedController()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_CHILL,
            ArrayAccessControlList::POLICY_REJECT
        );

        $statusRejected = $acl->getAccessStatus(
            'user1',
            new ResourceIdentifier('undefined-controller')
        );
        $this->assertEquals(
            Status::REJECTED,
            $statusRejected->getCode()
        );
        $this->assertEquals(
            'user1',
            $statusRejected->getIdentity()
        );

        $acl->setPolicy(ArrayAccessControlList::POLICY_AUTHENTICATE);
        $statusAuthenticate = $acl->getAccessStatus(
            'user1',
            new ResourceIdentifier('undefined-controller')
        );
        $this->assertEquals(
            Status::OK,
            $statusAuthenticate->getCode()
        );
        $this->assertEquals(
            'user1',
            $statusAuthenticate->getIdentity()
        );

        $acl->setPolicy(ArrayAccessControlList::POLICY_ACCEPT);
        $statusAccept = $acl->getAccessStatus(
            'user1',
            new ResourceIdentifier('undefined-controller')
        );
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
    /**
     * @throws AccessControlException
     */
    public function testGetAccessStatusWithStrictModeAndUndefinedAction()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            $this->controllers
        );
        $this->expectExceptionCode(
            AccessControlException::ACL_ACTION_NOT_DEFINED
        );
        $this->expectException(AccessControlException::class);
        $acl->getAccessStatus(
            null,
            new ResourceIdentifier(
                'MultiplePermissionsController',
                'undefinedAction'
            )
        );
    }

    // with undefined ction and multiple actions defined in controllers list
    /**
     * @throws AccessControlException
     */
    public function testGetAccessStatusWithChillModeAndUndefinedAction()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_CHILL,
            ArrayAccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities
        );

        $statusRejected = $acl->getAccessStatus(
            'user1',
            new ResourceIdentifier(
                'MultiplePermissionsController',
                'undefinedAction'
            )
        );

        $this->assertEquals(
            Status::REJECTED,
            $statusRejected->getCode()
        );
        $this->assertEquals(
            'user1',
            $statusRejected->getIdentity()
        );

        $acl->setPolicy(ArrayAccessControlList::POLICY_ACCEPT);
        $statusAccepted = $acl->getAccessStatus(
            'user1',
            new ResourceIdentifier(
                'MultiplePermissionsController',
                'undefinedAction'
            )
        );
        $this->assertEquals(
            Status::PUBLIC,
            $statusAccepted->getCode()
        );
        $this->assertEquals(
            'user1',
            $statusAccepted->getIdentity()
        );

        $acl->setPolicy(ArrayAccessControlList::POLICY_AUTHENTICATE);
        $statusAuth = $acl->getAccessStatus(
            'user1',
            new ResourceIdentifier(
                'MultiplePermissionsController',
                'undefinedAction'
            )
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

    /**
     * @throws AccessControlException
     */
    public function testGetAccessStatusWithBadControllerAccess()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            $this->controllers
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_INVALID_ACCESS_FORMAT
        );
        $acl->getAccessStatus(
            null,
            new ResourceIdentifier('BadAccessController')
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testGetAccessStatusWithBadActionAccess()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            $this->controllers
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_INVALID_ACCESS_FORMAT
        );
        $acl->getAccessStatus(
            null,
            new ResourceIdentifier(
                'MultiplePermissionsController',
                'badAccessAction'
            )
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testGetAccessStatusWithStrictModeAndUndefinedIdentity()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities,
            [],
            $this->permissions
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_IDENTITY_NOT_DEFINED
        );
        $acl->getAccessStatus(
            'undefined-identity',
            new ResourceIdentifier('AdminController')
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testGetAccessStatusWithChillModeAndUndefinedIdentity()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_CHILL,
            ArrayAccessControlList::POLICY_REJECT,
            $this->controllers,
            null,
            null,
            $this->permissions
        );
        $statusUnauth = $acl->getAccessStatus(
            'undefined-identity',
            new ResourceIdentifier('AdminController')
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

    /**
     * @throws AccessControlException
     */
    public function testGetAccessStatusWithBadIdentity()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities,
            null,
            $this->permissions
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_BAD_IDENTITY
        );
        $acl->getAccessStatus(
            'bad-identity',
            new ResourceIdentifier('AdminController')
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testGetAccessStatusWithStrictModeAndUndefinedPermission()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_PERMISSION_NOT_DEFINED
        );
        $acl->getAccessStatus(
            'user1',
            new ResourceIdentifier(
                'MultiplePermissionsController',
                'undefinedPermAction'
            )
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testGetAccessStatusWithChillModeAndUndefinedPermission()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_CHILL,
            ArrayAccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities,
            $this->roles
        );
        $status = $acl->getAccessStatus(
            'user1',
            new ResourceIdentifier(
                'MultiplePermissionsController',
                'undefinedPermAction'
            )
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

    /**
     * @throws AccessControlException
     */
    public function testGetAccessStatusWithUndefinedRole()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities
        );
        $status = $acl->getAccessStatus(
            'user1',
            new ResourceIdentifier(
                'MultiplePermissionsController',
                'undefinedRoleAction'
            )
        );
        $this->assertEquals(
            Status::UNAUTHORIZED,
            $status->getCode()
        );
        $this->assertEquals(
            'user1',
            $status->getIdentity()
        );

        $acl->getArrayListAdapter()->setMode(ArrayListAdapter::MODE_CHILL);
        $status = $acl->getAccessStatus(
            'user1',
            new ResourceIdentifier(
                'MultiplePermissionsController',
                'undefinedRoleAction'
            )
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

    /**
     * @throws AccessControlException
     */
    public function testGetAccessStatusWithNotFoundRole()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities
        );

        $status = $acl->getAccessStatus(
            'user1',
            new ResourceIdentifier(
                'MultiplePermissionsController',
                'notFoundRoleAction'
            )
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

    /**
     * @throws AccessControlException
     */
    public
    function testGetAccessStatusWithStrictModeAndFoundButUndefinedPermission()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
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
            new ResourceIdentifier(
                'MultiplePermissionsController',
                'foundButUndefinedPermAction'
            )
        );
    }

    /**
     * @throws AccessControlException
     */
    public
    function testGetAccessStatusWithChillModeAndFoundButUndefinedPermission()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_CHILL,
            ArrayAccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities
        );
        $status = $acl->getAccessStatus(
            'user5',
            new ResourceIdentifier(
                'MultiplePermissionsController',
                'foundButUndefinedPermAction'
            )
        );
        $this->assertEquals(
            Status::OK,
            $status->getCode()
        );
        $this->assertEquals(
            'user5',
            $status->getIdentity()
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testGetAccessStatusWithStrictModeAndFoundButUndefinedRole()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
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
            new ResourceIdentifier(
                'MultiplePermissionsController',
                'foundButUndefinedRoleAction'
            )
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testGetAccessStatusWithChillModeAndFoundButUndefinedRole()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_CHILL,
            ArrayAccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities,
            $this->roles
        );
        $status = $acl->getAccessStatus(
            'user4',
            new ResourceIdentifier(
                'MultiplePermissionsController',
                'foundButUndefinedRoleAction'
            )
        );
        $this->assertEquals(
            Status::OK,
            $status->getCode()
        );
        $this->assertEquals(
            'user4',
            $status->getIdentity()
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testGetAccessStatusWithInvalidFormat()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            $this->controllers
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_INVALID_ACCESS_FORMAT
        );
        $acl->getAccessStatus(
            null,
            new ResourceIdentifier(
                'MultiplePermissionsController',
                'invalidPermAction'
            )
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testGetAccessStatusWithInvalidPrefixFormat()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            $this->controllers
        );
        $this->expectException(AccessControlException::class);
        $this->expectExceptionCode(
            AccessControlException::ACL_INVALID_ACCESS_FORMAT
        );
        $acl->getAccessStatus(
            null,
            new ResourceIdentifier(
                'MultiplePermissionsController',
                'invalidPrefixAction'
            )
        );
    }

    /**
     * @throws AccessControlException
     */
    public function testGetAccessStatusAuthenticateWithEmptyIdentity()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
            $this->controllers,
            $this->identities,
            $this->roles,
            $this->permissions
        );
        $statuses = [];

        $statuses[] = $acl->getAccessStatus(
            '',
            new ResourceIdentifier('AuthRequiredController')
        );
        $statuses[] = $acl->getAccessStatus(
            '',
            new ResourceIdentifier(
                'MultiplePermissionsController',
                'authedAction'
            )
        );
        $statuses[] = $acl->getAccessStatus(
            null,
            new ResourceIdentifier('AuthRequiredController')
        );
        $statuses[] = $acl->getAccessStatus(
            null,
            new ResourceIdentifier(
                'MultiplePermissionsController',
                'authedAction'
            )
        );
        foreach ($statuses as $status) {
            $this->assertSame(
                Status::UNAUTHENTICATED,
                $status->getCode()
            );
            $this->assertTrue(
                empty($status->getIdentity())
            );
        }
    }

    /**
     * @throws AccessControlException
     */
    public function testGetAccessStatus()
    {
        $acl = new ArrayAccessControlList(
            ArrayListAdapter::MODE_STRICT,
            ArrayAccessControlList::POLICY_REJECT,
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
            $cases = array_merge($commonCases, $identityCases);
            foreach ($cases as $testCase) {
                $total++;
                $status = $acl->getAccessStatus(
                    $identity,
                    new ResourceIdentifier(
                        $testCase['controller'],
                        $testCase['action'] ?? null
                    )
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

    public function testPermissionHelper()
    {
        $this->assertSame(
            ArrayAccessControlList::ACCESS_PREFIX_PERM
            . ArrayAccessControlList::ACCESS_PREFIX_DELIMITER
            . 'test',
            ArrayAccessControlList::permission('test')
        );
    }

    public function testRoleHelper()
    {
        $this->assertSame(
            ArrayAccessControlList::ACCESS_PREFIX_ROLE
            . ArrayAccessControlList::ACCESS_PREFIX_DELIMITER
            . 'test',
            ArrayAccessControlList::role('test')
        );
    }
}