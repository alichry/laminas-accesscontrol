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

namespace AliChry\Laminas\AccessControl\Lists;

use AliChry\Laminas\AccessControl\AccessControlException;

use function array_merge;
use function in_array;

class ArrayListAdapter implements ListAdapterInterface
{
    const MODE_STRICT = 0;
    const MODE_CHILL = 1;
    const IDENTITY_ROLES_KEY = 'roles';
    const IDENTITY_PERMS_KEY = 'permissions';

    /**
     * @var int
     * strict mode checks for missing values
     * in controllers, permissions and identities arrays.
     * In other words,
     * - the controllers array must contain the list of
     * all routed controllers (accessible), and
     * - the identities array must contain the list
     * of all users (that you reference), and
     * - the permissions array must contain the list
     * of all valid permission names (that you reference).
     * chill mode allows you to save on storage space by
     * allowing you not to storing the list of users that
     * does not have any extra roles or permissions as well as
     * not defining a permissions list at the cost of relying
     * on the policy selected for checking against undefined
     * controllers/methods
     */
    private $mode;

    /**
     * @var array
     * Associative array where the key is the
     * identity name and the value is an
     * associative array with keys 'roles' or
     * 'permissions' with values as array of
     * roles and permissions names respectively.
     * This is the subject list with their corresponding
     * permissions/roles
     */
    private $identities;

    /**
     * @var array of system-defined roles. it is
     * an associative array where the key is the
     * role name, and the value is an array of
     * permission names.
     */
    private $roles;

    /**
     * @var array of system-defined permissions
     * if chill mode is used, this can be empty
     */
    private $permissions;

    /**
     * ArrayListAdapter constructor.
     * @param int $mode
     * @param array|null $identities
     * @param array|null $roles
     * @param array|null $permissions
     * @throws AccessControlException
     */
    public function __construct(
        int $mode,
        array $identities = null,
        array $roles = null,
        array $permissions = null
    )
    {
        $identities = $identities ?? [];
        $roles = $roles ?? [];
        $permissions = $permissions ?? [];
        $this->setMode($mode);
        $this->setIdentities($identities);
        $this->setRoles($roles);
        $this->setPermissions($permissions);
    }

    /**
     * @return int
     */
    public function getMode(): int
    {
        return $this->mode;
    }

    /**
     * @param int $mode
     * @throws AccessControlException
     */
    public function setMode(int $mode): void
    {
        if (!$this->checkMode($mode)) {
            throw new AccessControlException(
                sprintf(
                    'Mode "%s" is not valid',
                    $mode
                ), AccessControlException::ACL_INVALID_MODE
            );
        }
        $this->mode = $mode;
    }

    /**
     * @return array
     */
    public function getIdentities(): array
    {
        return $this->identities;
    }

    /**
     * @param array $identities
     */
    private function setIdentities(array $identities)
    {
        $this->identities = $identities;
    }

    /**
     * @return array
     */
    public function getRoles(): array
    {
        return $this->roles;
    }

    /**
     * @param $roles
     */
    private function setRoles(array $roles)
    {
        $this->roles = $roles;
    }

    /**
     * @return null|array
     */
    public function getPermissions(): ?array
    {
        return $this->permissions;
    }

    /**
     * @param array $permissions
     */
    private function setPermissions(array $permissions)
    {
        $this->permissions = $permissions;
    }

    /**
     * @param $identityName
     * @return array
     * @throws AccessControlException
     */
    public function getIdentity($identityName)
    {
        if (! $this->checkIdentity($identityName)) {
            if ($this->mode === self::MODE_CHILL) {
                return [];
            }
            throw new AccessControlException(
                sprintf(
                    'Identity "%s" is not defined in identities list',
                    $identityName
                ), AccessControlException::ACL_IDENTITY_NOT_DEFINED
            );
        }
        $identity = $this->identities[$identityName];
        if (
            ! is_array($identity)
            && ! $identity instanceof \Traversable
        ) {
            throw new AccessControlException(
                sprintf(
                    'Expected identity "%s" to be an array or instance of '
                    . 'Traversable, "%s" given',
                    $identityName,
                    is_object($identity)
                        ? get_class($identity)
                        : gettype($identity)
                ), AccessControlException::ACL_BAD_IDENTITY
            );
        }
        return $identity;
    }

    /**
     * @param string $identityName
     * @return array
     * @throws AccessControlException
     */
    public function getIdentityRoles($identityName)
    {
        $identity = $this->getIdentity($identityName);
        return $identity[self::IDENTITY_ROLES_KEY] ?? [];
    }

    /**
     * @param $identityName
     * @return array
     * @throws AccessControlException
     * @note Strict mode does not help here in checking if the returned
     *       permission array is defined in the permission list
     */
    public function getIdentityPermissions($identityName)
    {
        $identity = $this->getIdentity($identityName);
        $permissions = $identity[self::IDENTITY_PERMS_KEY] ?? [];
        //$roles = $this->getIdentityRoles($identityName);
        $roles = $identity[self::IDENTITY_ROLES_KEY] ?? [];
        foreach ($roles as $roleName) {
            $permissions = array_merge(
                $permissions,
                $this->getRolePermissions($roleName)
            );
        }
        return $permissions;
    }

    /**
     * @param string $identityName
     * @param string $permissionName
     * @return bool
     * @throws AccessControlException
     */
    public function identityHasPermission(
        $identityName,
        $permissionName
    ): bool
    {
        if (
            $this->mode === self::MODE_STRICT
            && !$this->checkPermission($permissionName)
        ) {
            throw new AccessControlException(
                sprintf(
                    'Permission "%s" is not defined in permission list: %s',
                    $permissionName,
                    implode(', ', $this->permissions)
                ), AccessControlException::ACL_PERMISSION_NOT_DEFINED
            );
        }
        $identityPermissions = $this->getIdentityPermissions($identityName);
        return in_array($permissionName, $identityPermissions, true);
    }

    /**
     * @param string $identityName
     * @param string $roleName
     * @return bool
     * @throws AccessControlException
     */
    public function identityHasRole(
        $identityName,
        $roleName
    ): bool
    {
        $identityRoles = $this->getIdentityRoles($identityName);
        $found = in_array($roleName, $identityRoles, true);
        if (
            $found === true
            && $this->mode === self::MODE_STRICT
            && ! $this->checkRole($roleName)
        ) {
            throw new AccessControlException(
                sprintf(
                    'Role "%s" is not defined in role list',
                    $roleName
                ),
                AccessControlException::ACL_ROLE_NOT_DEFINED
            );
        }
        return $found;
    }

    /**
     * @param string $roleName
     * @return array
     * @throws AccessControlException
     * @note Strict mode does not help here in checking if the returned
     *       permission array is defined in the permission list
     */
    public function getRolePermissions($roleName)
    {
        if (!$this->checkRole($roleName)) {
            throw new AccessControlException(
                sprintf(
                    'Role "%s" is not defined in role list',
                    $roleName
                ),
                AccessControlException::ACL_ROLE_NOT_DEFINED
            );
        }
        $role = $this->roles[$roleName];
        if (!is_array($role) && !$role instanceof \Traversable) {
            throw new AccessControlException(
                sprintf(
                    'Expected role "%s" to be an array or an instance of '
                    . 'Traversable, "%s" given',
                    $role,
                    gettype($role)
                ), AccessControlException::ACL_BAD_ROLE
            );
        }
        return $role;
    }

    /**
     * @param string $roleName
     * @param string $permissionName
     * @return bool
     * @throws AccessControlException
     */
    public function roleHasPermission($roleName, $permissionName): bool
    {
        $role = $this->getRolePermissions($roleName);
        if (
            $this->mode === self::MODE_STRICT
            && !$this->checkPermission($permissionName)
        ) {
            throw new AccessControlException(
                sprintf(
                    'Permission "%s" does not exists in permission list',
                    $permissionName
                ), AccessControlException::ACL_PERMISSION_NOT_DEFINED
            );
        }
        return in_array($permissionName, $role, true);
    }

    /**
     * @param string $permissionName
     * @return bool
     */
    private function checkPermission($permissionName): bool
    {
        return in_array($permissionName, $this->permissions, true);
    }

    /**
     * @param string $roleName
     * @return bool
     */
    private function checkRole($roleName): bool
    {
        return isset($this->roles[$roleName]);
    }

    /**
     * @param string $identityName
     * @return bool
     */
    private function checkIdentity($identityName): bool
    {
        return isset($this->identities[$identityName]);
    }

    /**
     * @param $mode
     * @return bool
     */
    private function checkMode($mode): bool
    {
        return $mode === self::MODE_STRICT
            || $mode === self::MODE_CHILL;
    }

    /* Leaving this for future reference

    private function addIdentity($identity)
    {
        $this->createIdentityIfNotExists($identity);
    }

    private function addIdentityRole($identity, $role)
    {
        $this->createIdentityIfNotExists($identity);
        $this->createRoleIfNotExists($role);
        if (
            in_array(
                $role,
                $this->identities[$identity]['roles'][$role]
            )
        ) {
            return;
        }
        $this->identities[$identity]['roles'][] = $role;
    }

    private function addRolePermission($role, $permission)
    {
        $this->createRoleIfNotExists($role);
        $this->createPermissionIfNotExists($permission);
        $this->roles[$role][] = $permission;
    }

    private function addRolePermissions($role, arrray $permissions)
    {
        $this->createRoleIfNotExists($role);
        foreach ($permissions as $permission) {
            $this->createPermissionIfNotExists($permission);
        }
        $this->roles[$role] = array_merge(
            $this->roles[$role],
            $permissions
        );
    }

    private function addIdentityPermission($identity, $permission)
    {
        $this->createIdentityIfNotExists($identity);
        $this->createPermissionIfNotExists($permission);
        $this->identities[$identity]['permissions'][] = $permission;
    }

    private function checkIdentities(array $identities)
    {
        foreach ($identities as $identity) {
            if (! is_array($identity)) {
                return false;
            }
            if (! isset($identity['roles'])) {
                return false;
            }
            if (! isset($identity['permissions'])) {
                return false;
            }
            if (! is_array($identity['roles'])) {
                return false;
            }
            if (! is_array($identity['permissions'])) {
                return false;
            }
        }
        return true;
    }

    private function createIdentityIfNotExists($identity)
    {
        if (isset($this->identities[$identity])) {
            return;
        }
        $this->identities[$identity] = [
            'roles' => [],
            'permissions' => []
        ];
    }

    private function createRoleIfNotExists($role)
    {
        if (isset($this->roles[$role])) {
            return;
        }
        $this->roles[$role] = [];
    }

    private function createPermissionIfNotExists($permission)
    {
        if (in_array($permission, $this->permissions)) {
            return;
        }
        $this->permissions[] = $permission;
    }
    */
}