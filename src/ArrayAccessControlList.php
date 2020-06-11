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
 *
 * Date: 2020-05-08
 * Time: 14:09
 */

namespace AliChry\Laminas\AccessControl;

class ArrayAccessControlList implements AccessControlListInterface
{
    const MODE_STRICT = 0;
    const MODE_CHILL = 1;

    const POLICY_REJECT = 0;
    const POLICY_AUTENTICATE = 1;
    const POLICY_ACCEPT = 2;

    const ACCESS_ALL = '*';
    const ACCESS_AUTHENTICATED_ONLY = '+';
    const ACCESS_REJECT_ALL = '^';
    const ACCESS_PREFIX_DELIMITER = ':';
    const ACCESS_PREFIX_PERM = 'perm';
    const ACCESS_PREFIX_ROLE = 'role';

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
     * controllers/actions
     */
    private $mode;

    /**
     * @var int
     * Policy helps dictate when filtering against an
     * undefined controller or controller action in
     * the controllers array
     */
    private $policy;

    /**
     * @var array
     * Associative array where the keys represent
     * the controller's class name and the values
     * are either an (associative array with keys
     * as actions where its values indicate the
     * permission names) or (a string implying the
     * permission or required authentication level)
     * Controllers/actions are the objects that the
     * identities are given permissions for.
     * This is the resource list
     */
    private $controllers;

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
     * role name, and the value  can be either a
     * string implying the permission name or an
     * array of permission names.
     */
    private $roles;

    /**
     * @var array of system-defined permissions
     * if chill mode is used, this can be empty
     */
    private $permissions;

    /**
     * ArrayAccessControlList constructor.
     * @param int $mode
     * @param int $policy
     * @param array $controllers
     * @param array $identities
     * @param array $roles
     * @param null|array $permissions
     * @throws AccessControlException
     */
    public function __construct(
        int $mode,
        int $policy,
        array $controllers,
        array $identities = null,
        array $roles = null,
        array $permissions = null
    )
    {
        $identities = $identities ?? [];
        $roles = $roles ?? [];
        $permissions = $permissions ?? [];
        $this->setMode($mode);
        $this->setPolicy($policy);
        $this->setControllers($controllers);
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
     * @return int
     */
    public function getPolicy(): int
    {
        return $this->policy;
    }

    /**
     * @param int $policy
     * @throws AccessControlException
     */
    public function setPolicy(int $policy): void
    {
        if (!$this->checkPolicy($policy)) {
            throw new AccessControlException(
                sprintf(
                    'Policy "%s" is not valid',
                    $policy
                ),
                AccessControlException::ACL_INVALID_POLICY
            );
        }
        $this->policy = $policy;
    }

    /**
     * @return array
     */
    public function getControllers(): array
    {
        return $this->controllers;
    }

    /**
     * @param array $controllers
     */
    private function setControllers(array $controllers)
    {
        $this->controllers = $controllers;
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
     * @return array|\Traversable
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
     * @return array|\Traversable
     * @throws AccessControlException
     */
    public function getIdentityRoles($identityName)
    {
        $identity = $this->getIdentity($identityName);
        return $identity[self::IDENTITY_ROLES_KEY] ?? [];
    }

    /**
     * @param $identityName
     * @return array|\Traversable
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
            $permissions = \array_merge(
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
        return \in_array($permissionName, $identityPermissions, true);
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
        $found = \in_array($roleName, $identityRoles, true);
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
     * @param string $controller
     * @param ?string $action
     * @return int
     * @throws AccessControlException
     */
    public function getControllerAccess($controller, $action = null)
    {
        $access = $this->controllers[$controller] ?? null;
        $isArray = is_array($access);
        if (
            null === $access
            || (
                true === $isArray
                && ! isset($access[$action])
            )
        ) {
            if (self::MODE_STRICT === $this->mode) {
                throw new AccessControlException(
                    sprintf(
                        'Controller/action not registered in controllers array,
                        controller: %s, action: %s',
                        $controller, (string) $action
                    ),
                    ! $access
                        ? AccessControlException::ACL_CONTROLLER_NOT_DEFINED
                        : AccessControlException::ACL_ACTION_NOT_DEFINED
                );
            }
            switch ($this->getPolicy()) {
                case self::POLICY_ACCEPT:
                    return self::ACCESS_ALL;
                case self::POLICY_AUTENTICATE:
                    return self::ACCESS_AUTHENTICATED_ONLY;
                case self::POLICY_REJECT:
                    return self::ACCESS_REJECT_ALL;
            }
        }
        if (! $isArray) {
            $value = $access;
        } else {
            $value = $access[$action];
        }
        if (! $this->checkAccess($value)) {
            throw new AccessControlException(
                sprintf(
                    'Invalid permission/role value for controller: %s, '
                    . ' action: %s',
                    $controller,
                    $action
                ),
                AccessControlException::ACL_INVALID_ACCESS_FORMAT
            );
        }
        return $value;
    }

    /**
     * @param string $identityName
     * @param string $controller
     * @param null|string $action
     * @return Status
     * @throws AccessControlException
     */
    public function getAccessStatus(
        $identityName,
        $controller,
        $action = null
    ): Status
    {
        $access = $this->getControllerAccess($controller, $action);
        switch ($access) {
            case self::ACCESS_ALL:
                return new Status(Status::PUBLIC, $identityName);
            case self::ACCESS_REJECT_ALL:
                return new Status(Status::REJECTED, $identityName);
            case self::ACCESS_AUTHENTICATED_ONLY:
                return new Status(Status::OK, $identityName);
            default:
                // permission or role
                $authorized = false;
                $explode = explode(self::ACCESS_PREFIX_DELIMITER, $access, 2);
                $prefix = $explode[0] ?? null;
                $value = $explode[1] ?? null;
                switch ($prefix) {
                    case self::ACCESS_PREFIX_PERM:
                        $authorized = $this->identityHasPermission(
                            $identityName,
                            $value
                        );
                        break;
                    case self::ACCESS_PREFIX_ROLE:
                        $authorized = $this->identityHasRole(
                            $identityName,
                            $value
                        );
                        break;
                    default:
                        throw new AccessControlException(
                            sprintf(
                                'Invalid permission/role format "%s"',
                                $access
                            ),
                            AccessControlException::ACL_INVALID_ACCESS_FORMAT
                        );
                }
                if (true === $authorized) {
                    return new Status(Status::OK, $identityName);
                }
                return new Status(
                    Status::UNAUTHORIZED,
                    $identityName,
                    [
                        sprintf(
                            'Identity "%s" requires %s',
                            $identityName,
                            $access
                        )
                    ]
                );
        }
    }

    /**
     * @param string $roleName
     * @return array|\Traversable
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
     * @param $controller
     * @param $action
     * @return bool
     * @throws AccessControlException
     */
    public function needsAuthentication($controller, $action): bool
    {
        $access = $this->getControllerAccess($controller, $action);
        switch ($access) {
            case self::ACCESS_ALL:
                return false;
            case self::ACCESS_REJECT_ALL:
                return false;
            case self::ACCESS_AUTHENTICATED_ONLY:
            default:
                return true;
        }
    }

    /**
     * @param $name
     * @return string
     */
    public static function permission($name): string
    {
        return self::ACCESS_PREFIX_PERM
            . self::ACCESS_PREFIX_DELIMITER
            . $name;
    }

    /**
     * @param $name
     * @return string
     */
    public static function role($name): string
    {
        return self::ACCESS_PREFIX_ROLE
            . self::ACCESS_PREFIX_DELIMITER
            . $name;
    }

    /**
     * @param string $permissionName
     * @return bool
     */
    private function checkPermission($permissionName): bool
    {
        return \in_array($permissionName, $this->permissions, true);
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

    private function checkPolicy($policy): bool
    {
        return $policy === self::POLICY_REJECT
            || $policy === self::POLICY_AUTENTICATE
            || $policy === self::POLICY_ACCEPT;
    }

    private function checkAccess($access): bool
    {
        switch ($access) {
            case self::ACCESS_ALL:
            case self::ACCESS_REJECT_ALL:
            case self::ACCESS_AUTHENTICATED_ONLY:
                return true;
            default:
                $prefix = explode(self::ACCESS_PREFIX_DELIMITER, $access, 2)[0]
                    ?? null;
                if (
                    null === $prefix
                    || (
                        $prefix !== self::ACCESS_PREFIX_PERM
                        && $prefix !== self::ACCESS_PREFIX_ROLE
                    )
                ) {
                    return false;
                }
                return true;
        }
    }
}