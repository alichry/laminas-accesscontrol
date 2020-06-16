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

use AliChry\Laminas\AccessControl\Lists\ArrayListAdapter;
use AliChry\Laminas\AccessControl\Resource\ResourceIdentifierInterface;

class ArrayAccessControlList implements AccessControlListInterface
{
    const POLICY_REJECT = 0;
    const POLICY_AUTHENTICATE = 1;
    const POLICY_ACCEPT = 2;

    const ACCESS_ALL = '*';
    const ACCESS_AUTHENTICATED_ONLY = '+';
    const ACCESS_REJECT_ALL = '^';
    const ACCESS_PREFIX_DELIMITER = ':';
    const ACCESS_PREFIX_PERM = 'perm';
    const ACCESS_PREFIX_ROLE = 'role';

    /**
     * @var ArrayListAdapter
     */
    private $arrayListAdapter;

    /**
     * @var int
     * Policy helps dictate when filtering against an
     * undefined controller or controller method in
     * the controllers array
     */
    private $policy;

    /**
     * @var array
     * Associative array where the keys represent
     * the controller's class name and the values
     * are either an (associative array with keys
     * as methods where its values indicate the
     * permission names) or (a string implying the
     * permission or required authentication level)
     * Controllers/methods are the objects (resources)
     * that the identities are given permissions for.
     * This is the resource list
     */
    private $controllers;

    /**
     * ArrayAccessControlList constructor.
     * @param int $mode
     * @param int $policy
     * @param null|array $controllers
     * @param null|array $identities
     * @param null|array $roles
     * @param null|array $permissions
     * @throws AccessControlException
     */
    public function __construct(
        int $mode,
        int $policy,
        array $controllers = null,
        array $identities = null,
        array $roles = null,
        array $permissions = null
    )
    {
        $controllers = $controllers ?? [];
        $this->setPolicy($policy);
        $this->setControllers($controllers);
        $this->setArrayListAdapter(
            new ArrayListAdapter(
                $mode,
                $identities,
                $roles,
                $permissions
            )
        );
    }

    /**
     * @return ArrayListAdapter
     */
    public function getArrayListAdapter()
    {
        return $this->arrayListAdapter;
    }

    /**
     * @param ArrayListAdapter $list
     */
    private function setArrayListAdapter(ArrayListAdapter $list)
    {
        $this->arrayListAdapter = $list;
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
     * @param string $identityName
     * @param string $permissionName
     * @return bool
     * @throws AccessControlException
     */
    public function identityHasPermission($identityName, $permissionName): bool
    {
        return $this->arrayListAdapter->identityHasPermission(
            $identityName,
            $permissionName
        );
    }

    /**
     * @param string $identityName
     * @param string $roleName
     * @return bool
     * @throws AccessControlException
     */
    public function identityHasRole($identityName, $roleName): bool
    {
        return $this->arrayListAdapter->identityHasRole(
            $identityName,
            $roleName
        );
    }

    /**
     * @param string $controller
     * @param null|string $method
     * @return int
     * @throws AccessControlException
     */
    public function getControllerAccess($controller, $method = null)
    {
        $access = $this->controllers[$controller] ?? null;
        $isArray = is_array($access);
        if (
            null === $access
            || (
                true === $isArray
                && ! isset($access[$method])
            )
        ) {
            if (
                ArrayListAdapter::MODE_STRICT ===
                    $this->arrayListAdapter->getMode()
            ) {
                throw new AccessControlException(
                    sprintf(
                        'Controller/method not registered in controllers array,
                        controller: %s, method: %s',
                        $controller, (string) $method
                    ),
                    ! $access
                        ? AccessControlException::ACL_CONTROLLER_NOT_DEFINED
                        : AccessControlException::ACL_METHOD_NOT_DEFINED
                );
            }
            switch ($this->getPolicy()) {
                case self::POLICY_ACCEPT:
                    return self::ACCESS_ALL;
                case self::POLICY_AUTHENTICATE:
                    return self::ACCESS_AUTHENTICATED_ONLY;
                case self::POLICY_REJECT:
                    return self::ACCESS_REJECT_ALL;
            }
        }
        if (! $isArray) {
            $value = $access;
        } else {
            $value = $access[$method];
        }
        if (! $this->checkAccess($value)) {
            throw new AccessControlException(
                sprintf(
                    'Invalid permission/role value for controller: %s, '
                    . ' method: %s',
                    $controller,
                    $method
                ),
                AccessControlException::ACL_INVALID_ACCESS_FORMAT
            );
        }
        return $value;
    }

    /**
     * @param string $identityName
     * @param ResourceIdentifierInterface $resourceIdentifier
     * @return Status
     * @throws AccessControlException
     */
    public function getAccessStatus(
        $identityName,
        $resourceIdentifier
    ): Status
    {
        $controller = $resourceIdentifier->getController();
        $method = $resourceIdentifier->getMethod();
        $access = $this->getControllerAccess($controller, $method);
        switch ($access) {
            case self::ACCESS_ALL:
                return new Status(Status::PUBLIC, $identityName);
            case self::ACCESS_REJECT_ALL:
                return new Status(Status::REJECTED, $identityName);
            case self::ACCESS_AUTHENTICATED_ONLY:
                if (empty($identityName)) {
                    return new Status(Status::UNAUTHENTICATED, $identityName);
                }
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

    private function checkPolicy($policy): bool
    {
        return $policy === self::POLICY_REJECT
            || $policy === self::POLICY_AUTHENTICATE
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
                $explode = explode(self::ACCESS_PREFIX_DELIMITER, $access, 2);
                $prefix = $explode[0] ?? null;
                $value = $explode[1] ?? null;
                if (
                    null === $prefix
                    || null === $value
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