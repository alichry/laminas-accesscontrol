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

namespace AliChry\Laminas\AccessControl;

use AliChry\Laminas\AccessControl\Identity\IdentityInterface;
use AliChry\Laminas\AccessControl\Resource\ResourceManagerInterface;

class AccessControlList implements AccessControlListInterface
{
    /**
     * @var ResourceManagerInterface
     */
    private $resourceManager;

    /**
     * AccessControlList constructor.
     * @param ResourceManagerInterface $resourceManager
     */
    public function __construct($resourceManager)
    {
        $this->setResourceManager($resourceManager);
    }

    /**
     * @return ResourceManagerInterface
     */
    public function getResourceManager(): ResourceManagerInterface
    {
        return $this->resourceManager;
    }

    /**
     * @param ResourceManagerInterface $resourceManager
     */
    private function setResourceManager(ResourceManagerInterface $resourceManager)
    {
        $this->resourceManager = $resourceManager;
    }

    /**
     * @param null|IdentityInterface $identity
     * @param $permission
     * @return bool
     * @throws AccessControlException
     */
    public function identityHasPermission($identity, $permission): bool
    {
        if (null === $identity) {
            return false;
        }
        if (! $this->checkIdentity($identity)) {
            throw new AccessControlException(
                sprintf(
                    'Expecting passed identity to be an instance of %s, got: %s',
                    IdentityInterface::class,
                    is_object($identity)
                        ? get_class($identity)
                        : gettype($identity)
                )
            );
        }
        /*if (
            ! is_object($permission)
            || ! $permission instanceof PermissionInterface
        ) {
            throw new AccessControlException(
                sprintf(
                    'Expecting passed permission to be an instance of %s, got: %s',
                    PermissionInterface::class,
                    is_object($permission)
                        ? get_class($permission)
                        : gettype($permission)
                )
            );
        }*/
        return $identity->hasPermission($permission);
    }

    /**
     * @param null|IdentityInterface $identity
     * @param $role
     * @return bool
     * @throws AccessControlException
     */
    public function identityHasRole($identity, $role): bool
    {
        if (null === $identity) {
            return false;
        }
        if (! $this->checkIdentity($identity)) {
            throw new AccessControlException(
                sprintf(
                    'Expecting passed identity to be an instance of %s, got: %s',
                    IdentityInterface::class,
                    is_object($identity)
                        ? get_class($identity)
                        : gettype($identity)
                )
            );
        }
        /*if (! is_object($role) || ! $role instanceof PermissionInterface) {
            throw new AccessControlException(
                sprintf(
                    'Expecting passed role to be an instance of %s, got: %s',
                    PermissionInterface::class,
                    is_object($role)
                        ? get_class($role)
                        : gettype($role)
                )
            );
        }*/
        return $identity->hasRole($role);
    }

    /**
     * @param null|IdentityInterface $identity
     * @param $controller
     * @param null $action
     * @return Status
     * @throws AccessControlException
     */
    public function getAccessStatus($identity, $controller, $action = null): Status
    {
        $resource = $this->resourceManager->getResource($controller, $action);
        $policy = $resource->getPolicy();
        if ($policy->isPublic()) {
            return new Status(Status::PUBLIC, $identity);
        }
        if ($policy->deniesAll()) {
            return new Status(Status::REJECTED, $identity);
        }
        if ($policy->requiresAuthentication()) {
            if (null === $identity) {
                return new Status(Status::UNAUTHENTICATED, $identity);
            }
            if (! $this->checkIdentity($identity)) {
                throw new AccessControlException(
                    sprintf(
                        'Expecting passed identity to be an instance of %s, '
                        . 'got: %s',
                        IdentityInterface::class,
                        is_object($identity)
                            ? get_class($identity)
                            : gettype($identity)
                    )
                );
            }
            return new Status(Status::OK, $identity);
        }
        if ($policy->requiresAuthorization()) {
            $permission = $resource->getPermission();
            $authorized = $this->identityHasPermission($identity, $permission);
            if (true === $authorized) {
                return new Status(Status::OK, $identity);
            }
            return new Status(Status::UNAUTHORIZED, $identity);
        }
        throw new AccessControlException(
            'Retrieved policy failed to assert requirement'
        );
    }

    /**
     * @param $identity
     * @return bool
     */
    private function checkIdentity($identity)
    {
        return is_object($identity)
            && $identity instanceof IdentityInterface;
    }
}

