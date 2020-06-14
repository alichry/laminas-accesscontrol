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

namespace AliChry\Laminas\AccessControl\Resource;

use AliChry\Laminas\AccessControl\Permission\PermissionInterface;
use AliChry\Laminas\AccessControl\Policy\PolicyInterface;

class Resource implements ResourceInterface
{
    /**
     * @var ResourceIdentifierInterface
     */
    private $identifier;

    /**
     * @var PolicyInterface
     */
    private $policy;

    /**
     * @var mixed|PermissionInterface
     */
    private $permission;

    /**
     * Resource constructor.
     * @param $identifier
     * @param $policy
     * @param null $permission
     */
    public function __construct($identifier, $policy, $permission = null)
    {
        $this->setIdentifier($identifier);
        $this->setPolicy($policy);
        $this->setPermission($permission);
    }

    /**
     * @return ResourceIdentifierInterface
     */
    public function getIdentifier()
    {
        return $this->identifier;
    }

    /**
     * @param ResourceIdentifierInterface $identifier
     */
    public function setIdentifier(ResourceIdentifierInterface $identifier)
    {
        $this->identifier = $identifier;
    }

    /**
     * @return PolicyInterface
     */
    public function getPolicy(): PolicyInterface
    {
        return $this->policy;
    }

    /**
     * @param PolicyInterface $policy
     */
    public function setPolicy(PolicyInterface $policy)
    {
        $this->policy = $policy;
    }

    /**
     * @return PermissionInterface
     */
    public function getPermission(): PermissionInterface
    {
        return $this->permission;
    }

    /**
     * @param PermissionInterface|mixed|null $permission
     */
    public function setPermission($permission = null)
    {
        $this->permission = $permission;
    }
}