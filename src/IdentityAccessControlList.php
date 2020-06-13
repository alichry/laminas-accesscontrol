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

class IdentityAccessControlList extends AbstractAccessControlList
{
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
        return $identity->hasRole($role);
    }

    /**
     * @param $identity
     * @return bool
     */
    public function checkIdentity($identity): bool
    {
        return is_object($identity)
            && $identity instanceof IdentityInterface;
    }
}

