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

use AliChry\Laminas\AccessControl\Lists\ListAdapterInterface;

class AccessControlList extends AbstractAccessControlList
{
    /**
     * @var ListAdapterInterface
     */
    private $listAdapter;

    public function __construct($resourceManager, $listAdapter)
    {
        parent::__construct($resourceManager);
        $this->setListAdapter($listAdapter);
    }

    /**
     * @return ListAdapterInterface
     */
    public function getListAdapter(): ListAdapterInterface
    {
        return $this->listAdapter;
    }

    /**
     * @param ListAdapterInterface $listAdapter
     */
    private function setListAdapter(
        ListAdapterInterface $listAdapter
    ): void
    {
        $this->listAdapter = $listAdapter;
    }

    /**
     * @param $identity
     * @param $permission
     * @return bool
     */
    public function identityHasPermission($identity, $permission): bool
    {
        return $this->listAdapter->identityHasPermission(
            $identity,
            $permission
        );
    }

    /**
     * @param $identity
     * @param $role
     * @return bool
     */
    public function identityHasRole($identity, $role): bool
    {
        return $this->listAdapter->identityHasRole(
            $identity,
            $role
        );
    }

    /**
     * @param $identity
     * @return bool
     */
    public function checkIdentity($identity): bool
    {
        return ! empty($identity);
    }
}