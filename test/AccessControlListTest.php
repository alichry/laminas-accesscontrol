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

use AliChry\Laminas\AccessControl\AccessControlException;
use AliChry\Laminas\AccessControl\AccessControlList;
use AliChry\Laminas\AccessControl\Lists\ListAdapterInterface;
use AliChry\Laminas\AccessControl\Resource\ResourceManagerInterface;
use PHPUnit\Framework\TestCase;

class AccessControlListTest extends TestCase
{
    public function testResourceManager()
    {
        $rm = $this->createMock(ResourceManagerInterface::class);
        $list = $this->createMock(ListAdapterInterface::class);
        $acl = new AccessControlList($rm, $list);
        $this->assertSame(
            $rm,
            $acl->getResourceManager()
        );
    }

    public function testListAdapter()
    {
        $rm = $this->createMock(ResourceManagerInterface::class);
        $list = $this->createMock(ListAdapterInterface::class);
        $acl = new AccessControlList($rm, $list);
        $this->assertSame(
            $list,
            $acl->getListAdapter()
        );
    }

    public function testIdentityHasPermission()
    {
        $rm = $this->createMock(ResourceManagerInterface::class);
        $list = $this->createMock(ListAdapterInterface::class);
        $acl = new AccessControlList($rm, $list);
        $list->expects($this->exactly(2))
            ->method('identityHasPermission')
            ->will(
                $this->returnValueMap(
                    [
                        ['testIdentity', 'permTrue', true],
                        ['testIdentity2', 'permFalse', false]
                    ]
                )
            );
        $this->assertSame(
            true,
            $acl->identityHasPermission('testIdentity', 'permTrue')
        );
        $this->assertSame(
            false,
            $acl->identityHasPermission('testIdentity2', 'permFalse')
        );
    }

    public function testIdentityHasPermissionThrowsException()
    {
        $rm = $this->createMock(ResourceManagerInterface::class);
        $list = $this->createMock(ListAdapterInterface::class);
        $acl = new AccessControlList($rm, $list);
        $list->expects($this->once())
            ->method('identityHasPermission')
            ->with('testIdentity', 'perm')
            ->willThrowException(new AccessControlException('bad input'));

        $this->expectException(AccessControlException::class);
        $this->expectExceptionMessage('bad input');
        $acl->identityHasPermission('testIdentity', 'perm');
    }

    public function testIdentityHasRole()
    {
        $rm = $this->createMock(ResourceManagerInterface::class);
        $list = $this->createMock(ListAdapterInterface::class);
        $acl = new AccessControlList($rm, $list);
        $list->expects($this->exactly(2))
            ->method('identityHasRole')
            ->will(
                $this->returnValueMap(
                    [
                        ['testIdentity', 'roleTrue', true],
                        ['testIdentity2', 'roleFalse', false]
                    ]
                )
            );
        $this->assertSame(
            true,
            $acl->identityHasRole('testIdentity', 'roleTrue')
        );
        $this->assertSame(
            false,
            $acl->identityHasRole('testIdentity2', 'roleFalse')
        );
    }

    public function testIdentityHasRoleThrowsException()
    {
        $rm = $this->createMock(ResourceManagerInterface::class);
        $list = $this->createMock(ListAdapterInterface::class);
        $acl = new AccessControlList($rm, $list);
        $list->expects($this->once())
            ->method('identityHasRole')
            ->with('testIdentity', 'role')
            ->willThrowException(new AccessControlException('bad input'));

        $this->expectException(AccessControlException::class);
        $this->expectExceptionMessage('bad input');
        $acl->identityHasRole('testIdentity', 'role');
    }

    public function testCheckIdentity()
    {
        $rm = $this->createMock(ResourceManagerInterface::class);
        $list = $this->createMock(ListAdapterInterface::class);
        $acl = new AccessControlList($rm, $list);

        $this->assertSame(
            false,
            $acl->checkIdentity('')
        );
        $this->assertSame(
            false,
            $acl->checkIdentity(null)
        );
    }
}
