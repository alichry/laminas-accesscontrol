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
use AliChry\Laminas\AccessControl\IdentityAccessControlList;
use AliChry\Laminas\AccessControl\Identity\IdentityInterface;
use AliChry\Laminas\AccessControl\Permission\PermissionInterface;
use AliChry\Laminas\AccessControl\Resource\ResourceManagerInterface;
use AliChry\Laminas\AccessControl\Role\RoleInterface;
use PHPUnit\Framework\TestCase;

class IdentityAccessControlListTest extends TestCase
{
    /**
     * @return array
     */
    public function badIdentityProvider()
    {
        return [
            [new \stdClass()],
            [2],
            [[]]
        ];
    }

    /**
     * @return array
     */
    public function goodIdentityProvider()
    {
        return [
            [null],
            [$this->createMock(IdentityInterface::class)]
        ];
    }

    /**
     * @return array
     */
    public function identityProvider()
    {
        return \array_merge(
            $this->badIdentityProvider(),
            $this->goodIdentityProvider()
        );
    }

    /**
     * @dataProvider badIdentityProvider
     * @param $identity
     * @throws AccessControlException
     */
    public function testIdentityHasPermissionWithBadIdentity($identity)
    {
        $mockResourceManager = $this->createMock(
            ResourceManagerInterface::class
        );

        $mockPermission = $this->createMock(PermissionInterface::class);

        $acl = new IdentityAccessControlList($mockResourceManager);
        $this->expectException(AccessControlException::class);
        $acl->identityHasPermission($identity,$mockPermission);
    }

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasPermission()
    {
        $mockResourceManager = $this->createMock(
            ResourceManagerInterface::class
        );

        $mockIdentityTrue = $this->createMock(IdentityInterface::class);
        $mockPermissionTrue = $this->createMock(PermissionInterface::class);
        $mockIdentityTrue->expects($this->once())
            ->method('hasPermission')
            ->with($mockPermissionTrue)
            ->willReturn(true);

        $mockIdentityFalse = $this->createMock(IdentityInterface::class);
        $mockPermissionFalse = $this->createMock(PermissionInterface::class);
        $mockIdentityFalse->expects($this->once())
            ->method('hasPermission')
            ->with($mockPermissionFalse)
            ->willReturn(false);

        $acl = new IdentityAccessControlList($mockResourceManager);
        $this->assertSame(
            false,
            $acl->identityHasPermission(null, $mockPermissionTrue)
        );
        $this->assertSame(
            true,
            $acl->identityHasPermission($mockIdentityTrue, $mockPermissionTrue)
        );
        $this->assertSame(
            false,
            $acl->identityHasPermission($mockIdentityFalse, $mockPermissionFalse)
        );
    }

    /**
     * @dataProvider badIdentityProvider
     * @param $identity
     * @throws AccessControlException
     */
    public function testIdentityHasRoleWithBadIdentity($identity)
    {
        $mockResourceManager = $this->createMock(
            ResourceManagerInterface::class
        );

        $mockPermission = $this->createMock(PermissionInterface::class);

        $acl = new IdentityAccessControlList($mockResourceManager);
        $this->expectException(AccessControlException::class);
        $acl->identityHasRole($identity,$mockPermission);
    }

    /**
     * @throws AccessControlException
     */
    public function testIdentityHasRole()
    {
        $mockResourceManager = $this->createMock(
            ResourceManagerInterface::class
        );

        $mockIdentityTrue = $this->createMock(IdentityInterface::class);
        $mockRoleTrue = $this->createMock(RoleInterface::class);
        $mockIdentityTrue->expects($this->once())
            ->method('hasRole')
            ->with($mockRoleTrue)
            ->willReturn(true);

        $mockIdentityFalse = $this->createMock(IdentityInterface::class);
        $mockRoleFalse = $this->createMock(RoleInterface::class);
        $mockIdentityFalse->expects($this->once())
            ->method('hasRole')
            ->with($mockRoleFalse)
            ->willReturn(false);

        $acl = new IdentityAccessControlList($mockResourceManager);
        $this->assertSame(
            false,
            $acl->identityHasRole(null, $mockRoleTrue)
        );
        $this->assertSame(
            true,
            $acl->identityHasRole($mockIdentityTrue, $mockRoleTrue)
        );
        $this->assertSame(
            false,
            $acl->identityHasRole($mockIdentityFalse, $mockRoleFalse)
        );
    }
}