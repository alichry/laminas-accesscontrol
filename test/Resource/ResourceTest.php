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

namespace AliChry\Laminas\AccessControl\Test\Resource;

use AliChry\Laminas\AccessControl\Permission\PermissionInterface;
use AliChry\Laminas\AccessControl\Policy\Policy;
use AliChry\Laminas\AccessControl\Policy\PolicyInterface;
use AliChry\Laminas\AccessControl\Resource\Resource;
use AliChry\Laminas\AccessControl\Resource\ResourceIdentifierInterface;
use PHPUnit\Framework\TestCase;
use stdClass;
use TypeError;

class ResourceTest extends TestCase
{
    public function testIdentifier()
    {
        $mockIdentifier = $this->createMock(ResourceIdentifierInterface::class);
        $mockPolicy = $this->createMock(PolicyInterface::class);
        $resource = new Resource($mockIdentifier, $mockPolicy);

        $this->assertSame(
            $mockIdentifier,
            $resource->getIdentifier()
        );

        $mockSomeOtherIdentifier = $this->createMock(
            ResourceIdentifierInterface::class
        );

        $resource->setIdentifier($mockSomeOtherIdentifier);
        $this->assertSame(
            $mockSomeOtherIdentifier,
            $resource->getIdentifier()
        );

        $badIdentifier = new stdClass();
        $this->expectException(TypeError::class);
        $resource->setIdentifier($badIdentifier);
    }

    public function testPolicy()
    {
        $mockIdentifier = $this->createMock(ResourceIdentifierInterface::class);
        $mockPolicy = $this->createMock(PolicyInterface::class);
        $resource = new Resource($mockIdentifier, $mockPolicy);

        $this->assertSame(
            $mockPolicy,
            $resource->getPolicy()
        );

        $mockSomeOtherPolicy = $this->createMock(PolicyInterface::class);
        $resource->setPolicy($mockSomeOtherPolicy);
        $this->assertSame(
            $mockSomeOtherPolicy,
            $resource->getPolicy()
        );

        $badPolicy = new stdClass();
        $this->expectException(TypeError::class);
        $resource->setPolicy($badPolicy);
    }

    public function testPermission()
    {
        $mockIdentifier = $this->createMock(ResourceIdentifierInterface::class);
        $mockPolicy = $this->createMock(PolicyInterface::class);
        $mockPermission = $this->createMock(PermissionInterface::class);
        $resource = new Resource($mockIdentifier, $mockPolicy, $mockPermission);

        $this->assertSame(
            $mockPermission,
            $resource->getPermission()
        );

        $mockSomeOtherPermission = $this->createMock(PermissionInterface::class);
        $resource->setPermission($mockSomeOtherPermission);
        $this->assertSame(
            $mockSomeOtherPermission,
            $resource->getPermission()
        );
    }
}