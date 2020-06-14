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

use AliChry\Laminas\AccessControl\AbstractAccessControlList;
use AliChry\Laminas\AccessControl\AccessControlException;
use AliChry\Laminas\AccessControl\Permission\PermissionInterface;
use AliChry\Laminas\AccessControl\Policy\PolicyInterface;
use AliChry\Laminas\AccessControl\Resource\ResourceIdentifierInterface;
use AliChry\Laminas\AccessControl\Resource\ResourceInterface;
use AliChry\Laminas\AccessControl\Resource\ResourceManagerInterface;
use AliChry\Laminas\AccessControl\Status;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use stdClass;
use function array_merge;

class AbstractAccessControlListTest extends TestCase
{
    public function testResourceManager()
    {
        $mockResourceManager = $this->createMock(
            ResourceManagerInterface::class
        );
        $mockACL = $this->mockAbstractAccessControlList($mockResourceManager);

        $this->assertSame(
            $mockResourceManager,
            $mockACL->getResourceManager()
        );
    }

    /**
     * @dataProvider identityProvider
     * @param $identity
     */
    public function testGetAccessStatusWithInconclusivePolicy($identity)
    {
        $mockResourceManager = $this->createMock(
            ResourceManagerInterface::class
        );
        $mockResource = $this->createMock(
            ResourceInterface::class
        );
        $mockResourceIdentifier = $this->createMock(
            ResourceIdentifierInterface::class
        );
        $mockPolicyInconclusive = $this->createMock(
            PolicyInterface::class
        );
        $mockResource->expects($this->once())
            ->method('getPolicy')
            ->willReturn($mockPolicyInconclusive);

        $mockResourceManager->expects($this->once())
            ->method('getResource')
            ->with($this->identicalTo($mockResourceIdentifier))
            ->willReturn($mockResource);
        $acl = $this->mockAbstractAccessControlList($mockResourceManager);
        $this->expectException(
            AccessControlException::class
        );
        $acl->getAccessStatus($identity, $mockResourceIdentifier);
    }

    /**
     * @dataProvider identityProvider
     * @param $identity
     */
    public function testGetAccessStatusPublic($identity)
    {
        $mockResourceManager = $this->createMock(
            ResourceManagerInterface::class
        );
        $mockResource = $this->createMock(
            ResourceInterface::class
        );
        $mockResourceIdentifier = $this->createMock(
            ResourceIdentifierInterface::class
        );
        $mockPolicyPublic = $this->createMock(
            PolicyInterface::class
        );

        $mockPolicyPublic->expects($this->once())
            ->method('isPublic')
            ->willReturn(true);

        $mockResource->expects($this->once())
            ->method('getPolicy')
            ->willReturn($mockPolicyPublic);

        $mockResourceManager->expects($this->once())
            ->method('getResource')
            ->with($this->identicalTo($mockResourceIdentifier))
            ->willReturn($mockResource);

        $acl = $this->mockAbstractAccessControlList($mockResourceManager);
        $status = $acl->getAccessStatus($identity, $mockResourceIdentifier);
        $this->assertSame(
            Status::PUBLIC,
            $status->getCode()
        );
        $this->assertSame(
            $identity,
            $status->getIdentity()
        );
    }

    /**
     * @dataProvider identityProvider
     * @param $identity
     */
    public function testGetAccessStatusDeniesAll($identity)
    {
        $mockResourceManager = $this->createMock(
            ResourceManagerInterface::class
        );
        $mockResource = $this->createMock(
            ResourceInterface::class
        );
        $mockResourceIdentifier = $this->createMock(
            ResourceIdentifierInterface::class
        );
        $mockPolicyDeniesAll = $this->createMock(
            PolicyInterface::class
        );

        $mockPolicyDeniesAll->expects($this->once())
            ->method('deniesAll')
            ->willReturn(true);

        $mockResource->expects($this->once())
            ->method('getPolicy')
            ->willReturn($mockPolicyDeniesAll);

        $mockResourceManager->expects($this->once())
            ->method('getResource')
            ->with($this->identicalTo($mockResourceIdentifier))
            ->willReturn($mockResource);

        $acl = $this->mockAbstractAccessControlList($mockResourceManager);
        $status = $acl->getAccessStatus($identity, $mockResourceIdentifier);
        $this->assertSame(
            Status::REJECTED,
            $status->getCode()
        );
        $this->assertSame(
            $identity,
            $status->getIdentity()
        );
    }

    /**
     * @dataProvider goodIdentityProvider
     * @param $identity
     */
    public function testGetAccessStatusRequiresAuthentication($identity)
    {
        $mockResourceManager = $this->createMock(
            ResourceManagerInterface::class
        );
        $mockResource = $this->createMock(
            ResourceInterface::class
        );
        $mockResourceIdentifier = $this->createMock(
            ResourceIdentifierInterface::class
        );
        $mockPolicyRequiresAuthentication = $this->createMock(
            PolicyInterface::class
        );

        $mockPolicyRequiresAuthentication->expects($this->once())
            ->method('requiresAuthentication')
            ->willReturn(true);

        $mockResource->expects($this->once())
            ->method('getPolicy')
            ->willReturn($mockPolicyRequiresAuthentication);

        $mockResourceManager->expects($this->once())
            ->method('getResource')
            ->with($this->identicalTo($mockResourceIdentifier))
            ->willReturn($mockResource);

        $acl = $this->mockAbstractAccessControlList($mockResourceManager);
        if (null !== $identity) {
            $acl->expects($this->once())
                ->method('checkIdentity')
                ->with($this->identicalTo($identity))
                ->willReturn(true);
        }

        $status = $acl->getAccessStatus($identity, $mockResourceIdentifier);
        $this->assertSame(
            null !== $identity
                ? Status::OK
                : Status::UNAUTHENTICATED,
            $status->getCode()
        );
        $this->assertSame(
            $identity,
            $status->getIdentity()
        );
    }

    /**
     * @dataProvider badIdentityProvider
     * @param $badIdentity
     */
    public function testGetAccessStatusRequiresAuthenticationWithBadIdentity(
        $badIdentity
    )
    {
        $mockResourceManager = $this->createMock(
            ResourceManagerInterface::class
        );
        $mockResource = $this->createMock(
            ResourceInterface::class
        );
        $mockResourceIdentifier = $this->createMock(
            ResourceIdentifierInterface::class
        );
        $mockPolicyRequiresAuthentication = $this->createMock(
            PolicyInterface::class
        );

        $mockPolicyRequiresAuthentication->expects($this->once())
            ->method('requiresAuthentication')
            ->willReturn(true);

        $mockResource->expects($this->once())
            ->method('getPolicy')
            ->willReturn($mockPolicyRequiresAuthentication);

        $mockResourceManager->expects($this->once())
            ->method('getResource')
            ->with($this->identicalTo($mockResourceIdentifier))
            ->willReturn($mockResource);

        $acl = $this->mockAbstractAccessControlList($mockResourceManager);
        $acl->expects($this->once())
            ->method('checkIdentity')
            ->with($this->identicalTo($badIdentity))
            ->willReturn(false);

        $this->expectException(AccessControlException::class);
        $acl->getAccessStatus($badIdentity, $mockResourceIdentifier);
    }

    /**
     * @dataProvider goodIdentityProvider
     * @param $identity
     */
    public function testGetAccessStatusRequiresAuthorizationTrue($identity)
    {
        $mockResourceManager = $this->createMock(
            ResourceManagerInterface::class
        );
        $mockResource = $this->createMock(
            ResourceInterface::class
        );
        $mockResourceIdentifier = $this->createMock(
            ResourceIdentifierInterface::class
        );
        $mockPolicyRequiresAuthorization = $this->createMock(
            PolicyInterface::class
        );
        $mockPermission = $this->createMock(
            PermissionInterface::class
        );

        $mockPolicyRequiresAuthorization->expects($this->once())
            ->method('requiresAuthorization')
            ->willReturn(true);

        $mockResource->expects($this->once())
            ->method('getPolicy')
            ->willReturn($mockPolicyRequiresAuthorization);
        $mockResource->expects($this->once())
            ->method('getPermission')
            ->willReturn($mockPermission);

        $mockResourceManager->expects($this->once())
            ->method('getResource')
            ->with($this->identicalTo($mockResourceIdentifier))
            ->willReturn($mockResource);

        $acl = $this->mockAbstractAccessControlList($mockResourceManager);

        if (null !== $identity) {
            $acl->expects($this->once())
                ->method('identityHasPermission')
                ->with(
                    $this->identicalTo($identity),
                    $this->identicalTo($mockPermission)
                )->willReturn(true);
        }

        $status = $acl->getAccessStatus($identity, $mockResourceIdentifier);
        $this->assertSame(
            null !== $identity
                ? Status::OK
                : Status::UNAUTHORIZED,
            $status->getCode()
        );
        $this->assertSame(
            $identity,
            $status->getIdentity()
        );
    }

    /**
     * @dataProvider goodIdentityProvider
     * @param $identity
     */
    public function testGetAccessStatusRequiresAuthorizationFalse($identity)
    {
        $mockResourceManager = $this->createMock(
            ResourceManagerInterface::class
        );
        $mockResource = $this->createMock(
            ResourceInterface::class
        );
        $mockResourceIdentifier = $this->createMock(
            ResourceIdentifierInterface::class
        );
        $mockPolicyRequiresAuthorization = $this->createMock(
            PolicyInterface::class
        );
        $mockPermission = $this->createMock(
            PermissionInterface::class
        );

        $mockPolicyRequiresAuthorization->expects($this->once())
            ->method('requiresAuthorization')
            ->willReturn(true);

        $mockResource->expects($this->once())
            ->method('getPolicy')
            ->willReturn($mockPolicyRequiresAuthorization);
        $mockResource->expects($this->once())
            ->method('getPermission')
            ->willReturn($mockPermission);

        $mockResourceManager->expects($this->once())
            ->method('getResource')
            ->with($this->identicalTo($mockResourceIdentifier))
            ->willReturn($mockResource);

        $acl = $this->mockAbstractAccessControlList($mockResourceManager);
        if (null !== $identity) {
            $acl->expects($this->once())
                ->method('identityHasPermission')
                ->with($identity, $mockPermission)
                ->willReturn(false);
        }
        $status = $acl->getAccessStatus($identity, $mockResourceIdentifier);
        $this->assertSame(
            Status::UNAUTHORIZED,
            $status->getCode()
        );
        $this->assertSame(
            $identity,
            $status->getIdentity()
        );
    }

    /**
     * @dataProvider badIdentityProvider
     * @param $badIdentity
     */
    public function testAccessStatusRequiresAuthorizationWithBadIdentity(
        $badIdentity
    )
    {
        $mockResourceManager = $this->createMock(
            ResourceManagerInterface::class
        );
        $mockResource = $this->createMock(
            ResourceInterface::class
        );
        $mockResourceIdentifier = $this->createMock(
            ResourceIdentifierInterface::class
        );
        $mockPolicyAuthorization = $this->createMock(
            PolicyInterface::class
        );
        $mockPermission = $this->createMock(PermissionInterface::class);

        $mockPolicyAuthorization->expects($this->once())
            ->method('requiresAuthorization')
            ->willReturn(true);

        $mockResource->expects($this->once())
            ->method('getPolicy')
            ->willReturn($mockPolicyAuthorization);
        $mockResource->expects($this->once())
            ->method('getPermission')
            ->willReturn($mockPermission);

        $mockResourceManager->expects($this->once())
            ->method('getResource')
            ->with($this->identicalTo($mockResourceIdentifier))
            ->willReturn($mockResource);

        $acl = $this->mockAbstractAccessControlList($mockResourceManager);
        $acl->expects($this->once())
            ->method('identityHasPermission')
            ->with($this->identicalTo($badIdentity))
            ->willThrowException(new AccessControlException('bad identity babe'));

        $this->expectException(AccessControlException::class);
        $this->expectExceptionMessage('bad identity babe');
        $acl->getAccessStatus($badIdentity, $mockResourceIdentifier);
    }

    /**
     * @return array
     */
    public function goodIdentityProvider()
    {
        return [
            [null],
            ['testIdentity']
        ];
    }

    /**
     * @return stdClass[][]
     */
    public function badIdentityProvider()
    {
        return [
            [new stdClass()]
        ];
    }

    /**
     * @return array
     */
    public function identityProvider()
    {
        return array_merge(
            $this->badIdentityProvider(),
            $this->goodIdentityProvider()
        );
    }

    /**
     * @param ResourceManagerInterface|null $resourceManager
     * @return MockObject<AbstractAccessControlList>
     */
    private function mockAbstractAccessControlList($resourceManager = null)
    {
        $mockACL = $this->getMockBuilder(AbstractAccessControlList::class);
        if (null !== $resourceManager) {
            $mockACL->setConstructorArgs([$resourceManager]);
        }
        return $mockACL->getMockForAbstractClass();
    }
}