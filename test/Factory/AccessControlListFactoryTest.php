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

namespace AliChry\Laminas\AccessControl\Test\Factory;

use AliChry\Laminas\AccessControl\Factory\AccessControlListFactory
    as Factory;
use AliChry\Laminas\AccessControl\AccessControlList;
use AliChry\Laminas\AccessControl\Lists\ListAdapterInterface;
use AliChry\Laminas\AccessControl\Resource\ResourceManagerInterface;
use Interop\Container\ContainerInterface;
use Interop\Container\Exception\ContainerException;
use Laminas\ServiceManager\Exception\ServiceNotCreatedException;
use Laminas\ServiceManager\ServiceManager;
use PHPUnit\Framework\TestCase;

class AccessControlListFactoryTest extends TestCase
{
    private $mockContainer;
    private $mockServiceManager;
    private $requestedName;

    public function __construct($name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        $this->requestedName = null;
        $this->mockContainer = $this->createMock(ContainerInterface::class);
        $this->mockServiceManager = $this->createMock(ServiceManager::class);
    }

    /**
     * @throws ContainerException
     */
    public function testNullOptions()
    {
        $this->expectException(ServiceNotCreatedException::class);
        $this->invokeFactory();
    }

    /**
     * @throws ContainerException
     */
    public function testNoResourceManager()
    {
        $this->expectException(ServiceNotCreatedException::class);
        $this->invokeFactory(
            []
        );
    }

    /**
     * @dataProvider notAStringProvider
     * @param $rm
     * @throws ContainerException
     */
    public function testBadResourceManager($rm)
    {
        $this->expectException(ServiceNotCreatedException::class);
        $this->invokeFactory(
            [
                Factory::OPTION_RESOURCE_MANAGER => $rm,
                Factory::OPTION_LIST_ADAPTER => '' // dummy
            ]
        );
    }

    /**
     * @throws ContainerException
     */
    public function testNoResourceManagerWithListAdapter()
    {
        $this->expectException(ServiceNotCreatedException::class);
        $this->invokeFactory(
            [
                Factory::OPTION_LIST_ADAPTER => $this->createMock(
                    ListAdapterInterface::class
                )
            ]
        );
    }

    /**
     * @throws ContainerException
     */
    public function testNoListAdapter()
    {
        $this->expectException(ServiceNotCreatedException::class);
        $this->invokeFactory(
            []
        );
    }

    /**
     * @dataProvider notAStringProvider
     * @param $la
     * @throws ContainerException
     */
    public function testBadListAdapter($la)
    {
        $this->expectException(ServiceNotCreatedException::class);
        $this->invokeFactory(
            [
                Factory::OPTION_LIST_ADAPTER => $la,
                Factory::OPTION_RESOURCE_MANAGER => '' // dummy
            ]
        );
    }

    /**
     * @throws ContainerException
     */
    public function testNoListAdapterWithResourceManager()
    {
        $this->expectException(ServiceNotCreatedException::class);
        $this->invokeFactory(
            [
                Factory::OPTION_RESOURCE_MANAGER => $this->createMock(
                    ResourceManagerInterface::class
                )
            ]
        );
    }

    /**
     * @throws ContainerException
     */
    public function testInvoke()
    {
        $rmPrefix = 'alichry.access_control.resource_manager.';
        $laPrefix = 'alichry.access_control.list_adapter.';
        $rm = 'rm';
        $la = 'la';
        $mockRM = $this->createMock(ResourceManagerInterface::class);
        $mockLA = $this->createMock(ListAdapterInterface::class);
        $options = [
            Factory::OPTION_RESOURCE_MANAGER => $rm,
            Factory::OPTION_LIST_ADAPTER => $la
        ];

        $this->mockContainer->expects($this->exactly(3))
            ->method('get')
            ->will(
                $this->returnValueMap(
                    [
                        [ServiceManager::class, $this->mockServiceManager],
                        [$rmPrefix . $rm, $mockRM],
                        [$laPrefix . $la, $mockLA]
                    ]
                )
            );

        $acl = new AccessControlList($mockRM, $mockLA);
        $built = $this->invokeFactory($options);
        $this->assertEquals(
            $acl,
            $built
        );
        $this->assertSame(
            $acl->getResourceManager(),
            $built->getResourceManager()
        );
        $this->assertSame(
            $acl->getListAdapter(),
            $built->getListAdapter()
        );
    }

    /**
     * @return array
     */
    public function notAStringProvider()
    {
        return [
            [1],
            [1.0],
            [[]],
            [new \stdClass()]
        ];
    }

    /**
     * @param null $options
     * @return IdentityAccessControlList|object
     * @throws ContainerException
     */
    private function invokeFactory($options = null)
    {
        $factory = new Factory();
        return $factory($this->mockContainer, $this->requestedName, $options);
    }

}