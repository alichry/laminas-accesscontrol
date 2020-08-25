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
 * Time: 19:13
 */

declare(strict_types=1);

namespace AliChry\Laminas\AccessControl\Test;

use AliChry\Laminas\AccessControl\AccessControlList;
use AliChry\Laminas\AccessControl\ArrayAccessControlList;
use AliChry\Laminas\AccessControl\Factory\AccessControlListFactory;
use AliChry\Laminas\AccessControl\Factory\ArrayAccessControlListFactory;
use AliChry\Laminas\AccessControl\Factory\BuildDelegator;
use AliChry\Laminas\AccessControl\Factory\IdentityAccessControlListFactory;
use AliChry\Laminas\AccessControl\IdentityAccessControlList;
use AliChry\Laminas\AccessControl\Module;
use PHPUnit\Framework\TestCase;

class ModuleTest extends TestCase
{
    /**
     * @var Module
     */
    private $module;

    /**
     * @var \string[][][][]
     */
    private $config = [
        'alichry' => [
            'access_control' => [
                'list_adapter' => [
                    'one' => '1',
                    'two' => '2',
                    'three' => [
                        'service' => '3'
                    ]
                ],
                'resource_manager' => [
                    'four' => '4',
                    'five' => '5',
                    'six' => [
                        'service' => '6'
                    ],
                ],
                'list' => [
                    'seven' => '7',
                    'eight' => '8',
                    'nine' => [
                        'service' => '9'
                    ]
                ]
            ]
        ]
    ];

    public function setUp()
    {
        $this->module = new Module();
    }

    public function testGetConfig()
    {
        $module = new Module();
        $this->assertSame(
            $module->getConfig(),
            include __DIR__ . '/../config/module.config.php'
        );
    }

    public function testConfig()
    {
        $config = $this->module->getConfig();
        $serviceManagerConfig = $config['service_manager'] ?? null;
        $this->assertTrue(
            isset($serviceManagerConfig),
            'service_manager key is not set in config'
        );
        $this->assertTrue(
            is_array($serviceManagerConfig),
            'service_manager key is not an array in config'
        );
        $factoriesConfig = $serviceManagerConfig['factories'] ?? null;
        $this->assertTrue(
            isset($factoriesConfig),
            'factories key is not set in config'
        );
        $this->assertTrue(
            is_array($factoriesConfig),
            'factories key is not an array in config'
        );
        $factories = [
            ArrayAccessControlList::class => ArrayAccessControlListFactory::class,
            IdentityAccessControlList::class =>
                IdentityAccessControlListFactory::class,
            AccessControlList::class => AccessControlListFactory::class
        ];
        foreach ($factories as $service => $expectedFactory) {
            $factory = $factoriesConfig[$service] ?? null;
            $this->assertTrue(
                isset($factory),
                sprintf(
                    '%s service is not set in factories config',
                    $service
                )
            );
            $this->assertTrue(
                class_exists($factory),
                sprintf(
                    'factory %s is not found',
                    $factory
                )
            );
            $this->assertSame(
                $expectedFactory,
                $factory
            );
        }
        $keysConfig = $config['alichry']['build_delegator']['keys'] ?? [];
        $expectedKeys = [
            'alichry.access_control.resource_manager',
            'alichry.access_control.list_adapter',
            'alichry.access_control.list',
        ];
        $this->assertSame(
            $expectedKeys,
            $keysConfig
        );
    }
}