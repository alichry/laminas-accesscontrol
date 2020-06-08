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
 * Date: 2020-06-08
 * Time: 16:04
 */

namespace AliChry\Laminas\AccessControl\Test\Factory;

use AliChry\Laminas\AccessControl\AccessControlException;
use AliChry\Laminas\AccessControl\AccessControlList;
use Interop\Container\ContainerInterface;
use Interop\Container\Exception\ContainerException;
use Laminas\ServiceManager\Exception\ServiceNotCreatedException;
use PHPUnit\Framework\TestCase;
use AliChry\Laminas\AccessControl\Factory\AccessControlListFactory as Factory;

class AccessControlListFactoryTest extends TestCase
{
    private $mockContainer;
    private $requestedName;

    public function __construct($name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        $this->mockContainer = $this->createMock(ContainerInterface::class);
        $this->requestedName = Factory::class;
    }

    public function binaryEnumerator()
    {
        // each option key is either in or out
        $fields = [
            Factory::OPTION_MODE,
            Factory::OPTION_POLICY,
            Factory::OPTION_CONTROLLERS_LIST,
            Factory::OPTION_IDENTITIES_LIST,
            Factory::OPTION_ROLES_LIST,
            Factory::OPTION_PERMISSIONS_LIST
        ];
        // some valid values if a field is in
        $someValidValues = [
            Factory::OPTION_MODE => AccessControlList::MODE_STRICT,
            Factory::OPTION_POLICY => AccessControlList::POLICY_REJECT,
            Factory::OPTION_CONTROLLERS_LIST => [],
            Factory::OPTION_IDENTITIES_LIST => [],
            Factory::OPTION_ROLES_LIST => [],
            Factory::OPTION_PERMISSIONS_LIST => []
        ];
        $data = [];
        $count = count($fields);
        for ($i = 0; $i < pow(2, $count); $i++) {
            $somethingNotIn = false;
            $options = [];
            foreach ($fields as $f => $field) {
                $in = (bool) ($i & pow(2, $f));
                if (! $in) {
                    $options[$field] = null;
                } else {
                    $options[$field] = $someValidValues[$field];
                }
                switch ($field) {
                    case Factory::OPTION_MODE:
                    case Factory::OPTION_POLICY:
                    case Factory::OPTION_CONTROLLERS_LIST:
                        if (! $in) {
                            $somethingNotIn = true;
                        }
                        break;
                }
            }
            $data[] = [
                $options,
                $somethingNotIn
            ];
        }
        return $data;
    }

    /**
     * @param null $options
     * @throws ContainerException
     */
    private function invokeFactory($options = null)
    {
        $factory = new Factory();
        return $factory($this->mockContainer, $this->requestedName, $options);
    }

    /**
     * @throws ContainerException
     */
    public function testNoOptions()
    {
        $this->expectException(ServiceNotCreatedException::class);
        $this->invokeFactory();
    }

    /**
     * @dataProvider binaryEnumerator
     * @param $options
     * @param $notIn
     * @throws ContainerException
     * @throws AccessControlException
     */
    public function testNotInPermutations($options, $notIn)
    {
        if ($notIn) {
            $this->expectException(ServiceNotCreatedException::class);
        }
        $result = $this->invokeFactory($options);
        if (! $notIn) { // in
            $this->assertEquals(
                $result,
                new AccessControlList(
                    ... array_values($options)
                )
            );
        }
    }
}