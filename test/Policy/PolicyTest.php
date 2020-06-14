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

namespace AliChry\Laminas\AccessControl\Test\Policy;

use AliChry\Laminas\AccessControl\AccessControlException;
use AliChry\Laminas\AccessControl\Policy\Policy;
use PHPUnit\Framework\TestCase;
use stdClass;
use TypeError;
use function array_merge;

class PolicyTest extends TestCase
{
    public function testGetType()
    {
        $policy = new Policy(1);
        $this->assertSame(
            1,
            $policy->getType()
        );
    }

    /**
     * @dataProvider validTypesProvider
     * @param $type
     * @throws AccessControlException
     */
    public function testType($type)
    {
        $policy = new Policy($type);
        $this->assertSame(
            $type,
            $policy->getType()
        );
    }

    /**
     * @dataProvider invalidTypesProvider
     * @param $type
     */
    public function testInvalidType($type)
    {
        $this->expectException(AccessControlException::class);
        $policy = new Policy($type);
    }

    /**
     * @throws AccessControlException
     */
    public function testBadType()
    {
        $this->expectException(TypeError::class);
        $policy = new Policy(new stdClass());
    }

    /**
     * @throws AccessControlException
     */
    public function testBadTypeOnSetType()
    {
        $this->expectException(TypeError::class);
        $policy = new Policy(Policy::POLICY_REJECT);
        $policy->setType(new stdClass());
    }

    public function testDeniiesAll()
    {
        $policy = new Policy(Policy::POLICY_REJECT);
        $this->assertTrue($policy->deniesAll());
    }

    public function testIsPublic()
    {
        $policy = new Policy(Policy::POLICY_ALLOW);
        $this->assertTrue($policy->isPublic());
    }

    public function testRequiresAuthentication()
    {
        $policy = new Policy(Policy::POLICY_AUTHENTICATE);
        $this->assertTrue($policy->requiresAuthentication());
    }

    public function testRequiresAuhtorization()
    {
        $policy = new Policy(Policy::POLICY_AUTHORIZE);
        $this->assertTrue($policy->requiresAuthorization());
    }

    public function validTypesProvider()
    {
        return [
            [Policy::POLICY_REJECT],
            [Policy::POLICY_AUTHORIZE],
            [Policy::POLICY_AUTHENTICATE],
            [Policy::POLICY_ALLOW]
        ];
    }

    /**
     * @return array
     */
    public function invalidTypesProvider()
    {
        $min = Policy::POLICY_REJECT;
        $max = Policy::POLICY_ALLOW;
        return array_merge(
            array_map(function ($type) {
                return [$type];
            }, range($min - 10,  miin - 1)),
            array_map(function ($type) {
                return [$type];
            }, range($max + 1, $max + 10))
        );
    }
}