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
 * Date: 2020-06-02
 * Time: 11:44
 */

namespace AliChry\Laminas\AccessControl\Test;

use AliChry\Laminas\AccessControl\AccessControlException;
use AliChry\Laminas\AccessControl\Status;
use PHPUnit\Framework\TestCase;

class StatusTest extends TestCase
{
    public function dataProvider()
    {
        $codes = [
            null,
            STATUS::CODE_MIN - 1,
            STATUS::CODE_MAX + 1,
            Status::UNAUTHORIZED,
            Status::REJECTED,
            Status::PUBLIC,
            Status::OK
        ];

        $identities = [
            null,
            'test',
            [
                'identity' => 'test',
                'email' => null
            ]
        ];

        $someMessages = [
            [],
            [
                'first message',
                'last message'
            ]
        ];

        // enumerate all permutations of all possible codes
        // with some other sample values
        $data = [];
        foreach ($codes as $code) {
            foreach ($identities as $identity) {
                foreach ($someMessages as $messages) {
                    $datum = [
                        $code,
                        $identity,
                        $messages
                    ];
                    if (
                        null === $code
                        || (
                            Status::UNAUTHORIZED !== $code
                            && Status::REJECTED !== $code
                            && Status::PUBLIC !== $code
                            && Status::OK !== $code
                        )
                    ) {
                        $datum[] = [
                            'exception' => AccessControlException::class,
                            'code' => AccessControlException::ACS_INVALID_CODE
                        ];
                    }
                    $data[] = $datum;
                }
            }
        }
        return $data;
    }

    /**
     * @dataProvider dataProvider
     * @param $code
     * @param $identity
     * @param $messages
     * @param array|null $exception
     * @throws AccessControlException
     */
    public function testAll(
        $code,
        $identity,
        $messages,
        array $exception = null
    )
    {
        if ($exception !== null) {
            $this->expectException($exception['exception']);
            $this->expectExceptionCode($exception['code']);
        }
        $status = new Status($code, $identity, $messages);
        if ($exception !== null) {
            return;
        }
        $this->assertEquals(
            $code,
            $status->getCode()
        );
        $this->assertEquals(
            $identity,
            $status->getIdentity()
        );
        $this->assertEquals(
            $messages,
            $status->getMessages()
        );
    }
}