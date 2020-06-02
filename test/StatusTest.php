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

namespace AliChry\Laminas\AccessControlTest;

use AliChry\Laminas\AccessControl\Status;
use PHPUnit\Framework\TestCase;

class StatusTest extends TestCase
{
    private $codes = [
        Status::UNAUTHORIZED,
        Status::REJECTED,
        Status::PUBLIC,
        Status::OK
    ];

    private $identities = [
        null,
        'test',
        [
            'identity' => 'test',
            'email' => null
        ]
    ];

    private $messages = [
        [],
        [
            'first message',
            'last message'
        ]
    ];

    public function testCode()
    {
        foreach ($this->codes as $code) {
            $status = new Status($code, null);
            $this->assertEquals(
                $code,
                $status->getCode()
            );
        }
    }

    public function testIdentity()
    {
        foreach ($this->codes as $code) {
            foreach ($this->identities as $identity) {
                $status = new Status($code, $identity);
                $this->assertEquals(
                    $code,
                    $status->getCode()
                );
                $this->assertEquals(
                    $identity,
                    $status->getIdentity()
                );
            }
        }
    }

    public function testMessages()
    {
        foreach ($this->codes as $code) {
            foreach ($this->identities as $identity) {
                foreach ($this->messages as $messages) {
                    $status = new Status($code, $identity, $messages);
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
        }
    }
}