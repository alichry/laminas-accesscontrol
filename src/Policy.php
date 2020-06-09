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

namespace AliChry\Laminas\AccessControl;

class Policy implements PolicyInterface
{
    const POLICY_ALLOW = 0;
    const POLICY_REJECT = 1;
    const POLICY_AUTHENTICATE = 2;
    const POLICY_AUTHORIZE = 3;

    /**
     * @var int
     */
    private $type;

    public function __construct($type)
    {
        $this->type = $type;
    }

    public function getType()
    {
        return $this->type;
    }

    /**
     * @return bool
     */
    public function deniesAll(): bool
    {
        return $this->type === self::POLICY_REJECT;
    }

    /**
     * @return bool
     */
    public function isPublic(): bool
    {
        return $this->type === self::POLICY_ALLOW;
    }

    /**
     * @return bool
     */
    public function requiresAuthentication(): bool
    {
        return $this->type >= self::POLICY_AUTHENTICATE;
    }

    /**
     * @return bool
     */
    public function requiresAuthorization(): bool
    {
        return $this->type === self::POLICY_AUTHORIZE;
    }
}