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

namespace AliChry\Laminas\AccessControl\Policy;

use AliChry\Laminas\AccessControl\AccessControlException;

class Policy implements PolicyInterface
{
    const POLICY_REJECT = 0;
    const POLICY_AUTHORIZE = 1;
    const POLICY_AUTHENTICATE = 2;
    const POLICY_ALLOW = 3;

    /**
     * @var int
     */
    private $type;

    /**
     * Policy constructor.
     * @param $type
     * @throws AccessControlException
     */
    public function __construct($type)
    {
        $this->setType($type);
    }

    /**
     * @return int
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * @param int $type
     * @throws AccessControlException
     */
    public function setType(int $type)
    {
        if (! self::checkType($type)) {
            throw new AccessControlException('Invalid type: ' . $type);
        }
        $this->type = $type;
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
        return $this->type === self::POLICY_AUTHENTICATE;
    }

    /**
     * @return bool
     */
    public function requiresAuthorization(): bool
    {
        return $this->type === self::POLICY_AUTHORIZE;
    }

    /**
     * @param $type
     * @return bool
     */
    public static function checkType(int $type): bool
    {
        return $type === self::POLICY_REJECT
            || $type === self::POLICY_AUTHORIZE
            || $type === self::POLICY_AUTHENTICATE
            || $type === self::POLICY_ALLOW;
    }
}