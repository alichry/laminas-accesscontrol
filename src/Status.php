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
 * Date: 2020-05-29
 * Time: 15:55
 */

namespace AliChry\Laminas\AccessControl;

class Status
{
    /**
     * The given identity is not authorized, i.e. does
     * not have specified permission or role for the
     * controller/action
     */
    const UNAUTHORIZED = -2;

    /**
     * If controller/action has reject all, or
     * policy is reject and controller undefined in list
     */
    const REJECTED = -1;

    /**
     * Publicly accessible, no need for authentication
     * or authorization
     */
    const PUBLIC = 0;

    /**
     * the given identity is authorized but not necessarily
     * authenticated, i.e. given identity does have specified
     * permission or role for the controller/action.
     * This does not imply if the user is authenticated.
     * Checking if authenticated is the purpose
     * of AuthenticationService
     */
    const OK = 1;

    /*
     * for checkStatus
     */
    const CODE_MIN = self::UNAUTHORIZED;
    const CODE_MAX = self::OK;

    /**
     * @var int
     */
    private $code;

    /**
     * @var mixed
     */
    private $identity;

    /**
     * @var array of messages
     */
    private $message;

    /**
     * Status constructor.
     * @param $code
     * @param mixed $identity
     * @param array $messages
     * @throws AccessControlException if passed code is baddie
     */
    public function __construct($code, $identity, array $messages = [])
    {
        if (!$this->checkCode($code)) {
            throw new AccessControlException(
                sprintf(
                    'Invalid status code: %s',
                    print_r($code, true)
                ),
                AccessControlException::ACS_INVALID_CODE
            );
        }
        $this->code = (int) $code;
        $this->identity = $identity;
        $this->message = $messages;
    }

    /**
     * @return int
     */
    public function getCode(): int
    {
        return $this->code;
    }

    /**
     * @return mixed
     */
    public function getIdentity()
    {
        return $this->identity;
    }

    /**
     * @return array
     */
    public function getMessages(): array
    {
        return $this->message;
    }

    /**
     * @param int $code
     * @return bool
     */
    private function checkCode($code): bool
    {
        return $code >= self::CODE_MIN && $code <= self::CODE_MAX;
    }
}