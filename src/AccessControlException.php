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
 * Date: 2019-07-29
 * Time: 09:21
 */

namespace AliChry\Laminas\AccessControl;

class AccessControlException extends \Exception
{
    const ANY = 0;
    const ACL_INVALID_MODE = 1;
    const ACL_INVALID_POLICY = 2;
    const ACL_IDENTITY_NOT_DEFINED = 3;
    const ACL_ROLE_NOT_DEFINED = 4;
    const ACL_PERMISSION_NOT_DEFINED = 5;
    const ACL_INVALID_ACCESS_FORMAT = 6;
    const ACL_BAD_IDENTITY = 7;
    const ACL_BAD_ROLE = 8;
    const ACL_CONTROLLER_NOT_DEFINED = 9;
    const ACL_METHOD_NOT_DEFINED = 10;
    const ACL_METHOD_NULL = 11;
    const ACL_DUPLICATE_METHOD = 12;
    const ACS_INVALID_CODE = 13;
}
