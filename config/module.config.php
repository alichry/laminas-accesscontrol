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
 * Time: 14:54
 */

use AliChry\Laminas\AccessControl\AccessControlList;
use AliChry\Laminas\AccessControl\ArrayAccessControlList;
use AliChry\Laminas\AccessControl\Factory\AccessControlListFactory;
use AliChry\Laminas\AccessControl\Factory\ArrayAccessControlListFactory;
use AliChry\Laminas\AccessControl\Factory\IdentityAccessControlListFactory;
use AliChry\Laminas\AccessControl\IdentityAccessControlList;

return [
    'service_manager' => [
        'factories' => [
            ArrayAccessControlList::class => ArrayAccessControlListFactory::class,
            IdentityAccessControlList::class =>
                IdentityAccessControlListFactory::class,
            AccessControlList::class => AccessControlListFactory::class
        ]
    ],
    'alichry' => [
        'access_control' => [
            'resource_manager' => [],
            'list_adapter' => [],
            'list' => []
        ],
        'build_delegator' => [
            'keys' => [
                'alichry.access_control.resource_manager',
                'alichry.access_control.list_adapter',
                'alichry.access_control.list'
            ]
        ]
    ]
];