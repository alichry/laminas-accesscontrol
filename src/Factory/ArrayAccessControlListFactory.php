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
 * Date: 2020-05-28
 * Time: 13:11
 */

namespace AliChry\Laminas\AccessControl\Factory;

use AliChry\Laminas\AccessControl\AccessControlException;
use AliChry\Laminas\AccessControl\ArrayAccessControlList;
use AliChry\Laminas\AccessControl\AuthorizationService;
use Interop\Container\ContainerInterface;
use Interop\Container\Exception\ContainerException;
use Laminas\Authentication\AuthenticationService;
use Laminas\ServiceManager\Exception\ServiceNotCreatedException;
use Laminas\ServiceManager\Exception\ServiceNotFoundException;
use Laminas\ServiceManager\Factory\FactoryInterface;

class ArrayAccessControlListFactory implements FactoryInterface
{
    const OPTION_MODE = 'mode';
    const OPTION_POLICY = 'policy';
    const OPTION_CONTROLLERS_LIST = 'controllers';
    const OPTION_ROLES_LIST = 'roles';
    const OPTION_PERMISSIONS_LIST = 'permissions';
    const OPTION_IDENTITIES_LIST = 'identities';

    /**
     * Create an ArrayAccessControlList object
     *
     * @param  ContainerInterface $container
     * @param  string $requestedName
     * @param  null|array $options
     * @return object
     * @throws ServiceNotFoundException if unable to resolve the service.
     * @throws ServiceNotCreatedException if an exception is raised when
     *     creating a service.
     * @throws ContainerException if any other error occurs«
     */
    public function __invoke(ContainerInterface $container, $requestedName, array $options = null)
    {
        if (null === $options) {
            throw new ServiceNotCreatedException(
                'Expecting \'$options\' to be non-null, ' .
                'got null (woah).'
            );
        }
        $mode = $options[self::OPTION_MODE] ?? null;
        $policy = $options[self::OPTION_POLICY] ?? null;
        $controllersList = $options[self::OPTION_CONTROLLERS_LIST] ?? null;
        $identities = $options[self::OPTION_IDENTITIES_LIST] ?? [];
        $roles = $options[self::OPTION_ROLES_LIST] ?? [];
        $permissions = $options[self::OPTION_PERMISSIONS_LIST] ?? [];
        if (null === $mode) {
            throw new ServiceNotCreatedException(
                sprintf(
                    'Mode (key "%s") is not set in options.',
                    self::OPTION_MODE
                )
            );
        }
        if (null === $policy) {
            throw new ServiceNotCreatedException(
                sprintf(
                    'Policy (key "%s") is not set in options.',
                    self::OPTION_POLICY
                )
            );
        }
        if (null === $controllersList) {
            throw new ServiceNotCreatedException(
                sprintf(
                    'Controllers list (key "%s") is not set in options.',
                    self::OPTION_CONTROLLERS_LIST
                )
            );
        }
        try {
            return new ArrayAccessControlList(
                $mode,
                $policy,
                $controllersList,
                $identities,
                $roles,
                $permissions
            );
        } catch (\Throwable $e) {
            throw new ServiceNotCreatedException(
                sprintf(
                    'Unable to create ArrayAccessControlList, exception thrown '
                    . 'with message: %s',
                    $e->getMessage()
                ),
                1,
                $e
            );
        }
    }
}