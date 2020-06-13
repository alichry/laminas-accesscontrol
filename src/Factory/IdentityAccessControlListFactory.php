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

use AliChry\Laminas\AccessControl\IdentityAccessControlList;
use Interop\Container\ContainerInterface;
use Interop\Container\Exception\ContainerException;
use Laminas\ServiceManager\Exception\ServiceNotCreatedException;
use Laminas\ServiceManager\Exception\ServiceNotFoundException;
use Laminas\ServiceManager\Factory\FactoryInterface;
use Laminas\ServiceManager\ServiceManager;

class IdentityAccessControlListFactory implements FactoryInterface
{
    const OPTION_RESOURCE_MANAGER = 'resource_manager';

    /**
     * Create an IdentityAccessControlList object
     *
     * @param  ContainerInterface $container
     * @param  string             $requestedName
     * @param  null|array         $options
     * @return object
     * @throws ServiceNotFoundException if unable to resolve the service.
     * @throws ServiceNotCreatedException if an exception is raised when
     *     creating a service.
     * @throws ContainerException if any other error occurs
     */
    public function __invoke(ContainerInterface $container, $requestedName, array $options = null)
    {
        if ($options === null) {
            throw new ServiceNotCreatedException(
                'Expecting build options to be set, ' .
                'got unset.'
            );
        }
        $resourceManagerOption = $options[self::OPTION_RESOURCE_MANAGER] ?? null;
        if (null === $resourceManagerOption) {
            throw new ServiceNotCreatedException(
                sprintf(
                    'Expecting key "%s" to be set in options, '
                    . 'got unset.',
                    self::OPTION_RESOURCE_MANAGER
                )
            );
        }
        if (! is_array($resourceManagerOption)) {
            $resourceManager = $container->get($resourceManagerOption);
        } else {
            $serviceManager = $container->get(ServiceManager::class);
            $resourceManager = $serviceManager->build(
                $resourceManagerOption['service'] ?? null,
                $resourceManagerOption['options'] ?? null
            );
        }

        return new IdentityAccessControlList(
            $resourceManager
        );
    }
}