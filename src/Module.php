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
 * Time: 14:55
 */

namespace AliChry\Laminas\AccessControl;

use Laminas\EventManager\EventInterface;
use Laminas\ModuleManager\Feature\BootstrapListenerInterface;
use Laminas\Mvc\MvcEvent;
use Laminas\ServiceManager\ServiceManager;

class Module implements BootstrapListenerInterface
{
    const CONFIG_ROOT_KEY = 'alichry';
    const CONFIG_MODULE_KEY = 'access_control';
    const CONFIG_LIST_KEY = 'list';
    const CONFIG_RESOURCE_MANAGER_KEY = 'resource_manager';
    const CONFIG_LIST_ADAPTER_KEY = 'list_adapter';

    public function getConfig()
    {
        return include __DIR__ . '/../config/module.config.php';
    }

    /**
     * @param EventInterface $e
     * @throws AccessControlException
     */
    public function onBootstrap(EventInterface $e)
    {
        if (! $e instanceof MvcEvent) {
            throw new AccessControlException(
                sprintf(
                    'Expecting event to be an instance of %s, got %s',
                    MvcEvent::class,
                    is_object($e) ? get_class($e) : gettype($e)
                )
            );
        }
        $serviceManager = $e->getApplication()->getServiceManager();
        $this->registerBuildDelegators($serviceManager);
    }

    /**
     * @param ServiceManager $serviceManager
     */
    private function registerBuildDelegators(ServiceManager $serviceManager)
    {
        $config = $serviceManager->get('Config');
        $config = $config[self::CONFIG_ROOT_KEY][self::CONFIG_MODULE_KEY] ?? [];

        $resourceManagers = $config[self::CONFIG_RESOURCE_MANAGER_KEY] ?? [];
        $listAdapters = $config[self::CONFIG_LIST_ADAPTER_KEY] ?? [];
        $lists = $config[self::CONFIG_LIST_KEY] ?? [];

        $aliases = [];

        foreach ($listAdapters as $name => $listAdapter) {
            $service = ! is_array($listAdapter)
                ? $listAdapter
                : $listAdapter['service'] ?? null;
            $key = self::CONFIG_ROOT_KEY . '.' . self::CONFIG_MODULE_KEY
                . '.' . self::CONFIG_LIST_ADAPTER_KEY . '.' . $name;

            $aliases[$key] = $service;
        }

        foreach ($resourceManagers as $name => $resourceManager) {
            $service = ! is_array($resourceManager)
                ? $resourceManager
                : ($resourceManager['service'] ?? null);
            $key = self::CONFIG_ROOT_KEY . '.' . self::CONFIG_MODULE_KEY
                . '.' . self::CONFIG_RESOURCE_MANAGER_KEY . '.' . $name;

            $aliases[$key] = $service;
        }

        foreach ($lists as $name => $list) {
            $service = ! is_array($list)
                ? $list
                : $list['service'] ?? null;
            $key = self::CONFIG_ROOT_KEY . '.' . self::CONFIG_MODULE_KEY
                . '.' . self::CONFIG_LIST_KEY . '.' . $name;

            $aliases[$key] = $service;
        }

        $serviceManager->configure(
            [
                'aliases' => $aliases
            ]
        );
    }
}