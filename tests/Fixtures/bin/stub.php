<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/*
 * Stands in for a shipped bin/ script.
 *
 * Echoes its argv to stdout, writes a line to stderr, and exits with
 * whatever code it was asked for. Enough to assert that arguments are
 * forwarded in the right order, that the two streams stay apart, and that
 * the exit code survives.
 *
 * Required rather than duplicated by each stub, because the wrapper commands
 * ask for the script by name — `firewall-doctor`, `firewall-check` — and a
 * test cannot rename them. One behaviour, eight names.
 */
$arguments = array_slice($argv, 1);

fwrite(STDOUT, 'ARGS:' . implode('|', $arguments) . "\n");
fwrite(STDERR, "on stderr\n");

foreach ($arguments as $argument) {
    if (str_starts_with($argument, '--exit=')) {
        exit((int) substr($argument, 7));
    }

    if ($argument === '--hang') {
        sleep(30);
    }
}

exit(0);
