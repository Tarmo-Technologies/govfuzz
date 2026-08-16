<?php
// SPDX-License-Identifier: Apache-2.0
declare(strict_types=1);

require __DIR__.'/../../../vendor/autoload.php';

use Monolog\Formatter\ChromePHPFormatter;
use Monolog\Level;
use Monolog\LogRecord;

function fuzz(string $data): void
{
    $record = new LogRecord(new DateTimeImmutable(), 'fuzz', Level::Info, $data);
    (new ChromePHPFormatter())->format($record);
}
