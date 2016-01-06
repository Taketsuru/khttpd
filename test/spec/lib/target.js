'use strict';

var child_process = require('child_process'),
    path = require('path');

function run(command) {
    var projdir = path.dirname(process.cwd()),
        result = child_process.spawnSync(
            'ssh',
            ['root@' + exports.name, 'cd ' + projdir + '; ' + command],
            { stdio: [null, 'pipe', 'inherit'] });

    if (result.error) {
        throw result.error;
    }

    if (result.status == 141) { // SIGPIPE
        result.status = 0;
    }

    return result;
}

exports.name = '192.168.56.3';
exports.port = 8080;
exports.run = run;
