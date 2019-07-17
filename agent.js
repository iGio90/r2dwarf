global.r2 = function (cmd) {
    send('r2 ' + cmd);
    var response = null;
    var op = recv('r2', function (payload) {
        response = payload['payload'];
    });
    op.wait();
    return response;
};

send('r2 init');