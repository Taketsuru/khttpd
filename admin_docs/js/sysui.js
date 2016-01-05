/*-
 * Copyright (c) 2015 Taketsuru <taketsuru11@gmail.com>.
 * All rights reserved.
 * License: 2-terms BSD
 */

(function () {
    var app = angular.module('sysUi', []);

    app.controller('sysctlPanelController', ['$http', function ($http) {
	var ctlr = this;
	ctlr.sysctl = {};

	$http.get('/sys/sysctl').then(function (response) {
	    ctlr.sysctl = response.data;
	});
    }])
})();
