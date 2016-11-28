all: khttpd.conf

test: khttpd.conf
	rm -f ktr.txt access.log error.log
	node_modules/jasmine/bin/jasmine.js

depend:
	npm install

clean:
	rm -rf node_modules khttpd.conf

khttpd.conf: khttpd.conf.tmpl
	sed 's,$$PROJECT,'${.CURDIR}',g' <khttpd.conf.tmpl > khttpd.conf \
	|| rm -f khttpd.conf
