all: docroot/js/bundle.js

docroot/js/bundle.js: main.js
	browserify -t [ babelify --presets [ react ] ] main.js \
		-o docroot/js/bundle.js

clean:
	rm -f docroot/js/bundle.js
	sudo rm -f access.log error.log
