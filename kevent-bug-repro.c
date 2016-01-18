#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <err.h>
#include <stdio.h>
#include <strings.h>
#include <sysexits.h>

int main()
{
	int pfd, wfd, rfd;
	int kq;

	pfd = socket(AF_INET, SOCK_STREAM, 0);
	if (pfd == -1)
		err(EX_OSERR, "socket 1");

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_len = sizeof(addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(8080);
	addr.sin_addr.s_addr = htonl((127 << 8*3) + 1);

	if (bind(pfd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
		err(EX_OSERR, "bind");

	if (listen(pfd, 128) == -1)
		err(EX_OSERR, "listen");

	rfd = socket(AF_INET, SOCK_STREAM, 0);
	if (rfd == -1)
		err(EX_OSERR, "socket write");

	if (connect(rfd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
		err(EX_OSERR, "connect");

	wfd = accept4(pfd, NULL, NULL, 0);
	if (wfd == -1)
		err(EX_OSERR, "accept4");

	if (shutdown(rfd, SHUT_WR) == -1)
		err(EX_OSERR, "shutdown");

	kq = kqueue();
	if (kq == -1)
		err(EX_OSERR, "kqueue");

	struct kevent kev;
	EV_SET(&kev, wfd, EVFILT_WRITE, EV_ADD|EV_DISABLE, 0, 0, 0);

	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		err(EX_OSERR, "kevent change 1");

	struct timespec ts;
	ts.tv_sec = 1;
	ts.tv_nsec = 0;

	int ne = kevent(kq, NULL, 0, &kev, 1, &ts);
	if (ne == -1)
		err(EX_OSERR, "kevent get 1");

	EV_SET(&kev, wfd, EVFILT_WRITE, EV_ENABLE, 0, 0, 0);

	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		err(EX_OSERR, "kevent change 2");

	ne = kevent(kq, NULL, 0, &kev, 1, &ts);
	if (ne == -1)
		err(EX_OSERR, "kevent get 2");

	if (ne != 1)
		errx(EX_OSERR, "what?!");
}
