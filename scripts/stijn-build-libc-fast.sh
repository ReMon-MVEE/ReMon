#debuild --preserve-envvar=CCACHE* --preserve-envvar=DISTCC* --prepend-path=/usr/local/bin/ -j8
DEB_BUILD_OPTIONS=nocheck debuild -j8 -us -uc -b
