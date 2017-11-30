include( ../common-project-config.pri )
include( ../common-vars.pri )
TEMPLATE = lib
TARGET = oauth2plugin
DESTDIR = lib/signon
QT += core \
    network
QT -= gui
CONFIG += plugin \
    warn_on \
    link_pkgconfig
public_headers += oauth2data.h oauth1data.h
private_headers = \
    base-plugin.h \
    common.h \
    oauth1plugin.h \
    oauth2plugin.h \
    oauth2tokendata.h \
    plugin.h
HEADERS = $$public_headers \
    $$private_headers
SOURCES += \
    base-plugin.cpp \
    oauth1plugin.cpp \
    oauth2plugin.cpp \
    plugin.cpp

isEmpty(SIGNON_PLUGINS_INCLUDEPATH) {
    PKGCONFIG += signon-plugins
} else {
    INCLUDEPATH += $${SIGNON_PLUGINS_INCLUDEPATH}
    LIBS += $${SIGNON_PLUGINS_LIBS}
    QMAKE_LIBDIR += $${SIGNON_PLUGINS_LIBDIR}
}

headers.files = $$public_headers
pkgconfig.files = signon-oauth2plugin.pc
include( ../common-installs-config.pri )
