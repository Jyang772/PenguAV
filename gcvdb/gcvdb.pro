#-------------------------------------------------
#
# Project created by QtCreator 2012-08-27T08:54:55
#
#-------------------------------------------------

QT       -= gui

TARGET = gcvdb
TEMPLATE = lib

DEFINES += PSVDB_LIBRARY

SOURCES += gcvdb.cpp \
    md5/hl_wrapperfactory.cpp \
    md5/hl_sha512wrapper.cpp \
    md5/hl_sha384wrapper.cpp \
    md5/hl_sha256wrapper.cpp \
    md5/hl_sha256.cpp \
    md5/hl_sha2ext.cpp \
    md5/hl_sha1wrapper.cpp \
    md5/hl_sha1.cpp \
    md5/hl_md5wrapper.cpp \
    md5/hl_md5.cpp

HEADERS += gcvdb.h\
        gcvdb_global.h \
    md5/hl_wrapperfactory.h \
    md5/hl_types.h \
    md5/hl_sha512wrapper.h \
    md5/hl_sha384wrapper.h \
    md5/hl_sha256wrapper.h \
    md5/hl_sha256.h \
    md5/hl_sha2mac.h \
    md5/hl_sha2ext.h \
    md5/hl_sha1wrapper.h \
    md5/hl_sha1.h \
    md5/hl_md5wrapper.h \
    md5/hl_md5.h \
    md5/hl_hashwrapper.h \
    md5/hl_exception.h \
    md5/hashlibpp.h \
    VirusDatabase.h

symbian {
    MMP_RULES += EXPORTUNFROZEN
    TARGET.UID3 = 0xE0A6995F
    TARGET.CAPABILITY = 
    TARGET.EPOCALLOWDLLDATA = 1
    addFiles.sources = psvdb.dll
    addFiles.path = !:/sys/bin
    DEPLOYMENT += addFiles
}

#unix:!symbian {
#    maemo5 {
#        target.path = /opt/usr/lib
#    } else {
#        target.path = /usr/lib
#    }
#    INSTALLS += target
#}
